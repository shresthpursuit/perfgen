"""Correlation: the deterministic scan, the two filters, and the single adjudication call.

No model is called anywhere in this file. The adjudicator is a protocol, so tests inject a fake
and assert on what it was given and what was done with what it returned.
"""

from __future__ import annotations

import json

import pytest

from perfgen.correlate import build_prompt, correlate, find_candidates
from perfgen.correlate.adjudicate import parse_response
from perfgen.correlate.models import Adjudication, AdjudicationResult, Candidate
from perfgen.correlate.scan import low_entropy_reason, response_values
from perfgen.ir.models import (
    Application,
    Auth,
    AuthType,
    Confidence,
    ExtractorType,
    Flow,
    Method,
    Provenance,
    Scope,
    Step,
    TestPlanIR,
)
from perfgen.probe.records import (
    ProbeRecord,
    RecordedCall,
    RecordedRequest,
    RecordedResponse,
    SkippedFlow,
)
from tests.fixtures.traffic import (
    ECHOED_CLIENT_VALUE,
    REAL_ITEM_ID,
    REAL_REQUEST_REF,
    bait_record,
    degraded_record,
)


class FakeAdjudicator:
    """Records what it was asked and answers from a script."""

    def __init__(
        self,
        decisions: list[Adjudication] | None = None,
        extractor: ExtractorType = ExtractorType.JSON_PATH,
    ):
        self.calls: list[list[Candidate]] = []
        self.decisions = decisions
        self.extractor = extractor

    def adjudicate(self, candidates):
        self.calls.append(list(candidates))
        if self.decisions is not None:
            return AdjudicationResult(decisions=self.decisions, model="fake")
        # Default: accept everything, naming the variable after the final path segment.
        return AdjudicationResult(
            model="fake",
            decisions=[
                Adjudication(
                    candidate_id=c.id,
                    accept=True,
                    var=c.source_location.rsplit(".", 1)[-1].rsplit("/", 1)[-1].split("[")[0]
                    or f"v{c.id}",
                    extractor=self.extractor,
                    scope=Scope.ITERATION,
                    evidence=f"observed at {c.source_location}",
                )
                for c in candidates
            ],
        )


def build_ir() -> TestPlanIR:
    return TestPlanIR(
        application=Application(name="Bait", base_url="https://api.example.internal"),
        auth=Auth(type=AuthType.NONE),
        flows=[
            Flow(
                id="F01",
                name="Search and view",
                share_pct=50,
                think_time_ms=0,
                probe_safe=True,
                steps=[
                    Step(index=1, name="Search catalogue", method=Method.GET,
                         path="/catalogue/search?q=widget", expected_status=200),
                    Step(index=2, name="Open record detail", method=Method.GET,
                         path="/catalogue/items/{itemId}", expected_status=200),
                ],
            ),
            Flow(
                id="F02",
                name="Submit",
                share_pct=50,
                think_time_ms=0,
                probe_safe=True,
                steps=[
                    Step(index=1, name="Create request", method=Method.POST, path="/requests",
                         body='{"type":"standard"}', expected_status=201),
                    Step(index=2, name="Check status", method=Method.GET,
                         path="/requests/{requestRef}/status", expected_status=200),
                ],
            ),
        ],
        load_profiles=[],
        provenance=Provenance(source_workbook="fixture", generated_at="2026-08-10T00:00:00Z"),
    )


def values_of(result) -> set[str]:
    return {candidate.value for candidate in result.candidates}


def rejected_values(result, filter_name: str) -> set[str]:
    return {r.value for r in result.rejected if r.filter_name == filter_name}


# --------------------------------------------------------------------------------------------
# The scan finds what it should
# --------------------------------------------------------------------------------------------


def test_real_correlations_are_found():
    found = values_of(find_candidates(bait_record()))
    assert REAL_ITEM_ID in found
    assert REAL_REQUEST_REF in found


def test_candidate_records_where_the_value_came_from_and_went():
    candidate = next(
        c for c in find_candidates(bait_record()).candidates if c.value == REAL_ITEM_ID
    )
    assert candidate.source_step_name == "Search catalogue"
    assert candidate.source_location == "$.results[0].id"
    assert candidate.source_kind == "response_body"
    assert candidate.used_step_name == "Open record detail"
    assert candidate.used_kind == "path"
    assert candidate.used_by() == "F01.2.path"


def test_a_value_is_never_a_candidate_for_an_earlier_call():
    """Correlation runs forwards only; a later response cannot supply an earlier request."""
    for candidate in find_candidates(bait_record()).candidates:
        assert candidate.used_step_index >= (candidate.source_step_index or 0)


# --------------------------------------------------------------------------------------------
# Filter one: low entropy
# --------------------------------------------------------------------------------------------


def test_boolean_string_is_rejected():
    assert "true" not in values_of(find_candidates(bait_record()))
    assert "true" in rejected_values(find_candidates(bait_record()), "low_entropy")


def test_currency_enum_is_rejected():
    assert "USD" not in values_of(find_candidates(bait_record()))
    assert "USD" in rejected_values(find_candidates(bait_record()), "low_entropy")


def test_small_integer_is_rejected():
    assert "200" not in values_of(find_candidates(bait_record()))
    assert "200" in rejected_values(find_candidates(bait_record()), "low_entropy")


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        # Too short to be an identifier - the cheapest check, so it fires first.
        ("true", "characters long"),
        ("USD", "characters long"),
        ("active", "characters long"),
        ("200", "characters long"),
        # Long enough, but still a constant rather than an identifier.
        ("standard", "common constant"),
        ("application/json", "common constant"),
        # Long enough, numeric, but too small to be an id.
        ("00001234", "small integer"),
        ("3.14159265", "decimal number"),
    ],
)
def test_low_entropy_reasons(value, fragment):
    reason = low_entropy_reason(value, distinct_sources=1)
    assert reason is not None and fragment in reason


def test_a_large_number_is_not_dismissed_as_a_counter():
    """An 8-digit id is plausible; the small-integer rule must not swallow it."""
    assert low_entropy_reason("87654321", distinct_sources=1) is None


def test_a_value_seen_in_many_responses_is_ambient():
    reason = low_entropy_reason("a-long-enough-identifier", distinct_sources=3)
    assert reason is not None and "different responses" in reason


def test_a_genuine_identifier_survives_the_entropy_filter():
    assert low_entropy_reason(REAL_ITEM_ID, distinct_sources=1) is None
    assert low_entropy_reason(REAL_REQUEST_REF, distinct_sources=1) is None


# --------------------------------------------------------------------------------------------
# Filter two: client-originated
# --------------------------------------------------------------------------------------------


def test_client_echoed_value_is_rejected():
    """The client sent it, the server echoed it back; it is static, not generated."""
    result = find_candidates(bait_record())
    assert ECHOED_CLIENT_VALUE not in values_of(result)
    assert ECHOED_CLIENT_VALUE in rejected_values(result, "client_originated")


def test_client_echoed_rejection_explains_itself():
    rejection = next(
        r for r in find_candidates(bait_record()).rejected if r.value == ECHOED_CLIENT_VALUE
    )
    assert "echoed back what the client sent" in rejection.reason


def test_the_server_generated_sibling_of_an_echoed_value_still_survives():
    """Both are in the same response; only the echoed one should go."""
    result = find_candidates(bait_record())
    assert REAL_REQUEST_REF in values_of(result)
    assert ECHOED_CLIENT_VALUE not in values_of(result)


# --------------------------------------------------------------------------------------------
# A body the scan cannot read must say so
#
# The body indexer only understands JSON. An XML or form-encoded response used to contribute
# nothing and produce no rejection either, so the run reported "0 candidates, 0 rejected" - which
# reads as "there was nothing there" when it actually meant "I could not look".
# --------------------------------------------------------------------------------------------

XML_REF = "ORD-8f2c91ab-7d3e"


def xml_body_record() -> ProbeRecord:
    """A high-entropy reference carried in an XML body into a later request's path."""
    return ProbeRecord(
        application="Xml",
        performed_at="2026-08-11T00:00:00Z",
        calls=[
            RecordedCall(
                flow_id="F01",
                step_index=1,
                name="Create order",
                request=RecordedRequest(method="POST", url="https://api.example.internal/orders"),
                response=RecordedResponse(
                    status=201,
                    headers={"Content-Type": "application/xml; charset=utf-8"},
                    body=f"<order><ref>{XML_REF}</ref></order>",
                ),
            ),
            RecordedCall(
                flow_id="F01",
                step_index=2,
                name="Fetch order",
                request=RecordedRequest(
                    method="GET", url=f"https://api.example.internal/orders/{XML_REF}"
                ),
                response=RecordedResponse(status=200, body="<order/>"),
            ),
        ],
    )


def prose_body_record() -> ProbeRecord:
    """A body no parser can read: not JSON, not well-formed XML, not key=value pairs."""
    record = xml_body_record()
    record.calls[0].response.headers = {"Content-Type": "text/plain"}
    record.calls[0].response.body = "Service Unavailable - please retry shortly"
    record.calls[1].response.body = "Service Unavailable - please retry shortly"
    return record


def test_an_unreadable_body_is_recorded_rather_than_ignored():
    result = find_candidates(prose_body_record())

    assert result.unreadable, "an unparseable body must leave a trace, not vanish"
    entry = result.unreadable[0]
    assert entry.step_name == "Create order"
    assert entry.content_type == "text/plain"
    assert entry.body_bytes > 0


def test_the_scan_summary_no_longer_reads_as_nothing_was_there():
    """'0 candidates, 0 rejected' alone is indistinguishable from a clean empty result."""
    summary = find_candidates(prose_body_record()).summary

    assert "0 candidate(s) survived" in summary
    assert "unreadable" in summary


def test_the_unreadable_body_names_where_it_came_from():
    entry = find_candidates(prose_body_record()).unreadable[0]
    described = entry.describe()

    assert "F01 step 1" in described
    assert "Create order" in described
    assert "text/plain" in described


def test_an_unreadable_body_surfaces_as_a_warning():
    outcome = correlate(build_ir(), prose_body_record(), FakeAdjudicator())

    warning = next(w for w in outcome.warnings if "could not be read" in w)
    assert "text/plain" in warning
    assert "has been missed" in warning


# --- Stage 2: XML and form bodies are now indexed rather than reported unreadable -------------


def test_an_xml_body_is_now_indexed():
    result = find_candidates(xml_body_record())

    assert result.unreadable == [], "XML is readable now"
    assert XML_REF in values_of(result)


def test_an_xml_candidate_carries_an_xpath_location_and_its_format():
    candidate = next(c for c in find_candidates(xml_body_record()).candidates if c.value == XML_REF)

    assert candidate.source_location == "/order/ref"
    assert candidate.body_format == "xml"


def test_an_xml_correlation_becomes_an_xpath_extractor():
    ir = build_ir()
    correlate(ir, xml_body_record(), FakeAdjudicator(extractor=ExtractorType.XPATH))

    extract = ir.flow("F01").steps[0].extracts[0]
    assert extract.extractor is ExtractorType.XPATH
    assert extract.expr == "/order/ref", "the location must survive as the XPath query"


def test_a_json_body_produces_no_unreadable_entry():
    assert find_candidates(bait_record()).unreadable == []
    assert "unreadable" not in find_candidates(bait_record()).summary


def test_an_empty_body_is_not_reported_as_unreadable():
    """Nothing to read is not the same as failing to read something."""
    record = xml_body_record()
    record.calls[0].response.body = ""
    record.calls[1].response.body = ""
    assert find_candidates(record).unreadable == []


def test_headers_are_still_indexed_when_the_body_is_unreadable():
    """A failed body must not cost us the parts that did parse."""
    indexed = response_values(prose_body_record().calls[0])

    assert indexed.unreadable is not None
    assert any(kind == "response_header" for kind, _, _ in indexed.values)


def test_a_json_body_with_the_wrong_content_type_still_parses():
    """Indexing is driven by the bytes, not the label, so a mislabelled body is not lost."""
    record = xml_body_record()
    record.calls[0].response.headers = {"Content-Type": "text/plain"}
    record.calls[0].response.body = json.dumps({"ref": XML_REF})

    result = find_candidates(record)

    assert XML_REF in values_of(result), "a JSON body labelled text/plain must still be indexed"
    assert not [u for u in result.unreadable if u.step_name == "Create order"]


# --------------------------------------------------------------------------------------------
# The exemption: a declared placeholder outranks the entropy rule
#
# Found by running against jsonplaceholder, which returns `"id": 101`. A three-character integer
# is exactly what the low-entropy rule exists to discard, and integer primary keys are among the
# most common identifiers there are - so the rule was throwing away real correlations. Where the
# spec author wrote `{id}` and the probe resolved it from a particular field, that is a stated
# dependency and entropy says nothing about it.
# --------------------------------------------------------------------------------------------


def short_id_record() -> ProbeRecord:
    """The real jsonplaceholder shape: POST returns id 101, GET fetches /posts/101."""
    return ProbeRecord(
        application="Smoke",
        performed_at="2026-08-11T00:00:00Z",
        calls=[
            RecordedCall(
                flow_id="F01",
                step_index=1,
                name="Create post",
                request=RecordedRequest(
                    method="POST",
                    url="https://api.example.internal/posts",
                    body='{"title": "perf test", "userId": 1}',
                ),
                response=RecordedResponse(
                    status=201, body=json.dumps({"title": "perf test", "userId": 1, "id": 101})
                ),
            ),
            RecordedCall(
                flow_id="F01",
                step_index=2,
                name="Fetch created post",
                request=RecordedRequest(
                    method="GET", url="https://api.example.internal/posts/101"
                ),
                response=RecordedResponse(status=200, body=json.dumps({"id": 101})),
                placeholder_bindings={"id": "$.id"},
            ),
        ],
    )


def test_a_short_declared_value_survives_the_entropy_filter():
    """101 is three characters; without the exemption it is discarded as coincidence."""
    result = find_candidates(short_id_record())

    assert "101" in values_of(result), [r.reason for r in result.rejected]
    assert "101" not in rejected_values(result, "low_entropy")


def test_the_surviving_candidate_carries_the_declaration():
    candidate = next(c for c in find_candidates(short_id_record()).candidates if c.value == "101")
    assert candidate.declared_placeholder == "id"
    assert candidate.source_location == "$.id"


def test_a_short_declared_value_reaches_the_adjudicator():
    fake = FakeAdjudicator()
    correlate(build_ir(), short_id_record(), fake)

    assert len(fake.calls) == 1
    assert "101" in {c.value for c in fake.calls[0]}


def test_a_declared_value_becomes_a_verified_extractor():
    """The whole point: real observed traffic must yield verified, not a guess."""
    ir = build_ir()
    correlate(ir, short_id_record(), FakeAdjudicator())

    extract = ir.flow("F01").steps[0].extracts[0]
    assert extract.var == "id"
    assert extract.expr == "$.id", "the observed path, not the recursive-descent fallback"
    assert extract.confidence is Confidence.VERIFIED
    assert extract.needs_review is False


def test_the_prompt_tells_the_model_the_dependency_was_declared():
    prompt = build_prompt(find_candidates(short_id_record()).candidates)
    assert "declared:" in prompt
    assert "{id}" in prompt


def test_an_undeclared_short_value_is_still_rejected():
    """The exemption is not a licence to lower the bar generally."""
    record = short_id_record()
    record.calls[1].placeholder_bindings = {}
    result = find_candidates(record)

    assert "101" not in values_of(result)
    assert "101" in rejected_values(result, "low_entropy")


def test_a_declared_placeholder_does_not_excuse_a_client_echoed_value():
    """The exemption covers low entropy only; an echoed value is static whatever points at it."""
    record = bait_record()
    # Pretend the spec declared a placeholder for the value the client itself supplied.
    record.calls[3].placeholder_bindings = {"clientRef": "$.clientRef"}
    result = find_candidates(record)

    assert ECHOED_CLIENT_VALUE not in values_of(result)
    assert ECHOED_CLIENT_VALUE in rejected_values(result, "client_originated")


# --------------------------------------------------------------------------------------------
# The single call
# --------------------------------------------------------------------------------------------


def test_adjudicator_is_called_exactly_once():
    fake = FakeAdjudicator()
    correlate(build_ir(), bait_record(), fake)
    assert len(fake.calls) == 1


def test_only_surviving_candidates_are_sent_to_the_model():
    fake = FakeAdjudicator()
    correlate(build_ir(), bait_record(), fake)
    sent = {c.value for c in fake.calls[0]}
    assert sent == {REAL_ITEM_ID, REAL_REQUEST_REF}


def test_accepted_decisions_become_extractors_on_the_producing_step():
    ir = build_ir()
    correlate(ir, bait_record(), FakeAdjudicator())

    search = ir.flow("F01").steps[0]
    assert [e.expr for e in search.extracts] == ["$.results[0].id"]
    assert search.extracts[0].scope is Scope.ITERATION
    assert search.extracts[0].confidence is Confidence.VERIFIED
    assert search.extracts[0].used_by == ["F01.2.path"]


def test_rejected_decisions_produce_no_verified_extractor():
    """Rejecting a candidate still leaves the spec's {placeholder} needing something.

    It falls back to a labelled guess rather than nothing: an unresolved placeholder is emitted as
    literal text and sent to the server, which is worse than a guess a reviewer can see.
    """
    fake = FakeAdjudicator(
        decisions=[
            Adjudication(candidate_id=1, accept=False, reason="coincidence"),
            Adjudication(candidate_id=2, accept=False, reason="coincidence"),
        ]
    )
    ir = build_ir()
    correlate(ir, bait_record(), fake)

    written = [e for f in ir.flows for s in f.steps for e in s.extracts]
    assert all(e.confidence is Confidence.INFERRED for e in written)
    assert all(e.needs_review for e in written)


def test_transformed_values_are_inferred_and_flagged():
    """A wrong extractor on a transformed value fails silently under load."""
    fake = FakeAdjudicator(
        decisions=[
            Adjudication(
                candidate_id=1,
                accept=True,
                var="itemId",
                transformed=True,
                evidence="the later request carries a base64 wrapping of the value",
            )
        ]
    )
    ir = build_ir()
    outcome = correlate(ir, bait_record(), fake)

    extract = ir.flow("F01").steps[0].extracts[0]
    assert extract.confidence is Confidence.INFERRED
    assert extract.needs_review is True
    assert any("transformed" in w for w in outcome.warnings)


def test_every_written_extract_carries_confidence_and_evidence():
    ir = build_ir()
    correlate(ir, bait_record(), FakeAdjudicator())
    for flow in ir.flows:
        for step in flow.steps:
            for extract in step.extracts:
                assert extract.confidence is not None
                assert extract.evidence.strip()


# --------------------------------------------------------------------------------------------
# The model never gets to invent anything
# --------------------------------------------------------------------------------------------


def test_decisions_for_unknown_candidate_ids_are_discarded():
    fake = FakeAdjudicator(
        decisions=[Adjudication(candidate_id=999, accept=True, var="invented")]
    )
    ir = build_ir()
    correlate(ir, bait_record(), fake)

    written = {e.var for f in ir.flows for s in f.steps for e in s.extracts}
    assert "invented" not in written, "the model cannot introduce a correlation the scan never saw"


def test_parse_response_drops_invented_ids():
    candidates = find_candidates(bait_record()).candidates
    reply = json.dumps(
        {"decisions": [{"candidate_id": 4242, "accept": True, "var": "ghost"}]}
    )
    assert parse_response(reply, candidates).decisions == []


def test_parse_response_drops_malformed_entries():
    candidates = find_candidates(bait_record()).candidates
    reply = json.dumps(
        {
            "decisions": [
                {"candidate_id": candidates[0].id, "accept": True, "var": "itemId"},
                {"candidate_id": candidates[0].id, "accept": True, "scope": "not-a-scope"},
                "nonsense",
            ]
        }
    )
    decisions = parse_response(reply, candidates).decisions
    assert len(decisions) == 1
    assert decisions[0].var == "itemId"


def test_parse_response_accepts_a_fenced_reply():
    candidates = find_candidates(bait_record()).candidates
    reply = (
        "Here you go:\n```json\n"
        + json.dumps(
            {"decisions": [{"candidate_id": candidates[0].id, "accept": True, "var": "itemId"}]}
        )
        + "\n```"
    )
    assert parse_response(reply, candidates).decisions[0].var == "itemId"


def test_parse_response_survives_a_non_json_reply():
    candidates = find_candidates(bait_record()).candidates
    assert parse_response("I am afraid I cannot help with that.", candidates).decisions == []


def test_accepted_but_unnamed_decisions_are_discarded():
    candidates = find_candidates(bait_record()).candidates
    reply = json.dumps(
        {"decisions": [{"candidate_id": candidates[0].id, "accept": True, "var": "  "}]}
    )
    assert parse_response(reply, candidates).decisions == []


def test_prompt_contains_the_evidence_the_model_needs():
    candidates = find_candidates(bait_record()).candidates
    prompt = build_prompt(candidates)
    assert REAL_ITEM_ID in prompt
    assert "$.results[0].id" in prompt
    assert "Search catalogue" in prompt
    assert "Open record detail" in prompt


# --------------------------------------------------------------------------------------------
# The degraded route: no traffic, no call
# --------------------------------------------------------------------------------------------


def test_degraded_probe_never_calls_the_model():
    fake = FakeAdjudicator()
    outcome = correlate(build_ir(), degraded_record(), fake)

    assert fake.calls == [], "a model call without evidence would be invention"
    assert outcome.llm_called is False
    assert "no model call was made" in outcome.skip_reason.lower()


def test_missing_record_never_calls_the_model():
    fake = FakeAdjudicator()
    correlate(build_ir(), None, fake)
    assert fake.calls == []


def test_degraded_probe_still_produces_usable_correlations():
    ir = build_ir()
    outcome = correlate(ir, degraded_record(), FakeAdjudicator())

    assert outcome.extracts_written > 0
    produced = {e.var for f in ir.flows for s in f.steps for e in s.extracts}
    assert {"itemId", "requestRef"} <= produced


def test_degraded_correlations_are_inferred_and_need_review():
    ir = build_ir()
    correlate(ir, degraded_record(), FakeAdjudicator())

    for flow in ir.flows:
        for step in flow.steps:
            for extract in step.extracts:
                assert extract.confidence is Confidence.INFERRED
                assert extract.needs_review is True
                assert "No traffic was observed" in extract.evidence


def test_no_candidates_means_no_call():
    """An empty candidate list is not worth a request."""
    record = bait_record()
    record.calls = record.calls[:1]  # nothing later to reuse anything
    fake = FakeAdjudicator()
    outcome = correlate(build_ir(), record, fake)

    assert fake.calls == []
    assert "nothing to adjudicate" in outcome.skip_reason


def test_skipped_flows_fall_back_to_placeholder_inference():
    record = bait_record()
    record.calls = [c for c in record.calls if c.flow_id != "F02"]
    record.skipped_flows = [SkippedFlow(flow_id="F02", reason="marked unsafe")]

    ir = build_ir()
    outcome = correlate(ir, record, FakeAdjudicator())

    f02_extracts = [e for s in ir.flow("F02").steps for e in s.extracts]
    assert f02_extracts, "a skipped flow still needs its placeholders wired, as guesses"
    assert all(e.needs_review for e in f02_extracts)
    assert any("never called" in w for w in outcome.warnings)

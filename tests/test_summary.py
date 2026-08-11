"""The run summary.

The user this tool is for has never opened JMeter. They will read this output and then trust the
script, or hand it to someone who will. A correlation that was guessed does not announce itself at
run time - the test passes and the measurement is meaningless - so the summary has to announce it
here, in a form that survives skimming.

These tests are mostly about prominence, which is unusual to assert on and worth doing anyway: a
warning nobody reads is the same as no warning.
"""

from __future__ import annotations

from perfgen.ir.models import (
    Application,
    Auth,
    AuthType,
    Confidence,
    Extract,
    ExtractorType,
    Flow,
    Gap,
    Method,
    Provenance,
    Scope,
    Severity,
    Source,
    Step,
    TestPlanIR,
)
from perfgen.summary import RunSummary, exit_code_for, summarise


def extract(var: str, *, confidence: Confidence, needs_review: bool, evidence: str) -> Extract:
    return Extract(
        var=var,
        source=Source.RESPONSE_BODY,
        extractor=ExtractorType.JSON_PATH,
        expr=f"$.{var}",
        scope=Scope.ITERATION,
        confidence=confidence,
        evidence=evidence,
        needs_review=needs_review,
    )


def build_ir(extracts: list[Extract] | None = None, *, degraded: bool = False) -> TestPlanIR:
    ir = TestPlanIR(
        application=Application(name="Claims intake", base_url="https://api.example.internal"),
        auth=Auth(type=AuthType.NONE),
        flows=[
            Flow(
                id="F01",
                name="Search",
                share_pct=100,
                think_time_ms=0,
                probe_safe=True,
                steps=[
                    Step(index=1, name="Search catalogue", method=Method.GET, path="/s",
                         expected_status=200, extracts=extracts or []),
                    Step(index=2, name="Open detail", method=Method.GET, path="/d",
                         expected_status=200),
                ],
            )
        ],
        load_profiles=[],
        provenance=Provenance(source_workbook="fixture", generated_at="2026-08-10T00:00:00Z"),
    )
    ir.provenance.probe.degraded = degraded
    ir.provenance.probe.performed = not degraded
    return ir


MIXED = [
    extract("itemId", confidence=Confidence.VERIFIED, needs_review=False, evidence="observed"),
    extract("orderRef", confidence=Confidence.VERIFIED, needs_review=False, evidence="observed"),
    extract(
        "sessionId",
        confidence=Confidence.INFERRED,
        needs_review=True,
        evidence="Guessed from the placeholder {sessionId}; no traffic confirmed it.",
    ),
    extract(
        "csrfToken",
        confidence=Confidence.INFERRED,
        needs_review=True,
        evidence="The later request carries a base64 wrapping rather than the value itself.",
    ),
    extract(
        "traceId",
        confidence=Confidence.INFERRED,
        needs_review=True,
        evidence="Flow was never called, so this is a guess.",
    ),
]


# --------------------------------------------------------------------------------------------
# The banner
# --------------------------------------------------------------------------------------------


def test_the_ratio_is_stated_in_words_a_skimmer_will_catch():
    """'3 of 5 correlations are guesses' must be present verbatim, not implied by a field."""
    text = summarise(build_ir(MIXED)).render()
    assert "3 OF 5 CORRELATION(S) IN THIS SCRIPT ARE GUESSES" in text


def test_the_banner_appears_before_the_detail():
    text = summarise(build_ir(MIXED)).render()
    assert text.index("ARE GUESSES") < text.index("Stages:")


def test_every_flagged_extractor_is_named_with_its_evidence():
    text = summarise(build_ir(MIXED)).render()
    for var in ("sessionId", "csrfToken", "traceId"):
        assert var in text
    assert "base64 wrapping" in text, "the evidence text itself must be shown, not just the name"
    assert "Guessed from the placeholder" in text


def test_flagged_extractors_name_where_they_live():
    text = summarise(build_ir(MIXED)).render()
    assert "F01 step 1" in text
    assert "Search catalogue" in text


def test_confident_extractors_are_not_flagged():
    text = summarise(build_ir(MIXED)).render()
    banner = text.split("!" * 78)[1]
    assert "itemId" not in banner
    assert "orderRef" not in banner


def test_no_banner_when_everything_was_verified():
    verified = [e for e in MIXED if e.confidence is Confidence.VERIFIED]
    text = summarise(build_ir(verified)).render()
    assert "ARE GUESSES" not in text
    assert "!" * 78 not in text


def test_counts_are_reported_in_the_stages_block_too():
    text = summarise(build_ir(MIXED)).render()
    assert "correlations: 5 total, 2 verified, 3 needing review" in text


def test_the_consequence_is_spelled_out_not_just_the_count():
    """A count alone does not tell a non-specialist why it matters."""
    text = summarise(build_ir(MIXED)).render()
    assert "does" in text and "not crash" in text
    assert "measures nothing" in text


# --------------------------------------------------------------------------------------------
# Degraded probe
# --------------------------------------------------------------------------------------------


def test_degraded_probe_gets_its_own_banner_line():
    text = summarise(build_ir(MIXED, degraded=True)).render()
    assert "THE PROBE DID NOT RUN." in text
    assert "Nothing in this script was verified" in text


def test_degraded_probe_banners_even_with_no_correlations():
    text = summarise(build_ir([], degraded=True)).render()
    assert "THE PROBE DID NOT RUN." in text


def test_trustworthy_only_when_nothing_is_flagged_and_the_probe_ran():
    assert summarise(build_ir([m for m in MIXED if not m.needs_review])).trustworthy
    assert not summarise(build_ir(MIXED)).trustworthy
    assert not summarise(build_ir([], degraded=True)).trustworthy


# --------------------------------------------------------------------------------------------
# The rest of the report
# --------------------------------------------------------------------------------------------


def test_blocking_gaps_fail_the_run():
    summary = RunSummary(
        application="x",
        gaps=[Gap(field="f", severity=Severity.BLOCKING, message="missing")],
    )
    assert exit_code_for(summary) == 1


def test_needing_review_is_a_caution_not_a_failure():
    """The script is still generated; it just cannot be trusted blind."""
    assert exit_code_for(summarise(build_ir(MIXED))) == 0


def test_warnings_gaps_and_artifacts_are_all_rendered(tmp_path):
    summary = summarise(
        build_ir(MIXED),
        stages=["parse: spec.xlsx"],
        artifacts=[tmp_path / "plan.jmx"],
        gaps=[Gap(field="flows.share_pct", severity=Severity.WARNING, message="totals 90")],
        warnings=["token expires mid-run"],
        notes=["SLA sheet was empty"],
        config_warnings=["llm.temperature has no effect"],
        next_command="jmeter -n -t plan.jmx",
    )
    text = summary.render()
    assert "parse: spec.xlsx" in text
    assert "plan.jmx" in text
    assert "totals 90" in text
    assert "token expires mid-run" in text
    assert "SLA sheet was empty" in text
    assert "llm.temperature has no effect" in text
    assert "jmeter -n -t plan.jmx" in text


def test_a_listing_keeps_its_line_structure():
    """Flattening a two-line secret listing into a paragraph makes it unreadable."""
    listing = (
        "The specification references secrets that are not set in the environment:\n"
        "  claims-perf-id  ->  CLAIMS_PERF_ID\n"
        "  claims-perf-secret  ->  CLAIMS_PERF_SECRET\n"
        "Set them for this shell, or add them to a .env file."
    )
    text = summarise(build_ir([]), warnings=[listing]).render()

    assert "claims-perf-id -> CLAIMS_PERF_ID" in text
    assert "claims-perf-secret -> CLAIMS_PERF_SECRET" in text
    assert "CLAIMS_PERF_ID claims-perf-secret" not in text, "the two entries ran together"


def test_long_evidence_is_wrapped_not_truncated():
    long_evidence = " ".join(["evidence"] * 40)
    text = summarise(build_ir([
        extract("x", confidence=Confidence.INFERRED, needs_review=True, evidence=long_evidence)
    ])).render()
    assert text.count("evidence") >= 40, "wrapping must not drop words"
    assert max(len(line) for line in text.splitlines()) <= 90

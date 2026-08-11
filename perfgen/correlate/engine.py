"""Traffic record + IR -> extractors written into the IR.

Two routes through here, and which one runs depends on whether there is anything to reason about.

**Observed traffic.** The scan finds candidates, the filters remove the noise, and whatever
survives goes to the adjudicator in a single call. Accepted decisions become extractors carrying
`confidence: verified` - except transformed values, which are `inferred` and flagged for review.

**No traffic.** A degraded probe, or a flow that was never called, leaves nothing to scan. The
model is not asked: there is no evidence, and an adjudication of an empty list would be invention
dressed up as an answer. Instead the `{placeholder}` names in the spec are taken at face value,
every extractor is `inferred` with `needs_review` set, and the run says so loudly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from perfgen.correlate.adjudicate import Adjudicator
from perfgen.correlate.models import (
    Adjudication,
    AdjudicationResult,
    Candidate,
    ScanResult,
    confidence_for,
)
from perfgen.correlate.scan import find_candidates
from perfgen.ir.models import Confidence, Extract, ExtractorType, Scope, Source, TestPlanIR
from perfgen.probe.records import ProbeRecord

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass
class CorrelationOutcome:
    scan: ScanResult
    adjudication: AdjudicationResult
    extracts_written: int = 0
    llm_called: bool = False
    skip_reason: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def needs_review(self) -> int:
        return sum(1 for w in self.warnings if "review" in w.lower())


def correlate(
    ir: TestPlanIR,
    record: ProbeRecord | None,
    adjudicator: Adjudicator | None = None,
) -> CorrelationOutcome:
    """Fill in the IR's extractors from observed traffic, or from placeholder names if there is
    none."""
    if record is None or record.degraded or not record.calls:
        return _infer_without_traffic(ir, record)

    scan = find_candidates(record)
    outcome = CorrelationOutcome(scan=scan, adjudication=AdjudicationResult())

    if not scan.candidates:
        outcome.skip_reason = (
            "the scan found no candidate correlations in the recorded traffic, so there was "
            "nothing to adjudicate and no model call was made"
        )
        _infer_remaining_placeholders(ir, record, outcome)
        return outcome

    if adjudicator is None:
        outcome.skip_reason = "no adjudicator configured"
        _infer_remaining_placeholders(ir, record, outcome)
        return outcome

    outcome.adjudication = adjudicator.adjudicate(scan.candidates)
    outcome.llm_called = True

    by_id = {candidate.id: candidate for candidate in scan.candidates}
    probe_observed = not record.degraded

    for decision in outcome.adjudication.accepted():
        candidate = by_id.get(decision.candidate_id)
        if candidate is None:
            continue
        if _write_extract(ir, candidate, decision, probe_observed):
            outcome.extracts_written += 1
            if decision.transformed:
                outcome.warnings.append(
                    f"{decision.var} appears transformed rather than copied between "
                    f"{candidate.source_step_name} and {candidate.used_step_name}. It is marked "
                    f"inferred and needs review - a wrong extractor here fails silently under load."
                )

    _rewrite_paths(ir)
    _infer_remaining_placeholders(ir, record, outcome)
    return outcome


# --------------------------------------------------------------------------------------------
# Writing extracts
# --------------------------------------------------------------------------------------------


def _write_extract(
    ir: TestPlanIR, candidate: Candidate, decision: Adjudication, probe_observed: bool
) -> bool:
    """Attach an extractor to the step whose response produced the value."""
    flow = ir.flow(candidate.source_flow_id) if candidate.source_flow_id else None
    if flow is None:
        return False
    step = next((s for s in flow.steps if s.index == candidate.source_step_index), None)
    if step is None:
        return False
    if any(existing.var == decision.var for existing in step.extracts):
        return False

    confidence = confidence_for(decision, probe_observed)
    step.extracts.append(
        Extract(
            var=decision.var,
            source=candidate.as_ir_source(),
            extractor=decision.extractor,
            expr=_expression_for(candidate, decision),
            scope=decision.scope,
            confidence=confidence,
            evidence=decision.evidence
            or f"observed in {candidate.source_step_name} and reused by "
            f"{candidate.used_step_name}",
            used_by=[candidate.used_by()],
            needs_review=decision.transformed or confidence is Confidence.INFERRED,
        )
    )
    return True


def _expression_for(candidate: Candidate, decision: Adjudication) -> str:
    """The extractor expression, taken from where the scan actually found the value."""
    if decision.extractor is ExtractorType.JSON_PATH:
        return candidate.source_location
    if decision.extractor is ExtractorType.HEADER:
        return candidate.source_location
    if decision.extractor is ExtractorType.REGEX:
        return f'"{re.escape(candidate.source_location.rsplit(".", 1)[-1])}"\\s*:\\s*"([^"]+)"'
    left, _, right = candidate.used_detail.partition(candidate.value)
    return f"{left[-12:]}||{right[:12]}" if left or right else "||"


def _rewrite_paths(ir: TestPlanIR) -> None:
    """No-op placeholder hook: the emitter resolves `{var}` from extract scope at emit time."""
    return


# --------------------------------------------------------------------------------------------
# The no-traffic route
# --------------------------------------------------------------------------------------------


def _infer_without_traffic(ir: TestPlanIR, record: ProbeRecord | None) -> CorrelationOutcome:
    """No observed traffic: read the spec's own placeholders and mark everything as a guess."""
    outcome = CorrelationOutcome(scan=ScanResult(), adjudication=AdjudicationResult())
    outcome.skip_reason = (
        "the probe did not run, so there is no traffic to adjudicate. No model call was made - "
        "an answer without evidence would be invention. Correlations below are inferred from the "
        "placeholder names in the specification and must be reviewed before the script is trusted."
    )
    written = _infer_from_placeholders(ir)
    outcome.extracts_written = written
    if written:
        outcome.warnings.append(
            f"{written} correlation(s) were inferred from placeholder names without any observed "
            f"traffic. Every one is marked needs_review."
        )
    return outcome


def _infer_remaining_placeholders(
    ir: TestPlanIR, record: ProbeRecord, outcome: CorrelationOutcome
) -> None:
    """Flows the probe never called still have placeholders that nothing produces."""
    skipped = set(record.skipped_flow_ids)
    if not skipped:
        return
    written = _infer_from_placeholders(ir, only_flows=skipped)
    if written:
        outcome.extracts_written += written
        outcome.warnings.append(
            f"{written} correlation(s) in flow(s) {', '.join(sorted(skipped))} were inferred from "
            f"placeholder names, because those flows were never called. Each is marked "
            f"needs_review."
        )


def _infer_from_placeholders(ir: TestPlanIR, only_flows: set[str] | None = None) -> int:
    """Guess a producer for each `{placeholder}` from an earlier step in the same flow.

    Deliberately crude, and labelled as such. The point is a script a human can correct, not one
    that looks authoritative.
    """
    written = 0
    for flow in ir.flows:
        if only_flows is not None and flow.id not in only_flows:
            continue

        produced = {extract.var for step in flow.steps for extract in step.extracts}
        for position, step in enumerate(flow.steps):
            for name in _PLACEHOLDER.findall(step.path) + _PLACEHOLDER.findall(step.body or ""):
                if name in produced or position == 0:
                    continue
                earlier = flow.steps[position - 1]
                if any(existing.var == name for existing in earlier.extracts):
                    continue
                earlier.extracts.append(
                    Extract(
                        var=name,
                        source=Source.RESPONSE_BODY,
                        extractor=ExtractorType.JSON_PATH,
                        expr=f"$..{name}",
                        scope=Scope.ITERATION,
                        confidence=Confidence.INFERRED,
                        evidence=(
                            f"No traffic was observed. Guessed from the placeholder {{{name}}} in "
                            f"{step.name!r}, assuming the preceding step returns a field of that "
                            f"name. Unverified."
                        ),
                        used_by=[f"{flow.id}.{step.index}.path"],
                        needs_review=True,
                    )
                )
                produced.add(name)
                written += 1
    return written

"""Folding what the probe observed back into the IR.

The IR is the artifact that accumulates through the stages, so the probe's findings belong in it:
the token expression it discovered, what it observed, and - importantly - what it did not observe,
because that is what decides whether a correlation can ever be called verified.
"""

from __future__ import annotations

from perfgen.ir.models import Confidence, TestPlanIR, TokenConfidence
from perfgen.probe.runner import ProbeOutcome


def apply_outcome(ir: TestPlanIR, outcome: ProbeOutcome) -> TestPlanIR:
    """Update the IR in place with the probe's findings and return it."""
    record = outcome.record

    ir.provenance.probe.performed = not record.degraded
    ir.provenance.probe.timestamp = record.performed_at
    ir.provenance.probe.steps_observed = record.steps_observed
    ir.provenance.probe.skipped_flows = record.skipped_flow_ids
    ir.provenance.probe.degraded = record.degraded

    if ir.auth.token_extract is not None and outcome.token_expr is not None:
        ir.auth.token_extract.expr = outcome.token_expr
        ir.auth.token_extract.confidence = outcome.token_confidence

    _downgrade_unobserved_correlations(ir, record.skipped_flow_ids, record.degraded)
    return ir


def _downgrade_unobserved_correlations(
    ir: TestPlanIR, skipped: list[str], degraded: bool
) -> None:
    """Nothing the probe did not see may claim to be verified.

    A flow that was skipped, or a run where the probe never happened, cannot produce evidence. Any
    extractor on it is a guess, and a guess labelled `verified` is worse than one labelled
    `inferred` - it stops a reviewer looking at the thing most likely to be wrong.
    """
    for flow in ir.flows:
        if not degraded and flow.id not in skipped:
            continue
        for step in flow.steps:
            for extract in step.extracts:
                if extract.confidence is Confidence.VERIFIED:
                    extract.confidence = Confidence.INFERRED

    if degraded and ir.auth.token_extract is not None:
        ir.auth.token_extract.confidence = TokenConfidence.UNKNOWN

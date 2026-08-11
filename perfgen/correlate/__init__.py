"""Correlation: a deterministic candidate scan, then exactly one LLM call to adjudicate it."""

from perfgen.correlate.adjudicate import Adjudicator, ClaudeAdjudicator, build_prompt
from perfgen.correlate.engine import CorrelationOutcome, correlate
from perfgen.correlate.models import Adjudication, AdjudicationResult, Candidate, ScanResult
from perfgen.correlate.scan import find_candidates

__all__ = [
    "Adjudication",
    "AdjudicationResult",
    "Adjudicator",
    "Candidate",
    "ClaudeAdjudicator",
    "CorrelationOutcome",
    "ScanResult",
    "build_prompt",
    "correlate",
    "find_candidates",
]

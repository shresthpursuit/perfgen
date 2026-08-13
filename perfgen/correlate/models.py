"""What the scan finds and what the adjudicator decides.

These are separate types on purpose. A `Candidate` is an observation - this string came back here
and was sent there - and carries no judgement. An `Adjudication` is a decision about one, and it
is the only thing in the pipeline an LLM produces. Keeping them apart is what makes the scan
testable without a model and the model's output checkable against a schema.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from perfgen.ir.models import Confidence, ExtractorType, Scope, Source


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


SourceKind = Literal["response_body", "response_header", "cookie"]
UseKind = Literal["path", "query", "header", "body"]


class Candidate(_Base):
    """A value that came back from the server and later went out again, unchanged."""

    id: int
    value: str

    source_flow_id: str | None = Field(default=None, description="null for the auth call")
    source_step_index: int | None = None
    source_step_name: str
    source_kind: SourceKind
    source_location: str = Field(description="json path, header name or cookie name")

    used_flow_id: str
    used_step_index: int
    used_step_name: str
    used_kind: UseKind
    used_detail: str = Field(description="header name, or the surrounding text of the match")

    declared_placeholder: str | None = Field(
        default=None,
        description=(
            "The `{placeholder}` in the spec that this value filled, when the probe recorded one. "
            "A declared dependency rather than a coincidental string match."
        ),
    )

    @property
    def same_flow(self) -> bool:
        return self.source_flow_id == self.used_flow_id

    def as_ir_source(self) -> Source:
        return {
            "response_body": Source.RESPONSE_BODY,
            "response_header": Source.RESPONSE_HEADER,
            "cookie": Source.COOKIE,
        }[self.source_kind]

    def used_by(self) -> str:
        """The `F01.2.path` reference the IR records on an extractor."""
        return f"{self.used_flow_id}.{self.used_step_index}.{self.used_kind}"


class Rejection(_Base):
    """A candidate the deterministic filters removed, kept so the run can explain itself."""

    value: str
    filter_name: Literal["low_entropy", "client_originated"]
    reason: str
    source_step_name: str
    used_step_name: str


class UnreadableBody(_Base):
    """A response whose body the scan could not index.

    Distinct from a `Rejection`, which is a judgement about a candidate the scan found. This is
    the scan admitting it could not look: nothing was examined, so nothing could be rejected
    either. Without it, "0 candidates, 0 rejected" reads as "there was nothing there" when it may
    mean "I could not read this".
    """

    step_name: str
    flow_id: str | None = None
    step_index: int | None = None
    content_type: str = Field(default="", description="as the server declared it, if at all")
    body_bytes: int = 0
    parse_error: str = ""

    def describe(self) -> str:
        where = (
            f"{self.flow_id} step {self.step_index} ({self.step_name})"
            if self.flow_id
            else self.step_name
        )
        kind = self.content_type or "no Content-Type declared"
        return f"{where}: {self.body_bytes}-byte {kind} body could not be parsed as JSON"


class ScanResult(_Base):
    candidates: list[Candidate] = Field(default_factory=list)
    rejected: list[Rejection] = Field(default_factory=list)
    unreadable: list[UnreadableBody] = Field(default_factory=list)

    @property
    def summary(self) -> str:
        text = (
            f"{len(self.candidates)} candidate(s) survived, "
            f"{len(self.rejected)} rejected by the filters"
        )
        if self.unreadable:
            text += f", {len(self.unreadable)} response body/bodies unreadable"
        return text


class Adjudication(_Base):
    """The model's decision about one candidate. Schema-validated; nothing else is trusted."""

    candidate_id: int
    accept: bool
    var: str = Field(default="", description="variable name to extract into")
    extractor: ExtractorType = ExtractorType.JSON_PATH
    scope: Scope = Scope.ITERATION
    transformed: bool = Field(
        default=False,
        description="the value appears altered rather than copied - base64, hashed, recomputed",
    )
    evidence: str = ""
    reason: str = Field(default="", description="why it was rejected, when accept is false")


class AdjudicationResult(_Base):
    decisions: list[Adjudication] = Field(default_factory=list)
    model: str = Field(default="", description="which model answered, for provenance")

    def accepted(self) -> list[Adjudication]:
        return [d for d in self.decisions if d.accept]


def confidence_for(decision: Adjudication, probe_observed: bool) -> Confidence:
    """A correlation is only ever `verified` when traffic was seen and nothing was transformed.

    A transformed value that is emitted as a confident extractor fails silently under load, which
    is the worst outcome available: the script runs, reports success, and measures nothing.
    """
    if not probe_observed or decision.transformed:
        return Confidence.INFERRED
    return Confidence.VERIFIED

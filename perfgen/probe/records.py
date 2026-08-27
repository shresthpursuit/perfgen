"""The traffic record the probe writes and the correlation engine reads.

Persisted as JSON rather than YAML: response bodies are arbitrary payloads, and JSON keeps them
exact without the quoting and block-scalar decisions YAML would impose on every one.

This file is the input to M4. It is written to `data/probe/`, which is gitignored - it holds real
response bodies from a live environment.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


# The generated /authorize call in a PKCE sequence, which is not a declared step. Zero because
# the parser requires declared step numbers to be 1 or greater, so it can never collide with
# one. Lives here rather than in the runner because both the probe that writes it and the
# correlation engine that reads it need it, and runner imports correlate.
AUTHORIZE_STEP_INDEX = 0


class RecordedRequest(_Base):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class RecordedResponse(_Base):
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    elapsed_ms: int = 0


class RecordedCall(_Base):
    """One request/response pair, tagged with where it came from in the spec."""

    flow_id: str | None = Field(default=None, description="null for the auth call")
    step_index: int | None = None
    name: str
    request: RecordedRequest
    response: RecordedResponse | None = None
    error: str | None = Field(default=None, description="set when the call could not complete")

    placeholder_bindings: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Placeholders in this step's path that the probe filled from an earlier response, "
            "as {varName: json_path}. A probe-time hypothesis so the flow can be walked at all - "
            "the correlation engine decides what actually becomes an extractor."
        ),
    )
    fallback_bindings: list[str] = Field(
        default_factory=list,
        description=(
            "Which of those bindings came from the preceding step's generic `id` rather than a "
            "field whose name actually matched. A weaker piece of evidence, kept distinguishable "
            "so it can be said so in the extractor's evidence rather than blending in."
        ),
    )

    @property
    def succeeded(self) -> bool:
        return self.error is None and self.response is not None


class SkippedFlow(_Base):
    flow_id: str
    reason: str


class ProbeRecord(_Base):
    application: str
    performed_at: str
    degraded: bool = False
    degraded_reason: str | None = None
    skipped_flows: list[SkippedFlow] = Field(default_factory=list)
    calls: list[RecordedCall] = Field(default_factory=list)

    redaction_note: str = (
        "Credential values and the auth token are redacted from headers and request bodies. "
        "Response bodies are stored verbatim - the correlation engine matches values across "
        "them, so redacting them would remove what it reads. Treat this file as sensitive."
    )

    @property
    def steps_observed(self) -> int:
        return sum(1 for call in self.calls if call.succeeded and call.flow_id is not None)

    @property
    def skipped_flow_ids(self) -> list[str]:
        return [skip.flow_id for skip in self.skipped_flows]

    def calls_for(self, flow_id: str) -> list[RecordedCall]:
        return [call for call in self.calls if call.flow_id == flow_id]


def dump_record(record: ProbeRecord, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(record.model_dump(mode="json"), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return target


def load_record(path: str | Path) -> ProbeRecord:
    return ProbeRecord.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))

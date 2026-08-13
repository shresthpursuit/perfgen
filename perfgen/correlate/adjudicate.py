"""The one LLM call in the tool.

Everything else - parsing, HTTP, matching, XML - has a right answer and is written as ordinary
code. This does not: deciding whether a string that travelled from one response to a later request
is a real dependency, what to call it, and how long it should live, is a judgement call over
evidence.

Three rules hold the blast radius down:

* **The model never emits XML, or an IR, or a file path.** It returns decisions about candidates
  the deterministic scan already found, validated against a schema. Anything malformed is dropped,
  not repaired.
* **It cannot invent a correlation.** Every decision references a `candidate_id` from the scan;
  ids it made up are discarded.
* **It is never called when there is nothing to decide.** No candidates, or no probe traffic at
  all, means no request is sent - an adjudication of an empty list is a fabrication waiting to
  happen, and a wasted call besides.
"""

from __future__ import annotations

import json
import re
from typing import Protocol

from perfgen.correlate.models import Adjudication, AdjudicationResult, Candidate

SYSTEM_PROMPT = """\
You are adjudicating candidate value correlations for a generated JMeter performance test.

A deterministic scan has already found strings that appeared in one HTTP response and then in a
later HTTP request. Your job is to decide which of them are real server-generated dependencies
that must be extracted and replayed, and to describe how.

For each candidate, decide:

- accept: true if the later request genuinely depends on the value the earlier response produced.
  false if it is a coincidence, a constant, or something the client would send anyway.
- var: a short camelCase variable name describing the value (itemId, requestRef, sessionToken).
- extractor: match it to the body the value came from. json_path for a JSON body, xpath for an
  XML body (the location given is already a valid XPath), regex for a form-encoded body, header
  when the value came from a response header. boundary only when none of those fit. Choosing an
  extractor that cannot read the format it is pointed at produces a script that runs and extracts
  nothing.
- scope: iteration for values re-fetched every pass through a flow, which is almost all record
  identifiers. thread for values established once per virtual user, such as a session. global for
  values shared by every user, such as a single shared auth token.
- transformed: true if the value appears altered rather than copied - base64 wrapped, hashed,
  truncated, concatenated with something else, or a recomputed timestamp. Set this whenever the
  later request does not contain the earlier value verbatim, and when in doubt.
- evidence: one sentence, concrete, saying what was observed. Not a restatement of the rule.

Guidance that matters:

- Scope is the most expensive thing to get wrong. A value scoped too widely makes every virtual
  user share one record and the test measures the wrong thing under load while passing a
  single-user smoke test. When unsure between iteration and thread, choose iteration.
- Do not accept a value merely because the scan found it. The scan matches strings; you are the
  step that asks whether the match means anything.
- A transformed value must never be presented as a confident extractor. Mark it transformed and
  say so in the evidence.

Reply with JSON only, no prose and no code fences, in exactly this shape:

{"decisions": [{"candidate_id": 1, "accept": true, "var": "itemId",
  "extractor": "json_path", "scope": "iteration", "transformed": false,
  "evidence": "...", "reason": ""}]}

Include exactly one entry per candidate you were given, using its candidate_id.
"""


class Adjudicator(Protocol):
    """Anything that can turn candidates into decisions. Injected, so tests never hit a model."""

    def adjudicate(self, candidates: list[Candidate]) -> AdjudicationResult: ...


def build_prompt(candidates: list[Candidate]) -> str:
    """Render the candidates as the user turn of the single call."""
    lines = [
        f"{len(candidates)} candidate correlation(s) were found. Adjudicate each one.",
        "",
    ]
    for candidate in candidates:
        lines.append(f"Candidate {candidate.id}:")
        lines.append(f"  value observed:   {candidate.value!r}")
        lines.append(
            f"  produced by:      {candidate.source_step_name}"
            + (
                f" (flow {candidate.source_flow_id}, step {candidate.source_step_index})"
                if candidate.source_flow_id
                else " (the authentication call)"
            )
        )
        lines.append(
            f"  found in:         {candidate.source_kind} at {candidate.source_location}"
            + (f" (a {candidate.body_format} body)" if candidate.body_format else "")
        )
        lines.append(
            f"  reused by:        {candidate.used_step_name} "
            f"(flow {candidate.used_flow_id}, step {candidate.used_step_index})"
        )
        lines.append(f"  reused in the:    {candidate.used_kind} -> {candidate.used_detail}")
        lines.append(
            f"  same flow:        {'yes' if candidate.same_flow else 'no'}"
        )
        if candidate.declared_placeholder:
            lines.append(
                f"  declared:         the specification writes "
                f"{{{candidate.declared_placeholder}}} at this position, so its author states "
                f"this call depends on the earlier one"
            )
        lines.append("")
    return "\n".join(lines)


def parse_response(text: str, candidates: list[Candidate]) -> AdjudicationResult:
    """Validate the model's reply against the schema and the candidate list.

    Anything that does not fit is dropped rather than coerced: a half-understood decision about a
    correlation is worse than no decision, because it reaches the generated script either way.
    """
    payload = _extract_json(text)
    if payload is None:
        return AdjudicationResult()

    known = {candidate.id for candidate in candidates}
    decisions: list[Adjudication] = []
    for raw in payload.get("decisions", []):
        try:
            decision = Adjudication.model_validate(raw)
        except Exception:
            continue  # malformed entry, not repairable without guessing what was meant
        if decision.candidate_id not in known:
            continue  # an id the scan never produced: the model invented a correlation
        if decision.accept and not decision.var.strip():
            continue  # accepted but unnamed is unusable
        decisions.append(decision)

    return AdjudicationResult(decisions=decisions)


def _extract_json(text: str) -> dict | None:
    """Pull the JSON object out of a reply, tolerating code fences and stray prose."""
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        pass

    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        return None


class ClaudeAdjudicator:
    """The real call site, via the Claude Agent SDK.

    `model` comes from `config.yaml` and is passed through. `temperature` cannot be: the SDK's
    options carry no temperature, and passing `--temperature` to the underlying CLI fails the call
    with "unknown option". Rather than accept a setting and ignore it, the configuration layer
    reports it as unsupported and the run summary prints that - see
    `LLMConfig.unsupported_settings`.
    """

    def __init__(self, model: str = ""):
        self.model = model

    @classmethod
    def from_config(cls, config) -> ClaudeAdjudicator:
        return cls(model=config.llm.model)

    def adjudicate(self, candidates: list[Candidate]) -> AdjudicationResult:
        if not candidates:
            return AdjudicationResult()

        text = self._ask(build_prompt(candidates))
        result = parse_response(text, candidates)
        result.model = self.model or "provider default"
        return result

    def _ask(self, prompt: str) -> str:
        """One request, one response. Kept separate so the transport can be swapped or faked."""
        import anyio
        from claude_agent_sdk import ClaudeAgentOptions, query

        async def run() -> str:
            options = ClaudeAgentOptions(
                system_prompt=SYSTEM_PROMPT,
                max_turns=1,
                allowed_tools=[],  # adjudication is a judgement, not a task with side effects
                **({"model": self.model} if self.model else {}),
            )
            chunks: list[str] = []
            async for message in query(prompt=prompt, options=options):
                for block in getattr(message, "content", []) or []:
                    piece = getattr(block, "text", None)
                    if piece:
                        chunks.append(piece)
            return "".join(chunks)

        return anyio.run(run)

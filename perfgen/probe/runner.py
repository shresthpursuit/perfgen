"""Executing the spec once, single-threaded, and writing down what happened.

The probe exists to answer questions the spreadsheet cannot: what does the auth response actually
look like, and which values does the server generate that a later request has to carry. It runs
each flow once, in step order, and records everything.

Three rules shape it:

* **A flow marked unsafe is never called.** Not once, not to "just check". The user answered No
  because the flow creates, changes or deletes real data. The skip is recorded and the flow's
  correlations are marked inferred.
* **Failure is degraded mode, not an exception.** An unreachable environment or a missing
  credential still produces a run: the correlations become inferred, and that fact travels all the
  way into a comment in the generated script.
* **Secrets live in memory only.** They are resolved here, used here, and redacted out of the
  record before it touches disk.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx

from perfgen import secrets
from perfgen.ir.models import (
    AuthType,
    Flow,
    Step,
    TestPlanIR,
    TokenConfidence,
)
from perfgen.probe.records import (
    ProbeRecord,
    RecordedCall,
    RecordedRequest,
    RecordedResponse,
    SkippedFlow,
)
from perfgen.probe.redact import Redactor

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Where an OAuth response usually carries the token, most specific first.
_TOKEN_KEYS = ("access_token", "accessToken", "id_token", "idToken", "token", "jwt")

DEFAULT_TIMEOUT_S = 30


@dataclass
class ProbeOutcome:
    record: ProbeRecord
    token_expr: str | None = None
    token_confidence: TokenConfidence = TokenConfidence.UNKNOWN
    warnings: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return self.record.degraded


def run_probe(
    ir: TestPlanIR,
    *,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    client: httpx.Client | None = None,
) -> ProbeOutcome:
    """Run the auth call and every safe flow once. Never raises for an unreachable environment."""
    record = ProbeRecord(
        application=ir.application.name,
        performed_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    outcome = ProbeOutcome(record=record)
    redactor = Redactor()

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout_s, follow_redirects=True)

    try:
        token = _acquire_token(ir, http, record, redactor, outcome)
        if ir.auth.type is not AuthType.NONE and token is None and not record.degraded:
            # Auth was configured and did not work. Flows would all 401; that is not useful
            # traffic, and hammering an environment with doomed requests is worse than stopping.
            _degrade(record, outcome, "the auth call did not return a usable token")

        if not record.degraded:
            _run_flows(ir, http, record, redactor, outcome, token)
        else:
            for flow in ir.flows:
                record.skipped_flows.append(
                    SkippedFlow(flow_id=flow.id, reason="the probe could not run")
                )
    finally:
        if owns_client:
            http.close()

    return outcome


# --------------------------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------------------------


def _acquire_token(
    ir: TestPlanIR,
    http: httpx.Client,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
) -> str | None:
    request_spec = ir.auth.token_request
    if ir.auth.type is AuthType.NONE or request_spec is None:
        return None

    try:
        resolved = secrets.resolve_all(request_spec.credential_refs)
    except RuntimeError as exc:
        # A missing credential is a configuration problem, not a broken environment: say exactly
        # which variable, and continue in degraded mode rather than half-running the spec.
        _degrade(record, outcome, str(exc))
        return None

    for value in resolved.values():
        redactor.add_secret(value)

    try:
        body = _token_body(request_spec.param_names, resolved)
    except secrets.MissingSecrets as exc:
        _degrade(record, outcome, str(exc))
        return None

    headers = {"Content-Type": request_spec.content_type}

    call = RecordedCall(
        name="Acquire token",
        request=RecordedRequest(
            method=request_spec.method.upper(),
            url=request_spec.url,
            headers=redactor.headers(headers),
            body=redactor.body(body, request_spec.content_type),
        ),
    )

    try:
        response = http.request(
            request_spec.method.upper(), request_spec.url, content=body, headers=headers
        )
    except httpx.HTTPError as exc:
        call.error = f"{type(exc).__name__}: {exc}"
        record.calls.append(call)
        _degrade(record, outcome, f"the token endpoint could not be reached: {exc}")
        return None

    token, expr = _find_token(response)
    if token:
        redactor.add_secret(token)
        outcome.token_expr = expr
        outcome.token_confidence = TokenConfidence.VERIFIED
    else:
        outcome.warnings.append(
            f"The token endpoint returned {response.status_code} but no recognisable token field. "
            f"Looked for {', '.join(_TOKEN_KEYS)} in the response body and an Authorization "
            f"header. The token extractor is left unset."
        )

    call.response = _record_response(response, redactor)
    record.calls.append(call)
    return token


def _token_body(param_names: list[str], resolved: dict[str, str]) -> str:
    """Build the token request body, matching each parameter to a credential by name.

    A parameter with no matching credential reference is still a value the spec did not supply -
    `grant_type` is the usual one. It is read from the environment under its own name. If it is
    not there either, that is a missing input, not a reason to send an empty string: an empty
    `client_id` produces an authentication failure that looks like a broken API rather than a
    missing variable.
    """
    from perfgen.emit.naming import match_credential_ref

    parts: list[tuple[str, str]] = []
    missing: list[tuple[str, str]] = []

    for name in param_names:
        reference = match_credential_ref(name, list(resolved))
        if reference is not None:
            parts.append((name, resolved[reference]))
            continue
        try:
            parts.append((name, secrets.resolve(name)))
        except secrets.MissingSecret as exc:
            missing.append((f"token parameter {name!r}", exc.variable))

    if missing:
        raise secrets.MissingSecrets(missing)
    return urlencode(parts)


def _find_token(response: httpx.Response) -> tuple[str | None, str | None]:
    """Locate the token in the response, returning (value, json path expression)."""
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        payload = None

    if isinstance(payload, dict):
        for key in _TOKEN_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value, f"$.{key}"
        # Some providers nest it one level down.
        for outer, inner in payload.items():
            if isinstance(inner, dict):
                for key in _TOKEN_KEYS:
                    value = inner.get(key)
                    if isinstance(value, str) and value:
                        return value, f"$.{outer}.{key}"

    header = response.headers.get("authorization")
    if header:
        return header.split(" ", 1)[-1], None

    return None, None


# --------------------------------------------------------------------------------------------
# Flows
# --------------------------------------------------------------------------------------------


def _run_flows(
    ir: TestPlanIR,
    http: httpx.Client,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
    token: str | None,
) -> None:
    base = ir.application.base_url.rstrip("/") + (ir.application.base_path or "")

    for flow in ir.flows:
        if not flow.probe_safe:
            # The user said this flow writes data they cannot afford to have written.
            record.skipped_flows.append(
                SkippedFlow(
                    flow_id=flow.id,
                    reason="marked not safe to run against this environment",
                )
            )
            outcome.warnings.append(
                f"Flow {flow.id} ({flow.name}) was not called: it is marked unsafe for this "
                f"environment. Its correlations can only be inferred."
            )
            continue

        _run_flow(flow, base, ir, http, record, redactor, outcome, token)


def _run_flow(
    flow: Flow,
    base: str,
    ir: TestPlanIR,
    http: httpx.Client,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
    token: str | None,
) -> None:
    # Values seen so far in this flow's responses, so a later step's {placeholder} can be filled.
    seen: dict[str, tuple[str, str]] = {}  # lowercased key -> (value, json path)

    for step in flow.steps:
        path, bindings, unresolved = _resolve_path(step.path, seen)
        url = f"{base}{path}"
        headers = _step_headers(step, flow, ir, token)

        call = RecordedCall(
            flow_id=flow.id,
            step_index=step.index,
            name=step.name,
            request=RecordedRequest(
                method=step.method.value,
                url=url,
                headers=redactor.headers(headers),
                body=redactor.body(step.body, step.content_type),
            ),
            placeholder_bindings=bindings,
        )

        if unresolved:
            outcome.warnings.append(
                f"{flow.id} step {step.index} ({step.name}): no earlier response supplied "
                f"{', '.join('{' + name + '}' for name in unresolved)}, so the request was sent "
                f"with the placeholder text in place and probably failed."
            )

        try:
            response = http.request(
                step.method.value, url, content=step.body, headers=headers
            )
        except httpx.HTTPError as exc:
            call.error = f"{type(exc).__name__}: {exc}"
            record.calls.append(call)
            outcome.warnings.append(
                f"{flow.id} step {step.index} ({step.name}) could not be called: {exc}"
            )
            continue

        call.response = _record_response(response, redactor)
        record.calls.append(call)

        if response.status_code != step.expected_status:
            outcome.warnings.append(
                f"{flow.id} step {step.index} ({step.name}) returned "
                f"{response.status_code}, not the expected {step.expected_status}. "
                f"Correlations found from here on are less trustworthy."
            )

        _index_response(response, seen)


def _step_headers(step: Step, flow: Flow, ir: TestPlanIR, token: str | None) -> dict[str, str]:
    headers = {**flow.headers, **step.headers}
    if step.content_type:
        headers.setdefault("Content-Type", step.content_type)
    if token and ir.auth.header_name:
        template = ir.auth.value_format or "{token}"
        headers[ir.auth.header_name] = template.replace("{token}", token)
    return headers


def _resolve_path(
    path: str, seen: dict[str, tuple[str, str]]
) -> tuple[str, dict[str, str], list[str]]:
    """Fill `{placeholder}` from an earlier response so the flow can actually be walked.

    Matching is by name: `{itemId}` looks for a JSON key `itemId`, then `id`. This is a probe-time
    hypothesis recorded as evidence, not a correlation decision - the correlation engine makes
    those, from the traffic this produces.
    """
    bindings: dict[str, str] = {}
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        candidate = seen.get(name.lower())
        if candidate is None and name.lower().endswith("id"):
            candidate = seen.get("id")
        if candidate is None:
            unresolved.append(name)
            return match.group(0)
        value, json_path = candidate
        bindings[name] = json_path
        return value

    return _PLACEHOLDER.sub(replace, path), bindings, unresolved


def _index_response(response: httpx.Response, seen: dict[str, tuple[str, str]]) -> None:
    """Remember every scalar leaf of a JSON response, keyed by its field name."""
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        return
    _walk(payload, "$", seen)


def _walk(node: Any, path: str, seen: dict[str, tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _walk(value, f"{path}.{key}", seen)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, f"{path}[{index}]", seen)
    elif isinstance(node, str | int | float) and not isinstance(node, bool):
        key = path.rsplit(".", 1)[-1].split("[")[0].lower()
        # First occurrence wins: the first `id` in a search result is the one a user would click.
        if key and key not in seen:
            seen[key] = (str(node), path)


def _record_response(response: httpx.Response, redactor: Redactor) -> RecordedResponse:
    return RecordedResponse(
        status=response.status_code,
        headers=redactor.headers(dict(response.headers)),
        cookies=redactor.cookies(dict(response.cookies)),
        # Response bodies are kept verbatim: the correlation scan reads them. Known secret values
        # are still replaced, so a token echoed back in a body does not survive.
        body=redactor.scrub(response.text),
        elapsed_ms=_elapsed_ms(response),
    )


def _elapsed_ms(response: httpx.Response) -> int:
    """Timing is a nice-to-have here; the record is about content, not performance."""
    try:
        return int(response.elapsed.total_seconds() * 1000)
    except RuntimeError:
        # Not set unless the response was read and closed - true of some transports.
        return 0


def _degrade(record: ProbeRecord, outcome: ProbeOutcome, reason: str) -> None:
    record.degraded = True
    record.degraded_reason = reason
    outcome.warnings.append(
        f"The probe could not run: {reason}. Correlations will be inferred from placeholder "
        f"names rather than observed traffic, and must be reviewed before the script is trusted."
    )

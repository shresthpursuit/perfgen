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

import base64
import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx

from perfgen import secrets
from perfgen.correlate import text
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


def _set_content_type(headers: dict[str, str], content_type: str | None) -> None:
    """Add a Content-Type only if the spec did not already give one, in any spelling.

    Header names are case-insensitive, `dict.setdefault` is not. A spec writing `Content-type`
    therefore got a second `Content-Type` alongside it, and Entra answers a request carrying two
    with `400 Bad Request - Invalid Header` - which reads as a problem with the body or the
    credentials, and is neither.
    """
    if not content_type:
        return
    if any(name.lower() == "content-type" for name in headers):
        return
    headers["Content-Type"] = content_type


def _pkce_pair() -> tuple[str, str]:
    """A verifier and its S256 challenge - RFC 7636, the same transformation the JMX performs."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _register_step_secrets(refs: list[str], redactor: Redactor) -> dict[str, str]:
    """Resolve every credential the login steps name, registering each before returning any.

    The ordering is the guarantee, not an implementation detail: `RecordedCall` runs its body and
    headers through the redactor, so a value that reaches the recorder before `add_secret` is a
    value written to disk. Registration happens inside this function and the values leave it only
    afterwards, so no arrangement of the caller can invert it.
    """
    resolved: dict[str, str] = {}
    for reference in refs:
        value = secrets.resolve(reference)
        redactor.add_secret(value)
        resolved[reference] = value
    return resolved


def _resolve_step_secrets(text_value: str, resolved: dict[str, str]) -> str:
    """Substitute `{secret:name}` from values already resolved and handed to the redactor.

    Takes a mapping rather than resolving here, so resolution and `add_secret` stay together at one
    call site. The value is substituted verbatim, exactly as the generated script will substitute
    it at run time - encoding it here and not there would make the probe succeed where the script
    fails, which is the one disagreement that is worse than both failing.
    """
    return secrets.substitute(text_value, lambda name: resolved.get(name, f"{{secret:{name}}}"))


def _pkce_client_credential(ir: TestPlanIR) -> str:
    """The client id, resolved from the environment like every other credential."""
    from perfgen.emit import naming

    request = ir.auth.token_request
    refs = request.credential_refs if request else []
    matched = naming.match_credential_ref("client_id", refs)
    return secrets.resolve(matched or "client_id")


def _authorization_code(response: httpx.Response) -> str | None:
    location = response.headers.get("location", "")
    match = re.search(r"[?&#]code=([^&#]+)", location)
    return match.group(1) if match else None


def _origin_of(url: str) -> str:
    parts = httpx.URL(url)
    return f"{parts.scheme}://{parts.netloc.decode()}"


def _record_auth_call(
    http: httpx.Client,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
    name: str,
    method: str,
    url: str,
    body: str | None,
    headers: dict[str, str],
    *,
    follow_redirects: bool = True,
    register: Callable[[httpx.Response], None] | None = None,
) -> httpx.Response | None:
    """Make one call in the auth sequence and record it, redacted.

    `register` exists because a response can carry a credential the request did not: the token
    exchange answers with the access token in its body. It runs after the request and before the
    response is recorded, which puts that ordering inside this function rather than leaving it to
    be re-established correctly at every call site. Getting it wrong writes the token to disk, and
    a first version of this did exactly that.
    """
    call = RecordedCall(
        name=name,
        request=RecordedRequest(
            method=method,
            # Scrubbed like the body and the headers. A query string is an ordinary place for
            # a credential to travel - OAuth puts client_id in one on every authorize call -
            # and recording the URL verbatim wrote it straight to disk.
            url=redactor.scrub(url) or url,
            headers=redactor.headers(headers),
            body=redactor.body(body, headers.get("Content-Type")),
        ),
    )
    try:
        response = http.request(
            method, url, content=body, headers=headers, follow_redirects=follow_redirects
        )
    except httpx.HTTPError as exc:
        call.error = f"{type(exc).__name__}: {exc}"
        record.calls.append(call)
        outcome.warnings.append(f"{name} could not be called: {exc}")
        return None

    if register is not None:
        register(response)
    call.response = _record_response(response, redactor)
    record.calls.append(call)
    return response


def _acquire_pkce_token(
    ir: TestPlanIR,
    http: httpx.Client,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
) -> str | None:
    """Walk the whole PKCE exchange: authorize, the declared login steps, then the token call.

    Every request is recorded, so correlation sees the login sequence as observed traffic and its
    extractors come from what actually came back rather than from placeholder names.
    """
    auth = ir.auth
    request_spec = auth.token_request
    if request_spec is None or not auth.authorize_url:
        return None

    try:
        step_secrets = _register_step_secrets(auth.step_credential_refs, redactor)
        # Registered like any other resolved reference. It is a public OAuth identifier rather
        # than a secret, but the spec declared it through `Credential reference names`, and the
        # rule that a resolved reference never reaches disk does not have an exemption for values
        # that look harmless - deciding which ones do is exactly the judgement that goes wrong.
        client_id = _pkce_client_credential(ir)
        redactor.add_secret(client_id)
    except RuntimeError as exc:
        _degrade(record, outcome, str(exc))
        return None

    for cookie in auth.seed_cookies:
        http.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)

    verifier, challenge = _pkce_pair()
    seen: dict[str, tuple[str, str]] = {}

    authorize_url = f"{auth.authorize_url}?" + urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "scope": auth.scope or "",
            "redirect_uri": auth.redirect_uri or "",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    response = _record_auth_call(
        http, record, redactor, outcome, "Authorize", "GET", authorize_url, None, {}
    )
    if response is None:
        _degrade(record, outcome, "the /authorize request could not be made")
        return None
    _index_response(response, seen, wanted=_outstanding(auth.flow_steps, 0))

    code = _walk_auth_steps(ir, http, record, redactor, outcome, seen, step_secrets)
    if code is None:
        return None

    body = urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": auth.redirect_uri or "",
            "code_verifier": verifier,
            "client_id": client_id,
        }
    )
    # The token arrives in this response's body, so it must be registered with the redactor before
    # that body is recorded - see `_record_auth_call`.
    issued: list[tuple[str | None, str | None]] = []

    def register_token(response: httpx.Response) -> None:
        token, expr = _find_token(response)
        if token:
            redactor.add_secret(token)
        issued.append((token, expr))

    response = _record_auth_call(
        http,
        record,
        redactor,
        outcome,
        "Exchange code for token",
        "POST",
        request_spec.url,
        body,
        {"Content-Type": "application/x-www-form-urlencoded"},
        register=register_token,
    )
    if response is None or response.status_code != 200:
        _degrade(
            record,
            outcome,
            f"the token exchange returned "
            f"{response.status_code if response else 'no response'}, not 200",
        )
        return None

    token, expr = issued[0] if issued else (None, None)
    if token is None:
        _degrade(record, outcome, "the token exchange succeeded but carried no access token")
        return None

    outcome.token_expr = expr
    outcome.token_confidence = TokenConfidence.VERIFIED
    return token


def _walk_auth_steps(
    ir: TestPlanIR,
    http: httpx.Client,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
    seen: dict[str, tuple[str, str]],
    step_secrets: dict[str, str],
) -> str | None:
    """Run each declared login step, returning the authorization code the last one yields."""
    auth = ir.auth
    code_step = auth.code_step
    base = _origin_of(auth.authorize_url or "")

    for step in auth.flow_steps:
        path, _, _, unresolved = _resolve_path(step.path, seen, seen)
        url = path if "://" in path else f"{base}{path}"

        body_text, _, _, body_unresolved = _resolve_path(step.body or "", seen, seen)
        headers, _, _, header_unresolved = _resolve_headers(step.headers, seen, seen)
        _set_content_type(headers, step.content_type)

        missing = [*unresolved, *body_unresolved, *header_unresolved]
        if missing:
            outcome.warnings.append(
                f"Auth step {step.index} ({step.name}): nothing supplied "
                f"{', '.join('{' + name + '}' for name in missing)}, so the request was sent with "
                f"the placeholder text in place and probably failed."
            )

        body_text = _resolve_step_secrets(body_text, step_secrets)
        headers = {k: _resolve_step_secrets(v, step_secrets) for k, v in headers.items()}

        is_code_step = code_step is not None and step.index == code_step.index
        response = _record_auth_call(
            http,
            record,
            redactor,
            outcome,
            step.name,
            step.method.value,
            url,
            body_text or None,
            headers,
            # Explicit, never inherited. The authorization code arrives in a Location header, and a
            # followed redirect consumes it before anything can read it. httpx happens to default
            # to not following, which is exactly the kind of unstated default the reference script
            # relies on and which one library upgrade would quietly reverse.
            follow_redirects=not is_code_step,
        )
        if response is None:
            _degrade(record, outcome, f"auth step {step.index} ({step.name}) could not be called")
            return None
        if response.status_code != step.expected_status:
            outcome.warnings.append(
                f"Auth step {step.index} ({step.name}) returned {response.status_code}, not the "
                f"expected {step.expected_status}."
            )

        _index_response(response, seen, wanted=_outstanding(auth.flow_steps, step.index))

        if is_code_step:
            code = _authorization_code(response)
            if code is None:
                _degrade(
                    record,
                    outcome,
                    f"auth step {step.index} ({step.name}) was expected to produce an "
                    f"authorization code in its Location header, and did not",
                )
                return None
            return code

    _degrade(record, outcome, "no auth flow step produced an authorization code")
    return None


def _acquire_token(
    ir: TestPlanIR,
    http: httpx.Client,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
) -> str | None:
    if ir.auth.type is AuthType.NONE:
        return None

    if ir.auth.type.is_static_credential:
        return _static_credential(ir, record, redactor, outcome)

    if ir.auth.type is AuthType.OAUTH2_PKCE:
        return _acquire_pkce_token(ir, http, record, redactor, outcome)

    request_spec = ir.auth.token_request
    if request_spec is None:
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


def _static_credential(
    ir: TestPlanIR,
    record: ProbeRecord,
    redactor: Redactor,
    outcome: ProbeOutcome,
) -> str | None:
    """Resolve the credential for a scheme that has no token call.

    There is nothing to request, but the flows still have to be probed authenticated - otherwise
    every step 401s and the run captures no useful traffic.
    """
    refs = ir.auth.static_credential_refs
    if not refs:
        _degrade(record, outcome, f"{ir.auth.type} has no credential reference to read")
        return None

    try:
        resolved = secrets.resolve_all(refs)
    except RuntimeError as exc:
        _degrade(record, outcome, str(exc))
        return None

    for value in resolved.values():
        redactor.add_secret(value)

    if ir.auth.type is AuthType.BASIC and len(refs) == 2:
        pair = f"{resolved[refs[0]]}:{resolved[refs[1]]}"
        encoded = base64.b64encode(pair.encode()).decode()
        redactor.add_secret(encoded)
        return encoded

    return resolved[refs[0]]


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
    seen: dict[str, tuple[str, str]] = {}  # normalised key -> (value, json path), whole flow
    preceding: dict[str, tuple[str, str]] = {}  # the immediately previous response, alone

    for step in flow.steps:
        path, bindings, fallback, unresolved = _resolve_path(step.path, seen, preceding)
        url = f"{base}{path}"
        headers = _step_headers(step, flow, ir, token)

        # The body and the headers carry placeholders too, and until this was wired the body went
        # out verbatim - a login step posting {"originalRequest":"{sCtx}"} sent that literal text.
        # They share `seen`, so a value found once is available wherever it is referenced.
        body, body_bindings, body_fallback, body_unresolved = _resolve_path(
            step.body or "", seen, preceding
        )
        headers, header_bindings, header_fallback, header_unresolved = _resolve_headers(
            headers, seen, preceding
        )
        bindings = {**bindings, **body_bindings, **header_bindings}
        fallback = [*fallback, *body_fallback, *header_fallback]
        unresolved = [*unresolved, *body_unresolved, *header_unresolved]
        body = body or None

        call = RecordedCall(
            flow_id=flow.id,
            step_index=step.index,
            name=step.name,
            request=RecordedRequest(
                method=step.method.value,
                url=redactor.scrub(url) or url,
                headers=redactor.headers(headers),
                body=redactor.body(body, step.content_type),
            ),
            placeholder_bindings=bindings,
            fallback_bindings=fallback,
        )

        if unresolved:
            outcome.warnings.append(
                f"{flow.id} step {step.index} ({step.name}): no earlier response supplied "
                f"{', '.join('{' + name + '}' for name in unresolved)}, so the request was sent "
                f"with the placeholder text in place and probably failed."
            )

        try:
            response = http.request(step.method.value, url, content=body, headers=headers)
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

        # Index this response twice: into the running `seen` for exact-name matches anywhere in
        # the flow, and into a fresh `preceding` holding only this step, which is the sole source
        # the bare-`id` fallback is allowed to draw on.
        preceding = {}
        _index_response(response, preceding, wanted=_outstanding(flow.steps, step.index))
        for key, entry in preceding.items():
            seen.setdefault(key, entry)


def _step_headers(step: Step, flow: Flow, ir: TestPlanIR, token: str | None) -> dict[str, str]:
    """The headers a probed request carries - the same set the generated script will send.

    The application's additional headers are included because some APIs reject a request without
    them: Twitch's Helix wants Client-Id on every call. Probing without it returns 400 on
    everything, the correlation scan finds nothing in the error bodies, and the run degrades to
    guesses - a script whose correlations were never actually verified.
    """
    headers = {**ir.application.additional_headers, **flow.headers, **step.headers}
    _set_content_type(headers, step.content_type)
    if token and ir.auth.header_name:
        template = ir.auth.value_format or "{token}"
        headers[ir.auth.header_name] = template.replace("{token}", token)
    return headers


def _outstanding(steps: list[Step], after_index: int) -> list[str]:
    """Placeholder names the steps still to come will need.

    Text scanning has to be told what to look for - an HTML page cannot be enumerated the way a
    JSON body can, but the names the remaining steps reference are a short, known list.
    """
    names: list[str] = []
    for step in steps:
        if step.index <= after_index:
            continue
        for text_field in (step.path, step.body or "", *step.headers.values()):
            names.extend(_PLACEHOLDER.findall(text_field))
    return list(dict.fromkeys(names))


def _resolve_headers(
    headers: dict[str, str],
    seen: dict[str, tuple[str, str]],
    preceding: dict[str, tuple[str, str]] | None = None,
) -> tuple[dict[str, str], dict[str, str], list[str], list[str]]:
    """Fill `{placeholder}` in header values, by the same rules as the path and body.

    The reference Entra login sends `canary`, `hpgid` and `client-request-id` as headers, all of
    them correlated out of the previous response - so a header with a placeholder is not an edge
    case here, it is most of the login sequence.
    """
    resolved: dict[str, str] = {}
    bindings: dict[str, str] = {}
    fallback: list[str] = []
    unresolved: list[str] = []

    for name, value in headers.items():
        filled, found, fell_back, missing = _resolve_path(value, seen, preceding)
        resolved[name] = filled
        bindings.update(found)
        fallback.extend(fell_back)
        unresolved.extend(missing)
    return resolved, bindings, fallback, unresolved


def _resolve_path(
    path: str,
    seen: dict[str, tuple[str, str]],
    preceding: dict[str, tuple[str, str]] | None = None,
) -> tuple[str, dict[str, str], list[str], list[str]]:
    """Fill `{placeholder}` from an earlier response so the flow can actually be walked.

    Two rules, tried in order.

    **Exact name, separators ignored.** `{userId}` finds a field spelled `user_id`, `userId` or
    `USER-ID`, anywhere seen so far in the flow.

    **Otherwise, the immediately preceding step's bare `id`** - and only that step's. A resource
    endpoint answers with its own key called `id`, so `{gameId}` after a call to `/games` is the
    one guess worth making. Bounding it to the adjacent step is what matters: the original version
    searched everything seen so far, so `{userId}` at step 3 picked up a category id captured at
    step 1 and sent it confidently to a users endpoint, while the real `user_id` sat unused in
    step 2's response.

    A fallback-derived binding is reported separately from an exact match, because the correlation
    engine trusts bindings - they exempt a value from the low-entropy filter and override the
    model's chosen variable name - and a reviewer should be able to tell the two apart.
    """
    bindings: dict[str, str] = {}
    fallback: list[str] = []
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        key = normalise_field(name)

        candidate = seen.get(key)
        if candidate is None and key.endswith("id") and preceding is not None:
            candidate = preceding.get("id")
            if candidate is not None:
                fallback.append(name)

        if candidate is None:
            unresolved.append(name)
            return match.group(0)

        value, json_path = candidate
        bindings[name] = json_path
        return value

    return _PLACEHOLDER.sub(replace, path), bindings, fallback, unresolved


def _index_response(
    response: httpx.Response,
    seen: dict[str, tuple[str, str]],
    wanted: list[str] | None = None,
) -> None:
    """Remember every scalar leaf of a JSON response, keyed by its field name.

    When the body is not JSON and `wanted` names the placeholders a later step still needs, fall
    back to key-anchored text scanning. An HTML login page is the case this exists for: Entra
    returns `"sCtx":"…"` inside a script blob, nothing structured can read it, and without this the
    probe sends `{sCtx}` as literal text and the login fails.

    Text scanning is driven by what is wanted rather than by what the body holds, because an HTML
    blob cannot be enumerated into leaves while the outstanding placeholder names are a short list.
    """
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        pass
    else:
        _walk(payload, "$", seen)
        return

    if not wanted:
        return
    body = response.text
    if not body:
        return
    for name in wanted:
        key = normalise_field(name)
        if key in seen:
            continue
        match = text.find_by_key(body, name)
        if match is not None and text.verify(body, match):
            seen[key] = (match.value, f"text:{match.key}")


def normalise_field(name: str) -> str:
    """Compare field and placeholder names ignoring case and separators.

    APIs answer in snake_case and specs are written in camelCase, so `user_id` and `{userId}` are
    the same thing spelled two ways. Without this they never match, and the placeholder falls
    through to whatever weaker rule sits behind it.
    """
    return re.sub(r"[^a-z0-9]+", "", name.strip().lower())


def _walk(node: Any, path: str, seen: dict[str, tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _walk(value, f"{path}.{key}", seen)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, f"{path}[{index}]", seen)
    elif isinstance(node, str | int | float) and not isinstance(node, bool):
        key = normalise_field(path.rsplit(".", 1)[-1].split("[")[0])
        # First occurrence wins: the first `id` in a search result is the one a user would click.
        # Note this holds across steps too, so an early generic `id` keeps the slot for the whole
        # flow - preferring the nearest preceding step is a separate, known improvement.
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
        # Reasons come from exception messages, which usually punctuate themselves.
        f"The probe could not run: {reason.rstrip().rstrip('.')}.\n"
        f"Correlations will be inferred from placeholder names rather than observed traffic, "
        f"and must be reviewed before the script is trusted."
    )

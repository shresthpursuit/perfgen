"""IR → .jmx, plus the property files and SLA criteria that travel with it.

Deterministic throughout. The same IR always produces byte-identical output, so a regenerated
script diffs cleanly against the one in review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from perfgen.emit import naming
from perfgen.emit.apportion import apportion_float, largest_remainder
from perfgen.emit.assembler import Node, build_document, node, to_xml
from perfgen.ir.models import (
    AuthStrategy,
    AuthType,
    Extract,
    ExtractorType,
    Flow,
    LoadProfile,
    Scope,
    Source,
    Step,
    TestPlanIR,
)

CONNECT_TIMEOUT_MS = 10_000
RESPONSE_TIMEOUT_MS = 60_000
EXTRACT_DEFAULT = "PERFGEN_NOT_FOUND"

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass
class EmitResult:
    jmx_path: Path
    property_files: list[Path] = field(default_factory=list)
    sla_path: Path | None = None
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------------
# Load apportionment
# --------------------------------------------------------------------------------------------


@dataclass
class ProfilePlan:
    """A profile's load parameters, already split per flow."""

    profile: LoadProfile
    users_by_flow: dict[str, int]
    tput_per_minute_by_flow: dict[str, float]


def plan_profile(profile: LoadProfile, flows: list[Flow]) -> ProfilePlan:
    """Apportion a profile's users and throughput across flows by share_pct."""
    shares = [f.share_pct for f in flows]
    users = largest_remainder(profile.users or 0, shares)
    users_by_flow = {f.id: u for f, u in zip(flows, users, strict=True)}

    tput_by_flow: dict[str, float] = {}
    if profile.throughput is not None:
        per_minute = profile.throughput.per_minute()
        for flow, value in zip(flows, apportion_float(per_minute, shares), strict=True):
            tput_by_flow[flow.id] = round(value, 4)

    return ProfilePlan(profile, users_by_flow, tput_by_flow)


def _baseline_plan(ir: TestPlanIR, plans: dict[str, ProfilePlan]) -> ProfilePlan:
    """The profile whose values become the JMX's inline defaults."""
    if "baseline" in plans:
        return plans["baseline"]
    return plans[next(iter(plans))]


# --------------------------------------------------------------------------------------------
# Placeholder rewriting
# --------------------------------------------------------------------------------------------


def _scope_index(ir: TestPlanIR) -> dict[str, Scope]:
    """Map every extracted variable name to the scope it was extracted at."""
    scopes: dict[str, Scope] = {}
    for flow in ir.flows:
        for step in flow.steps:
            for extract in step.extracts:
                scopes[extract.var] = extract.scope
    if ir.auth.token_extract is not None:
        token = ir.auth.token_extract
        scopes[token.var] = (
            Scope.GLOBAL if ir.auth.strategy is AuthStrategy.SHARED_SETUP else Scope.THREAD
        )
    return scopes


def rewrite_placeholders(text: str, scopes: dict[str, Scope]) -> str:
    """Turn `{varName}` into the right JMeter reference for that variable's scope.

    A `global` value lives in a JVM property and must be read with `${__P(name)}`; a thread or
    iteration value is an ordinary `${name}`. Getting this wrong is the failure the brief calls
    out — it passes a single-user smoke test and breaks under load.
    """

    def replace(match: re.Match[str]) -> str:
        var = match.group(1)
        scope = scopes.get(var)
        if scope is None:
            # No producer: leave the placeholder intact so structural validation reports it
            # rather than the emitter silently inventing a variable.
            return match.group(0)
        return naming.var_ref(var, scope is Scope.GLOBAL)

    return _PLACEHOLDER.sub(replace, text)


def unresolved_placeholders(text: str, scopes: dict[str, Scope]) -> list[str]:
    return [m.group(1) for m in _PLACEHOLDER.finditer(text) if m.group(1) not in scopes]


# --------------------------------------------------------------------------------------------
# Element builders
# --------------------------------------------------------------------------------------------


def _extractor_node(extract: Extract, scopes: dict[str, Scope]) -> list[Node]:
    """One extractor, plus a JSR223 publisher when the value is global-scoped."""
    testname = f"Extract {extract.var}"
    use_headers = "true" if extract.source is Source.RESPONSE_HEADER else "false"

    if extract.extractor is ExtractorType.JSON_PATH:
        element = node(
            "json_extractor",
            testname=testname,
            var=extract.var,
            expr=extract.expr,
            default_value=EXTRACT_DEFAULT,
        )
    elif extract.extractor is ExtractorType.XPATH:
        element = node(
            "xpath_extractor",
            testname=testname,
            var=extract.var,
            expr=extract.expr,
            default_value=EXTRACT_DEFAULT,
        )
    elif extract.extractor is ExtractorType.REGEX:
        element = node(
            "regex_extractor",
            testname=testname,
            var=extract.var,
            expr=extract.expr,
            use_headers=use_headers,
            default_value=EXTRACT_DEFAULT,
        )
    elif extract.extractor is ExtractorType.HEADER:
        # JMeter has no dedicated header extractor; a regex over the response headers is the
        # documented way. expr is the header name.
        element = node(
            "regex_extractor",
            testname=testname,
            var=extract.var,
            expr=f"{re.escape(extract.expr)}:\\s*(.+)",
            use_headers="true",
            default_value=EXTRACT_DEFAULT,
        )
    elif extract.extractor is ExtractorType.BOUNDARY:
        left, _, right = extract.expr.partition("||")
        if not right:
            raise ValueError(
                f"boundary extractor for {extract.var!r} needs an expr of the form "
                f"'left||right', got {extract.expr!r}"
            )
        element = node(
            "boundary_extractor",
            testname=testname,
            var=extract.var,
            lboundary=left,
            rboundary=right,
            use_headers=use_headers,
            default_value=EXTRACT_DEFAULT,
        )
    else:  # pragma: no cover - the enum is closed
        raise ValueError(f"unsupported extractor type {extract.extractor}")

    nodes = [element]
    if extract.scope is Scope.GLOBAL:
        nodes.append(_publish_global(extract.var))
    return nodes


def _publish_global(var: str) -> Node:
    """A global value is a JVM property, written by Groovy and read as ${__P(name)}."""
    return node(
        "jsr223_postprocessor",
        testname=f"Publish {var} to properties",
        script=f'props.put("{var}", vars.get("{var}"));',
    )


def _assertion_node(expected_status: int, testname: str) -> Node:
    return node(
        "response_assertion",
        testname=testname,
        expected=str(expected_status),
        hash_code=naming.java_hash_code(str(expected_status)),
        custom_message="",
    )


def _sampler_node(
    step: Step,
    ir: TestPlanIR,
    scopes: dict[str, Scope],
    protocol: str,
    domain: str,
    port: str,
) -> Node:
    base_path = ir.application.base_path or ""
    path = rewrite_placeholders(f"{base_path}{step.path}", scopes)
    body = rewrite_placeholders(step.body, scopes) if step.body else ""

    return node(
        "http_sampler",
        testname=step.name,
        protocol=protocol,
        domain=domain,
        port=port,
        path=path,
        method=step.method.value,
        body=body,
        connect_timeout_ms=CONNECT_TIMEOUT_MS,
        response_timeout_ms=RESPONSE_TIMEOUT_MS,
    )


def _content_type_headers(step: Step) -> dict[str, str]:
    """Content-Type is set consistently: explicit when given, else inferred from a JSON body."""
    headers = dict(step.headers)
    if step.content_type:
        headers.setdefault("Content-Type", step.content_type)
    elif step.body:
        stripped = step.body.lstrip()
        if stripped.startswith(("{", "[")):
            headers.setdefault("Content-Type", "application/json")
    return headers


def _auth_header(ir: TestPlanIR) -> dict[str, str]:
    """The auth header, reading the credential from wherever it actually lives.

    Two shapes. An OAuth token was fetched at run time and sits in a variable or a property,
    depending on its scope. A static scheme has no token call at all: its secret is read straight
    from the environment, which is why these types emitted no header until this was fixed.
    """
    if ir.auth.type is AuthType.NONE:
        return {}

    reference = _credential_reference(ir)
    if reference is None:
        return {}

    value = (ir.auth.value_format or "{token}").replace("{token}", reference)
    return {ir.auth.header_name or "Authorization": value}


def _credential_reference(ir: TestPlanIR) -> str | None:
    """The run-time expression that yields the credential, or None if there is nothing to read."""
    if ir.auth.type.is_static_credential:
        refs = ir.auth.static_credential_refs
        if not refs:
            return None
        if ir.auth.type is AuthType.BASIC and len(refs) == 2:
            # Two references means a user and a password to be encoded together.
            return naming.basic_auth_lookup(refs[0], refs[1])
        # One reference: the secret is already whatever the header needs after the scheme word.
        return naming.env_lookup(refs[0])

    if ir.auth.token_extract is None:
        return None
    return naming.var_ref(
        ir.auth.token_extract.var, ir.auth.strategy is AuthStrategy.SHARED_SETUP
    )


def _headers_node(headers: dict[str, str], testname: str) -> Node | None:
    if not headers:
        return None
    return node(
        "header_manager",
        testname=testname,
        headers=[{"name": k, "value": v} for k, v in headers.items()],
    )


# --------------------------------------------------------------------------------------------
# Thread groups
# --------------------------------------------------------------------------------------------


def _token_sampler(ir: TestPlanIR, warnings: list[str], *, publish_global: bool) -> Node:
    """The token acquisition request, with its extractor attached.

    `publish_global` writes the token to a JVM property so every thread group can read it; that is
    only right for a shared token. A per-thread token stays a thread variable.
    """
    token = ir.auth.token_extract
    request = ir.auth.token_request
    assert token is not None and request is not None  # guaranteed by Auth validation

    protocol, domain, port, path = naming.split_url(request.url)

    # Credentials are read from the environment at run time. No secret value is ever written here,
    # only the name of the environment variable the value will come from.
    body = "&".join(
        f"{name}={naming.env_lookup(_credential_for(name, request, warnings))}"
        for name in request.param_names
    )

    sampler = node(
        "http_sampler",
        testname="Acquire token",
        protocol=protocol,
        domain=domain,
        port=port,
        path=path,
        method=request.method.upper(),
        body=body,
        connect_timeout_ms=CONNECT_TIMEOUT_MS,
        response_timeout_ms=RESPONSE_TIMEOUT_MS,
    )

    content_type = _headers_node({"Content-Type": request.content_type}, "Token request headers")
    if content_type:
        sampler.add(content_type)

    if token.expr:
        sampler.add(
            node(
                "json_extractor",
                testname=f"Extract {token.var}",
                var=token.var,
                expr=token.expr,
                default_value=EXTRACT_DEFAULT,
            )
        )
        if publish_global:
            sampler.add(_publish_global(token.var))
    sampler.add(_assertion_node(200, "Token request succeeded"))
    return sampler


def _setup_thread_group(ir: TestPlanIR, warnings: list[str]) -> Node:
    """Acquires the shared token once, before the flow groups start."""
    group = node("setup_thread_group", testname="setUp Thread Group - acquire token")
    group.add(_token_sampler(ir, warnings, publish_global=True))
    return group


def _credential_for(param: str, request, warnings: list[str]) -> str:
    """The credential reference supplying a token parameter, falling back to the parameter name.

    The IR carries `param_names` and `credential_refs` as two unrelated lists, so which secret
    fills which parameter is matched by name rather than declared. A parameter with no matching
    reference still has to come from somewhere, so it reads an environment variable of its own
    name and the run summary says so.
    """
    matched = naming.match_credential_ref(param, request.credential_refs)
    if matched is None:
        warnings.append(
            f"Token parameter {param!r} has no matching credential reference in the spec. "
            f"The script reads it from the environment variable {naming.env_var(param)} - set "
            f"that variable, or add a credential reference whose suffix matches the parameter."
        )
        return param
    return matched


def _flow_thread_group(
    flow: Flow,
    ir: TestPlanIR,
    scopes: dict[str, Scope],
    plan: ProfilePlan,
    protocol: str,
    domain: str,
    port: str,
    warnings: list[str],
) -> Node:
    users_default = plan.users_by_flow.get(flow.id, 0)
    group = node(
        "thread_group",
        testname=f"{flow.id} - {flow.name}",
        num_threads=naming.prop_ref(naming.users_prop(flow.id), users_default),
        ramp_time=naming.prop_ref(naming.RAMPUP_PROP, plan.profile.ramp_up_s or 0),
        duration=naming.prop_ref(naming.DURATION_PROP, plan.profile.duration_s or 0),
    )

    per_thread_auth = (
        ir.auth.type is not AuthType.NONE
        and ir.auth.strategy is AuthStrategy.PER_THREAD
        and ir.auth.token_request is not None
    )
    auth_header = _auth_header(ir)

    if per_thread_auth:
        # Every virtual user logs in once on its first iteration and reuses its own token.
        once = group.add(node("once_only_controller", testname="Acquire token (once per user)"))
        once.add(_token_sampler(ir, warnings, publish_global=False))

    # A group-level Header Manager applies to every sampler in the group, including the token
    # request — which would send an unresolved Authorization header to the auth endpoint. With
    # per-thread auth the header therefore rides on each step's sampler instead.
    group_headers = dict(flow.headers)
    if not per_thread_auth:
        group_headers.update(auth_header)
    header_node = _headers_node(group_headers, "HTTP Header Manager")
    if header_node:
        group.add(header_node)

    for step in flow.steps:
        controller = group.add(
            node(
                "transaction_controller",
                testname=naming.transaction_name(flow.id, step.index, step.name),
                parent=False,
            )
        )
        sampler = controller.add(_sampler_node(step, ir, scopes, protocol, domain, port))

        step_headers = _content_type_headers(step)
        if per_thread_auth:
            step_headers.update(auth_header)
        step_header_node = _headers_node(step_headers, f"{step.name} headers")
        if step_header_node:
            sampler.add(step_header_node)

        for extract in step.extracts:
            for extractor in _extractor_node(extract, scopes):
                sampler.add(extractor)

        sampler.add(_assertion_node(step.expected_status, f"Status {step.expected_status}"))

        # D2: the timer sits inside the controller so it is scoped to this one sampler, and the
        # controller carries includeTimers=false so the delay stays out of the transaction time.
        if flow.think_time_ms > 0:
            controller.add(
                node("constant_timer", testname="Think time", delay_ms=flow.think_time_ms)
            )

    if plan.tput_per_minute_by_flow:
        default = plan.tput_per_minute_by_flow.get(flow.id, 0.0)
        group.add(
            node(
                "constant_throughput_timer",
                testname=f"Throughput - {flow.id}",
                throughput_per_minute=naming.prop_ref(naming.throughput_prop(flow.id), default),
            )
        )

    return group


# --------------------------------------------------------------------------------------------
# Top level
# --------------------------------------------------------------------------------------------


def build_tree(ir: TestPlanIR, jmeter_version: str) -> tuple[bytes, list[str]]:
    """Build the JMX document. Returns the XML and any warnings for the run summary."""
    warnings: list[str] = []
    scopes = _scope_index(ir)
    protocol, domain, port = naming.split_base_url(ir.application.base_url)

    plans = {p.id.value: plan_profile(p, ir.flows) for p in ir.enabled_profiles}
    if not plans:
        raise ValueError("no enabled load profile; nothing to emit")
    baseline = _baseline_plan(ir, plans)

    for flow_id, count in baseline.users_by_flow.items():
        if count == 0:
            warnings.append(
                f"Flow {flow_id} is apportioned 0 threads at the {baseline.profile.id.value} "
                f"profile's {baseline.profile.users} users - it will not run. Raise the user "
                f"count or the flow's share of load."
            )

    comments = [f"Generated by perfgen from {ir.provenance.source_workbook}."]
    if ir.auth.refresh_required:
        message = (
            f"WARNING: a test runs longer than the token lifetime of "
            f"{ir.auth.lifetime_seconds}s. This script does not refresh the token and will "
            f"start failing mid-run when it expires."
        )
        comments.append(message)
        warnings.append(message)
    if ir.provenance.probe.degraded:
        message = (
            "WARNING: the probe did not run. Every correlation here is inferred from placeholder "
            "names, not observed traffic, and must be reviewed before this script is trusted."
        )
        comments.append(message)
        warnings.append(message)
    if ir.provenance.probe.skipped_flows:
        skipped = ", ".join(ir.provenance.probe.skipped_flows)
        message = (
            f"NOTE: flows {skipped} were not probed (marked unsafe for this environment); "
            f"their correlations are inferred."
        )
        comments.append(message)
        warnings.append(message)

    plan_node = node("test_plan", testname=ir.application.name, comments="\n".join(comments))

    plan_node.add(
        node(
            "arguments",
            testname="User Defined Variables",
            args=[
                {"name": "baseProtocol", "value": protocol},
                {"name": "baseHost", "value": domain},
                {"name": "basePort", "value": port},
                {"name": "basePath", "value": ir.application.base_path or ""},
            ],
        )
    )
    plan_node.add(node("cookie_manager"))
    plan_node.add(node("cache_manager"))

    if (
        ir.auth.type is not AuthType.NONE
        and ir.auth.strategy is AuthStrategy.SHARED_SETUP
        and ir.auth.token_request is not None
    ):
        plan_node.add(_setup_thread_group(ir, warnings))

    for flow in ir.flows:
        plan_node.add(
            _flow_thread_group(flow, ir, scopes, baseline, protocol, domain, port, warnings)
        )

    document = build_document([plan_node], jmeter_version)
    return to_xml(document), warnings


def write_property_files(ir: TestPlanIR, out_dir: Path) -> list[Path]:
    """One property file per enabled profile (D1). The JMX itself stays profile-agnostic."""
    written: list[Path] = []
    for profile in ir.enabled_profiles:
        plan = plan_profile(profile, ir.flows)
        lines = [
            f"# {profile.id.value} profile for {ir.application.name}",
            f"# jmeter -n -q {profile.id.value}.properties -t {_jmx_name(ir)} -l results.jtl",
            "",
            f"{naming.RAMPUP_PROP}={profile.ramp_up_s or 0}",
            f"{naming.DURATION_PROP}={profile.duration_s or 0}",
        ]
        for flow in ir.flows:
            lines.append(f"{naming.users_prop(flow.id)}={plan.users_by_flow.get(flow.id, 0)}")
        if plan.tput_per_minute_by_flow:
            lines.append("")
            lines.append("# throughput in samples per minute")
            for flow in ir.flows:
                value = plan.tput_per_minute_by_flow.get(flow.id, 0.0)
                lines.append(f"{naming.throughput_prop(flow.id)}={value:g}")
        target = out_dir / f"{profile.id.value}.properties"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(target)
    return written


def write_sla_criteria(ir: TestPlanIR, out_dir: Path) -> Path | None:
    """SLAs go to a separate criteria file, never into the script as duration assertions.

    A per-sample duration assertion marks slow-but-successful responses as errors, corrupting the
    error rate exactly when the system is degrading.
    """
    if not ir.sla:
        return None
    payload = {
        "application": ir.application.name,
        "criteria": [
            {
                "scope": s.scope,
                "metric": s.metric.value,
                "target": s.target,
                "unit": s.unit.value,
            }
            for s in ir.sla
        ],
    }
    target = out_dir / "sla_criteria.yaml"
    target.write_text(
        yaml.safe_dump(payload, sort_keys=False, default_flow_style=False), encoding="utf-8"
    )
    return target


def _jmx_name(ir: TestPlanIR) -> str:
    return f"{naming.slug(ir.application.name)}.jmx"


def emit(ir: TestPlanIR, out_root: Path, jmeter_version: str = "5.6.3") -> EmitResult:
    """Write the JMX, its property files and the SLA criteria under `out_root/{app_name}/`."""
    out_dir = Path(out_root) / naming.slug(ir.application.name)
    out_dir.mkdir(parents=True, exist_ok=True)

    xml, warnings = build_tree(ir, jmeter_version)
    jmx_path = out_dir / _jmx_name(ir)
    jmx_path.write_bytes(xml)

    return EmitResult(
        jmx_path=jmx_path,
        property_files=write_property_files(ir, out_dir),
        sla_path=write_sla_criteria(ir, out_dir),
        warnings=warnings,
    )

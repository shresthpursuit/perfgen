"""Specification workbook -> Test Plan IR.

Two rules govern everything here.

**Never invent a value.** A field that is missing, blank or unrecognised becomes a `gaps` entry.
An invented thread count or a guessed auth type produces a script that runs, validates, and
measures the wrong thing - which is worse than no script, because it looks like an answer.

**Never raise on the first problem.** A user with six blank cells should be told about six blank
cells once, not made to run the tool six times. Parsing collects and continues; the caller decides
what to do about blocking gaps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from openpyxl import load_workbook

from perfgen import secrets
from perfgen.ir.gaps import auth_gaps, flow_gaps, load_profile_gaps
from perfgen.ir.models import (
    Application,
    Auth,
    AuthStrategy,
    AuthType,
    Flow,
    Gap,
    LoadProfile,
    ProbeProvenance,
    ProfileId,
    Provenance,
    SeedCookie,
    Severity,
    Sla,
    Step,
    TestPlanIR,
    Throughput,
    TokenExtract,
    TokenRequest,
)
from perfgen.parse import values
from perfgen.parse.sheets import (
    LabelledSheet,
    cell_text,
    find_header_row,
    find_sheet,
    iter_data_rows,
)
from perfgen.parse.values import (
    ACCOUNT_MODELS,
    AUTH_TYPES,
    METHODS,
    PROFILE_IDS,
    SLA_METRICS,
    SLA_UNITS,
    THROUGHPUT_UNITS,
)
from perfgen.probe.redact import is_sensitive_key

APPLICATION_SHEET = ("Application",)
FLOWS_SHEET = ("Flows", "Flow")
STEPS_SHEET = ("Flow steps", "Flow Steps", "Steps")
AUTH_STEPS_SHEET = ("Auth flow steps", "Auth Flow Steps", "Auth steps")
PROFILES_SHEET = ("Load profiles", "Load Profiles", "Load profile")
SLA_SHEET = ("SLA", "SLAs", "Service levels")

DEFAULT_TOKEN_VAR = "authToken"

# Every profile the template ships, so a missing row can be reported by name.
EXPECTED_PROFILES = ["Baseline", "Peak load", "Capacity / overload", "Endurance"]


@dataclass
class ParseResult:
    ir: TestPlanIR | None
    gaps: list[Gap] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    """Things worth stating that are not problems - e.g. an optional sheet left empty.

    A user who leaves the SLA sheet blank should be told it was read and was empty, rather than
    being left to wonder whether it was checked at all. That is not a gap: it is a legal spec.
    """

    @property
    def blocking(self) -> list[Gap]:
        return [g for g in self.gaps if g.severity is Severity.BLOCKING]

    @property
    def ok(self) -> bool:
        return self.ir is not None and not self.blocking


class _Collector:
    """Accumulates gaps while parsing, so nothing raises until the caller decides."""

    def __init__(self) -> None:
        self.gaps: list[Gap] = []
        self.notes: list[str] = []

    def blocking(self, field_path: str, message: str) -> None:
        self.gaps.append(Gap(field=field_path, severity=Severity.BLOCKING, message=message))

    def warning(self, field_path: str, message: str) -> None:
        self.gaps.append(Gap(field=field_path, severity=Severity.WARNING, message=message))

    def note(self, message: str) -> None:
        self.notes.append(message)

    def has_field(self, field_path: str) -> bool:
        return any(g.field == field_path for g in self.gaps)

    def missing_sheet(self, name: str) -> None:
        self.blocking(
            f"sheet.{name}",
            f"The workbook has no '{name}' sheet. It is one of the five sheets the "
            f"specification template ships with.",
        )


def parse_workbook(path: str | Path) -> ParseResult:
    """Read a specification workbook and build the IR, collecting every gap on the way.

    Every sheet is read and reported on whatever happened to the ones before it. A blank template
    should produce its whole list of blocking fields in one run: making the user fix the top of
    the first sheet before being told the last sheet is empty turns one report into three.
    """
    source = Path(path)
    collector = _Collector()
    workbook = load_workbook(source, data_only=True, read_only=False)

    application, auth, declared_auth_type = _parse_application(workbook, collector)
    if declared_auth_type is AuthType.OAUTH2_PKCE:
        # A separate sheet, so it cannot be read inside _parse_application with the rest of auth.
        auth.flow_steps = _parse_auth_steps(workbook, collector)
    flows = _parse_flows(workbook, collector)
    profiles = _parse_profiles(workbook, collector)
    slas = _parse_sla(workbook, collector)

    # Structural checks run on the parsed lists, not on an assembled IR, so they still report when
    # the IR could not be built. These take the parsed values as given; per-row problems have
    # already been recorded above, and a field already reported is not reported twice.
    for gap in [*load_profile_gaps(profiles), *flow_gaps(flows), *auth_gaps(auth, pre_probe=True)]:
        if not collector.has_field(gap.field):
            collector.gaps.append(gap)

    if application is None:
        return ParseResult(ir=None, gaps=collector.gaps, notes=collector.notes)

    provenance = Provenance(
        source_workbook=source.name,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        probe=ProbeProvenance(),
    )

    try:
        ir = TestPlanIR(
            application=application,
            auth=auth,
            flows=flows,
            load_profiles=profiles,
            sla=slas,
            gaps=collector.gaps,
            provenance=provenance,
        )
    except ValueError as exc:
        collector.blocking(
            "ir",
            f"The spec could not be assembled into a valid test plan: {exc}",
        )
        return ParseResult(ir=None, gaps=collector.gaps, notes=collector.notes)

    # refresh_required is only derived once the IR validates, so its warning cannot be raised from
    # the parsed auth object above and is added here instead.
    for gap in auth_gaps(ir.auth, pre_probe=True):
        if not collector.has_field(gap.field):
            collector.gaps.append(gap)

    ir.gaps = collector.gaps
    return ParseResult(ir=ir, gaps=collector.gaps, notes=collector.notes)


# --------------------------------------------------------------------------------------------
# Application + auth
# --------------------------------------------------------------------------------------------


def _parse_application(
    workbook, collector: _Collector
) -> tuple[Application | None, Auth, AuthType]:
    """Returns the declared auth type alongside the Auth.

    The two differ when required auth fields are missing: `Auth` validation raises and the
    fallback is `AuthType.NONE`, which would hide from the caller that the spec said PKCE and
    therefore still owes an 'Auth flow steps' sheet.
    """
    fallback_auth = Auth(type=AuthType.NONE)
    sheet = find_sheet(workbook, *APPLICATION_SHEET)
    if sheet is None:
        collector.missing_sheet("Application")
        return None, fallback_auth, AuthType.NONE

    header = find_header_row(sheet, ["Attribute", "Value"])
    if header is None or not header.has("Value"):
        collector.blocking(
            "application",
            "The 'Application' sheet has no 'Value' column header. Values are read from the "
            "column headed 'Value' - the 'Example' column is guidance only and is never used.",
        )
        return None, fallback_auth, AuthType.NONE

    labelled = LabelledSheet(sheet, header)

    def required(label: str, field_path: str) -> str | None:
        value = cell_text(labelled.get(label))
        if value is None:
            location = _where("Application", labelled.row_of(label))
            reason = (
                "is empty" if labelled.has_label(label) else "is missing from the sheet"
            )
            collector.blocking(field_path, f"{location}: '{label}' {reason}.")
        return value

    name = required("Application name", "application.name")
    base_url = required("Base URL", "application.base_url")

    if base_url is not None and not base_url.lower().startswith(("http://", "https://")):
        collector.blocking(
            "application.base_url",
            f"{_where('Application', labelled.row_of('Base URL'))}: 'Base URL' is "
            f"{base_url!r}, which has no http:// or https:// scheme.",
        )
        base_url = None

    auth, declared_type = _parse_auth(labelled, collector)

    if name is None or base_url is None:
        return None, auth, declared_type

    application = Application(
        name=name,
        base_url=base_url.rstrip("/"),
        base_path=_normalise_base_path(cell_text(labelled.get("Base path"))),
        api_reference=cell_text(labelled.get("API reference location")),
        additional_headers=_parse_additional_headers(labelled, collector, auth),
    )
    return application, auth, declared_type


def _parse_header_lines(
    raw: str | None, collector: _Collector, field: str, location: str, what: str = "header"
) -> dict[str, str]:
    """`Name: value` per line, into a mapping. Shared by step headers and seed cookies.

    Splits on the first colon only, because values legitimately contain them - a URL, a timestamp,
    the `https://...` of a Referer. Every problem is a warning: the field is optional, but nothing
    is dropped silently, because a header the user meant to send and which quietly went missing
    surfaces much later as an unexplained 400.
    """
    parsed: dict[str, str] = {}
    if raw is None:
        return parsed

    for line in values.as_lines(raw):
        name, separator, value = line.partition(":")
        name, value = name.strip(), value.strip()

        if not separator or not name:
            collector.warning(
                field,
                f"{location}: {line!r} is not a {what}. Write one per line as "
                f"'Name: value'. This line is ignored.",
            )
            continue
        if name in parsed:
            collector.warning(
                field,
                f"{location}: {what} {name!r} is listed more than once. The first value is used "
                f"and the later one ignored.",
            )
            continue
        parsed[name] = value
    return parsed


def _parse_additional_headers(
    labelled: LabelledSheet, collector: _Collector, auth: Auth
) -> dict[str, str]:
    """Read `Additional required headers`, one `Header-Name: value` per line.

    Every problem here is a warning rather than a blocker: the field is optional, and a spec
    without it is still a valid spec. But none of them are silent, because a header the user meant
    to send and which quietly went missing shows up much later as an unexplained 400 from the
    server - the kind of failure this tool exists to keep off the reader's desk.
    """
    label = "Additional required headers"
    location = _where("Application", labelled.row_of(label))
    headers: dict[str, str] = {}

    for line in values.as_lines(labelled.get(label)):
        name, separator, value = line.partition(":")
        # Split on the first colon only: values legitimately contain them - a URL, a timestamp.
        name, value = name.strip(), value.strip()

        if not separator or not name:
            collector.warning(
                "application.additional_headers",
                f"{location}: {line!r} is not a header. Write one per line as "
                f"'Header-Name: value'. This line is ignored.",
            )
            continue

        if name in headers:
            collector.warning(
                "application.additional_headers",
                f"{location}: header {name!r} is listed more than once. The first value is used "
                f"and the later one ignored.",
            )
            continue

        if auth.header_name and name.lower() == auth.header_name.lower():
            collector.warning(
                "application.additional_headers",
                f"{location}: header {name!r} is also the 'Auth header name'. The authentication "
                f"header wins, and this literal value is ignored - two mechanisms cannot both own "
                f"one header.",
            )
            continue

        if is_sensitive_key(name):
            collector.warning(
                "application.additional_headers",
                f"{location}: header {name!r} looks like a credential, and its value is written "
                f"into the generated script in clear text. If it is a secret, put its name in "
                f"'Credential reference names' instead.",
            )

        headers[name] = value

    return headers


def _normalise_base_path(value: str | None) -> str | None:
    if value is None:
        return None
    path = value.strip().rstrip("/")
    if not path:
        return None
    return path if path.startswith("/") else f"/{path}"


def _parse_auth(labelled: LabelledSheet, collector: _Collector) -> tuple[Auth, AuthType]:
    raw_type = labelled.get("Auth type")
    auth_type = values.lookup(AUTH_TYPES, raw_type)

    if auth_type is None:
        if cell_text(raw_type) is None:
            collector.blocking(
                "auth.type",
                f"{_where('Application', labelled.row_of('Auth type'))}: 'Auth type' is empty. "
                f"Choose one of: {', '.join(sorted(AUTH_TYPES))}.",
            )
        else:
            collector.blocking(
                "auth.type",
                f"{_where('Application', labelled.row_of('Auth type'))}: 'Auth type' is "
                f"{cell_text(raw_type)!r}, which is not a recognised value. Choose one of: "
                f"{', '.join(sorted(AUTH_TYPES))}.",
            )
        # The remaining auth fields are conditionally required - a token endpoint is needed for an
        # OAuth flow and meaningless for 'None' - so with the type unknown they cannot be judged.
        # Say that, rather than either inventing requirements or staying silent.
        unset = [
            label
            for label in (
                "Token endpoint URL",
                "Auth header name",
                "Auth header value format",
                "Account model",
            )
            if cell_text(labelled.get(label)) is None
        ]
        if unset:
            collector.note(
                "The remaining authentication fields ("
                + ", ".join(f"'{label}'" for label in unset)
                + ") are empty. Whether they are required depends on 'Auth type', so they will "
                "be checked once that is set."
            )
        return Auth(type=AuthType.NONE), AuthType.NONE

    raw_model = labelled.get("Account model")
    strategy = values.lookup(ACCOUNT_MODELS, raw_model)
    if strategy is None and auth_type is not AuthType.NONE:
        collector.blocking(
            "auth.strategy",
            f"{_where('Application', labelled.row_of('Account model'))}: 'Account model' is "
            f"{cell_text(raw_model)!r}. Use 'Single shared' or 'One per user'.",
        )
        # Still a blocking gap; this only keeps parsing going. PKCE falls back the other way
        # because that is the shape its reference actually ran - see the strategy note below.
        strategy = (
            AuthStrategy.PER_THREAD
            if auth_type is AuthType.OAUTH2_PKCE
            else AuthStrategy.SHARED_SETUP
        )

    if auth_type is AuthType.NONE:
        return (
            Auth(type=AuthType.NONE, strategy=strategy or AuthStrategy.SHARED_SETUP),
            AuthType.NONE,
        )

    header_name = cell_text(labelled.get("Auth header name"))
    value_format = cell_text(labelled.get("Auth header value format"))
    for label, value, path in (
        ("Auth header name", header_name, "auth.header_name"),
        ("Auth header value format", value_format, "auth.value_format"),
    ):
        if value is None:
            collector.blocking(
                path,
                f"{_where('Application', labelled.row_of(label))}: '{label}' is required when "
                f"an authentication type is set.",
            )

    if value_format is not None and "{token}" not in value_format:
        collector.warning(
            "auth.value_format",
            f"{_where('Application', labelled.row_of('Auth header value format'))}: "
            f"'Auth header value format' is {value_format!r} and contains no {{token}} "
            f"placeholder, so the token will not be substituted into the header.",
        )

    token_request = None
    token_extract = None
    static_refs: list[str] = []

    if auth_type.needs_token_request:
        token_request = _parse_token_request(labelled, collector)
        # The expression is discovered by the probe (M3); until then it is unknown, not invented.
        token_extract = TokenExtract(var=DEFAULT_TOKEN_VAR)
    elif auth_type.is_static_credential:
        static_refs = _parse_static_credentials(labelled, collector, auth_type)

    lifetime = values.as_int(labelled.get("Token lifetime (seconds)"))
    if lifetime is None and cell_text(labelled.get("Token lifetime (seconds)")) is not None:
        collector.warning(
            "auth.lifetime_seconds",
            f"{_where('Application', labelled.row_of('Token lifetime (seconds)'))}: "
            f"'Token lifetime (seconds)' is not a whole number of seconds.",
        )

    pkce: dict[str, object] = {}
    if auth_type is AuthType.OAUTH2_PKCE:
        pkce = _parse_pkce_fields(labelled, collector)

    try:
        built = Auth(
            type=auth_type,
            # PKCE defaults to per_thread: the confirmed-working reference runs the whole exchange
            # inside the load thread group, once per virtual user, and that is the shape that has
            # actually reached a token against a live tenant. shared_setup stays available when a
            # spec asks for it - one login is gentler on an IdP at high user counts - but it is
            # not the default, because it is the shape nobody has run.
            strategy=strategy
            or (
                AuthStrategy.PER_THREAD
                if auth_type is AuthType.OAUTH2_PKCE
                else AuthStrategy.SHARED_SETUP
            ),
            token_request=token_request,
            token_extract=token_extract,
            static_credential_refs=static_refs,
            lifetime_seconds=lifetime,
            header_name=header_name,
            value_format=value_format,
            **pkce,
        )
    except ValueError:
        # Required auth fields are already reported above; fall back so parsing can continue.
        # The declared type still travels with it: a PKCE spec that failed validation here
        # nevertheless owes an 'Auth flow steps' sheet, and the caller has to know that.
        return Auth(type=AuthType.NONE), auth_type
    return built, auth_type


def _parse_pkce_fields(labelled: LabelledSheet, collector: _Collector) -> dict[str, object]:
    """The three registration facts PKCE needs, plus optional seed cookies.

    These cannot be discovered. Entra rejects any `/authorize` whose `redirect_uri` does not
    exactly match a pre-registered value, so there is no first request to observe without already
    knowing it. The gap message therefore names *where to obtain* each one rather than only saying
    it is required - that is the difference between a spec that gets completed and one that stalls.
    """
    where_to_look = (
        "Ask the team that owns the app registration. In Azure: App registrations -> your app -> "
        "Authentication -> Redirect URIs; 'Scope' and the tenant id in the authorize URL come from "
        "the same registration."
    )

    parsed: dict[str, object] = {}
    for label, attribute in (
        ("Authorize endpoint URL", "authorize_url"),
        ("Redirect URI", "redirect_uri"),
        ("Scope", "scope"),
    ):
        text = cell_text(labelled.get(label))
        if text:
            parsed[attribute] = text
        else:
            collector.blocking(
                f"auth.{attribute}",
                f"{_where('Application', labelled.row_of(label))}: '{label}' is required when "
                f"'Auth type' is 'OAuth2 PKCE'. It is a registration fact held by the identity "
                f"provider, so it cannot be discovered by probing. {where_to_look}",
            )

    label = "Seed cookies"
    location = _where("Application", labelled.row_of(label))
    domain = cell_text(labelled.get("Seed cookie domain"))
    cookies = _parse_header_lines(
        cell_text(labelled.get(label)), collector, "auth.seed_cookies", location, what="cookie"
    )
    if cookies and not domain:
        collector.warning(
            "auth.seed_cookies",
            f"{location}: 'Seed cookies' are listed but 'Seed cookie domain' is empty, so there "
            f"is no host to send them to. They are ignored.",
        )
    elif cookies:
        parsed["seed_cookies"] = [
            SeedCookie(name=name, value=value, domain=domain)
            for name, value in cookies.items()
        ]
    return parsed


def _parse_static_credentials(
    labelled: LabelledSheet, collector: _Collector, auth_type: AuthType
) -> list[str]:
    """Read the credential references for a scheme with no token call.

    Bearer static, API key and Basic put a secret straight into the header. One reference names
    it; Basic may name two, a user and a password to be encoded together at run time.
    """
    refs = values.as_lines(labelled.get("Credential reference names"))
    location = _where("Application", labelled.row_of("Credential reference names"))

    if not refs:
        collector.blocking(
            "auth.static_credential_refs",
            f"{location}: 'Credential reference names' is empty, but '{auth_type.value}' sends a "
            f"secret in the '{cell_text(labelled.get('Auth header name')) or 'Authorization'}' "
            f"header. Name the secret it should read - the value itself never goes in the "
            f"workbook.",
        )
        return []

    limit = 2 if auth_type is AuthType.BASIC else 1
    if len(refs) > limit:
        expected = (
            "one for the user and one for the password"
            if auth_type is AuthType.BASIC
            else "just one"
        )
        collector.blocking(
            "auth.static_credential_refs",
            f"{location}: 'Credential reference names' lists {len(refs)} names ({', '.join(refs)}) "
            f"but '{auth_type.value}' takes {expected}. Which one carries the credential cannot "
            f"be guessed.",
        )
        return []

    return refs


def _parse_token_request(labelled: LabelledSheet, collector: _Collector) -> TokenRequest | None:
    url = cell_text(labelled.get("Token endpoint URL"))
    if url is None:
        collector.blocking(
            "auth.token_request.url",
            f"{_where('Application', labelled.row_of('Token endpoint URL'))}: "
            f"'Token endpoint URL' is required for an OAuth2 flow.",
        )
        return None

    method = cell_text(labelled.get("Token request method")) or "POST"
    if values.lookup(METHODS, method) is None:
        collector.warning(
            "auth.token_request.method",
            f"{_where('Application', labelled.row_of('Token request method'))}: "
            f"'Token request method' is {method!r}; expected POST or GET.",
        )

    param_names = values.as_lines(labelled.get("Token request parameters"))
    if not param_names:
        collector.warning(
            "auth.token_request.param_names",
            f"{_where('Application', labelled.row_of('Token request parameters'))}: "
            f"'Token request parameters' is empty, so the token request will have no body.",
        )

    credential_refs = values.as_lines(labelled.get("Credential reference names"))
    if not credential_refs:
        collector.warning(
            "auth.token_request.credential_refs",
            f"{_where('Application', labelled.row_of('Credential reference names'))}: "
            f"'Credential reference names' is empty. The generated script will read every token "
            f"parameter from an environment variable named after the parameter itself.",
        )

    return TokenRequest(
        method=method.upper(),
        url=url,
        content_type=cell_text(labelled.get("Token request content type"))
        or "application/x-www-form-urlencoded",
        param_names=param_names,
        credential_refs=credential_refs,
    )


# --------------------------------------------------------------------------------------------
# Flows and steps
# --------------------------------------------------------------------------------------------


def _parse_flows(workbook, collector: _Collector) -> list[Flow]:
    sheet = find_sheet(workbook, *FLOWS_SHEET)
    if sheet is None:
        collector.missing_sheet("Flows")
        return []

    header = find_header_row(sheet, ["Flow ID", "Flow name", "Share of load %"])
    id_column = header.column_of("Flow ID") if header else None
    if header is None or id_column is None:
        collector.blocking(
            "flows",
            "The 'Flows' sheet has no 'Flow ID' column header, so its rows cannot be read.",
        )
        return []

    steps_by_flow = _parse_steps(workbook, collector)

    flows: list[Flow] = []
    seen: set[str] = set()
    for row_index, cells in iter_data_rows(sheet, header, key_column=id_column):
        flow_id = cell_text(cells.get(id_column))
        assert flow_id is not None
        location = _where("Flows", row_index)

        if flow_id in seen:
            collector.blocking(
                f"flows.{flow_id}",
                f"{location}: Flow ID {flow_id!r} appears more than once.",
            )
            continue
        seen.add(flow_id)

        name = _column_text(cells, header, "Flow name") or flow_id
        share = values.as_int(_column_value(cells, header, "Share of load %"))
        if share is None:
            collector.blocking(
                f"flows.{flow_id}.share_pct",
                f"{location}: 'Share of load %' is empty or not a whole number for {flow_id}.",
            )
            continue

        think_seconds = _column_value(cells, header, "Think time between calls (s)")
        think_ms = values.seconds_to_ms(think_seconds)
        if think_ms is None:
            think_ms = 0
            collector.warning(
                f"flows.{flow_id}.think_time_ms",
                f"{location}: 'Think time between calls (s)' is empty for {flow_id}; "
                f"the script will send requests back to back.",
            )

        probe_safe = values.as_bool(
            _column_value(cells, header, "Safe to run against this environment")
        )
        if probe_safe is None:
            probe_safe = False
            collector.warning(
                f"flows.{flow_id}.probe_safe",
                f"{location}: 'Safe to run against this environment' is not Yes or No for "
                f"{flow_id}; treating it as No, so this flow will not be called during the probe.",
            )

        steps = steps_by_flow.get(flow_id, [])
        if not steps:
            collector.blocking(
                f"flows.{flow_id}.steps",
                f"{location}: flow {flow_id} has no rows on the 'Flow steps' sheet.",
            )
            continue

        flows.append(
            Flow(
                id=flow_id,
                name=name,
                share_pct=min(share, 100),
                think_time_ms=think_ms,
                probe_safe=probe_safe,
                steps=steps,
            )
        )

    orphaned = set(steps_by_flow) - seen
    for flow_id in sorted(orphaned):
        collector.warning(
            f"flows.{flow_id}",
            f"The 'Flow steps' sheet has rows for flow {flow_id!r}, but there is no such Flow ID "
            f"on the 'Flows' sheet. Those steps are ignored.",
        )

    if not flows:
        detail = (
            "The 'Flows' sheet has no rows."
            if not seen
            else "No usable flows were found on the 'Flows' sheet."
        )
        collector.blocking(
            "flows",
            f"{detail} At least one flow is needed - one row per business process being tested.",
        )
    return flows


def _parse_auth_steps(workbook, collector: _Collector) -> list[Step]:
    """The declared login sequence, read only when the auth type is PKCE.

    Same shape as `Flow steps` minus the `Flow ID` column - there is one sequence, not several.
    `{placeholder}` works exactly as it does there, and correlation discovers what fills it.
    """
    sheet = find_sheet(workbook, *AUTH_STEPS_SHEET)
    if sheet is None:
        collector.blocking(
            "auth.flow_steps",
            "'Auth type' is 'OAuth2 PKCE' but there is no 'Auth flow steps' sheet. PKCE needs the "
            "login sequence that runs between /authorize and the token exchange - one row per "
            "request, in the order a browser would make them.",
        )
        return []

    header = find_header_row(sheet, ["Step no", "Endpoint path"])
    key_column = header.column_of("Step no") if header else None
    if header is None or key_column is None:
        collector.blocking(
            "auth.flow_steps",
            "The 'Auth flow steps' sheet has no 'Step no' column header, so its rows cannot be "
            "read.",
        )
        return []

    collected: list[Step] = []
    for row_index, cells in iter_data_rows(sheet, header, key_column=key_column):
        location = _where("Auth flow steps", row_index)

        step_no = values.as_int(cells.get(key_column))
        if step_no is None or step_no < 1:
            collector.blocking(
                "auth.flow_steps.index",
                f"{location}: 'Step no' is empty or not a positive whole number.",
            )
            continue

        path = _column_text(cells, header, "Endpoint path")
        if path is None:
            collector.blocking("auth.flow_steps.path", f"{location}: 'Endpoint path' is empty.")
            continue

        raw_method = _column_text(cells, header, "Method")
        method = values.lookup(METHODS, raw_method)
        if method is None:
            collector.blocking(
                "auth.flow_steps.method",
                f"{location}: 'Method' is {raw_method!r}; expected one of "
                f"{', '.join(m.value for m in METHODS.values())}.",
            )
            continue

        expected_status = values.as_int(_column_value(cells, header, "Expected status"))
        if expected_status is None:
            expected_status = 200
            collector.warning(
                "auth.flow_steps.expected_status",
                f"{location}: 'Expected status' is empty; the script will assert 200. A login "
                f"step that ends in a redirect usually answers 302.",
            )

        body = _column_text(cells, header, "Request body or parameters")
        raw_headers = _column_text(cells, header, "Request headers")
        for field_text in (path, body or "", raw_headers or ""):
            if secrets.MALFORMED_SECRET_REF.search(field_text):
                collector.warning(
                    "auth.flow_steps.credentials",
                    f"{location}: '{{secret:}}' has no reference name, so nothing will be "
                    f"substituted and the literal text is sent. Write it as "
                    f"'{{secret:pkce-login-password}}', naming the credential reference.",
                )

        collected.append(
            Step(
                index=step_no,
                name=_column_text(cells, header, "Step name") or f"auth step {step_no}",
                method=method,
                path=path,
                body=body,
                content_type=values.infer_content_type(body),
                expected_status=expected_status,
                headers=_parse_header_lines(
                    raw_headers, collector, "auth.flow_steps.headers", location
                ),
            )
        )

    if not collected:
        collector.blocking(
            "auth.flow_steps",
            "The 'Auth flow steps' sheet has no usable rows. PKCE needs at least one login step "
            "between /authorize and the token exchange.",
        )
        return []

    indices = [step.index for step in collected]
    duplicates = sorted({i for i in indices if indices.count(i) > 1})
    if duplicates:
        collector.blocking(
            "auth.flow_steps.index",
            f"'Auth flow steps' repeats 'Step no' {', '.join(str(d) for d in duplicates)}. Each "
            f"step needs its own number - the order they run in is the order they are numbered.",
        )
        return []

    return sorted(collected, key=lambda s: s.index)


def _parse_steps(workbook, collector: _Collector) -> dict[str, list[Step]]:
    sheet = find_sheet(workbook, *STEPS_SHEET)
    if sheet is None:
        collector.missing_sheet("Flow steps")
        return {}

    header = find_header_row(sheet, ["Flow ID", "Step no", "Endpoint path"])
    id_column = header.column_of("Flow ID") if header else None
    if header is None or id_column is None:
        collector.blocking(
            "flows.steps",
            "The 'Flow steps' sheet has no 'Flow ID' column header, so its rows cannot be read.",
        )
        return {}

    collected: dict[str, list[tuple[int, Step]]] = {}
    saw_any_row = False
    for row_index, cells in iter_data_rows(sheet, header, key_column=id_column):
        saw_any_row = True
        flow_id = cell_text(cells.get(id_column))
        assert flow_id is not None
        location = _where("Flow steps", row_index)

        path = _column_text(cells, header, "Endpoint path")
        if path is None:
            collector.blocking(
                f"flows.{flow_id}.steps.path",
                f"{location}: 'Endpoint path' is empty.",
            )
            continue

        step_no = values.as_int(_column_value(cells, header, "Step no"))
        if step_no is None or step_no < 1:
            collector.blocking(
                f"flows.{flow_id}.steps.index",
                f"{location}: 'Step no' is empty or not a positive whole number.",
            )
            continue

        raw_method = _column_text(cells, header, "Method")
        method = values.lookup(METHODS, raw_method)
        if method is None:
            collector.blocking(
                f"flows.{flow_id}.steps.method",
                f"{location}: 'Method' is {raw_method!r}; expected one of "
                f"{', '.join(m.value for m in METHODS.values())}.",
            )
            continue

        expected_status = values.as_int(_column_value(cells, header, "Expected status"))
        if expected_status is None:
            expected_status = 200
            collector.warning(
                f"flows.{flow_id}.steps.expected_status",
                f"{location}: 'Expected status' is empty; the script will assert 200.",
            )

        body = _column_text(cells, header, "Request body or parameters")
        step = Step(
            index=step_no,
            name=_column_text(cells, header, "Step name") or f"{flow_id} step {step_no}",
            method=method,
            path=path if path.startswith("/") else f"/{path}",
            body=body,
            content_type=values.infer_content_type(body),
            expected_status=expected_status,
            headers=_parse_header_lines(
                _column_text(cells, header, "Request headers"),
                collector,
                f"flows.{flow_id}.steps.headers",
                location,
            ),
        )
        collected.setdefault(flow_id, []).append((row_index, step))

    if not saw_any_row:
        collector.blocking(
            "flows.steps",
            "The 'Flow steps' sheet has no rows. Every API call the test makes is one row here.",
        )

    result: dict[str, list[Step]] = {}
    for flow_id, entries in collected.items():
        indices = [step.index for _, step in entries]
        duplicates = sorted({i for i in indices if indices.count(i) > 1})
        if duplicates:
            collector.blocking(
                f"flows.{flow_id}.steps.index",
                f"Flow steps: flow {flow_id} uses step number {duplicates} more than once. "
                f"Step numbers set the order, so they must be unique within a flow.",
            )
            continue
        # Steps run in the order numbered, whatever order the rows happen to be in.
        result[flow_id] = [step for _, step in sorted(entries, key=lambda e: e[1].index)]
    return result


# --------------------------------------------------------------------------------------------
# Load profiles and SLA
# --------------------------------------------------------------------------------------------


def _parse_profiles(workbook, collector: _Collector) -> list[LoadProfile]:
    sheet = find_sheet(workbook, *PROFILES_SHEET)
    if sheet is None:
        collector.missing_sheet("Load profiles")
        return []

    header = find_header_row(sheet, ["Test type", "Required", "Concurrent users"])
    type_column = header.column_of("Test type") if header else None
    if header is None or type_column is None:
        collector.blocking(
            "load_profiles",
            "The 'Load profiles' sheet has no 'Test type' column header.",
        )
        return []

    profiles: list[LoadProfile] = []
    seen: set[ProfileId] = set()
    for row_index, cells in iter_data_rows(sheet, header, key_column=type_column):
        raw_type = cell_text(cells.get(type_column))
        profile_id = values.lookup(PROFILE_IDS, raw_type)
        location = _where("Load profiles", row_index)

        if profile_id is None:
            collector.warning(
                "load_profiles",
                f"{location}: test type {raw_type!r} is not one of "
                f"{', '.join(EXPECTED_PROFILES)}; the row is ignored.",
            )
            continue
        if profile_id in seen:
            collector.warning(
                f"load_profiles.{profile_id.value}",
                f"{location}: test type {raw_type!r} appears more than once; "
                f"only the first row is used.",
            )
            continue
        seen.add(profile_id)

        enabled = values.as_bool(_column_value(cells, header, "Required"))
        if enabled is None:
            enabled = False

        throughput = _parse_throughput(cells, header, profile_id, location, collector)

        profiles.append(
            LoadProfile(
                id=profile_id,
                enabled=enabled,
                users=values.as_int(_column_value(cells, header, "Concurrent users")),
                ramp_up_s=values.as_int(_column_value(cells, header, "Ramp-up (s)")),
                duration_s=values.minutes_to_seconds(
                    _column_value(cells, header, "Duration (min)")
                ),
                throughput=throughput,
            )
        )

    if not profiles:
        collector.blocking(
            "load_profiles",
            "The 'Load profiles' sheet has no recognisable test type rows.",
        )
    return profiles


def _parse_throughput(cells, header, profile_id, location, collector) -> Throughput | None:
    raw_value = _column_value(cells, header, "Target throughput")
    amount = values.as_float(raw_value)
    raw_unit = _column_text(cells, header, "Throughput unit")
    unit = values.lookup(THROUGHPUT_UNITS, raw_unit)

    if amount is None:
        if cell_text(raw_value) is not None:
            collector.warning(
                f"load_profiles.{profile_id.value}.throughput",
                f"{location}: 'Target throughput' is not a number; it is ignored.",
            )
        return None
    if amount <= 0:
        collector.warning(
            f"load_profiles.{profile_id.value}.throughput",
            f"{location}: 'Target throughput' must be greater than zero; it is ignored.",
        )
        return None
    if unit is None:
        collector.blocking(
            f"load_profiles.{profile_id.value}.throughput.unit",
            f"{location}: 'Target throughput' is {amount:g} but 'Throughput unit' is "
            f"{raw_unit!r}. Use TPS, TPM or TPH - the rate is meaningless without it.",
        )
        return None
    return Throughput(value=amount, unit=unit)


def _parse_sla(workbook, collector: _Collector) -> list[Sla]:
    sheet = find_sheet(workbook, *SLA_SHEET)
    if sheet is None:
        collector.warning(
            "sla",
            "The workbook has no 'SLA' sheet, so no pass/fail criteria file will be written.",
        )
        return []

    header = find_header_row(sheet, ["Applies to", "Metric", "Target"])
    scope_column = header.column_of("Applies to") if header else None
    if header is None or scope_column is None:
        collector.warning("sla", "The 'SLA' sheet has no 'Applies to' column header.")
        return []

    slas: list[Sla] = []
    for row_index, cells in iter_data_rows(sheet, header, key_column=scope_column):
        location = _where("SLA", row_index)
        scope = values.sla_scope(cells.get(scope_column))
        metric = values.lookup(SLA_METRICS, _column_text(cells, header, "Metric"))
        target = values.as_float(_column_value(cells, header, "Target"))
        unit = values.lookup(SLA_UNITS, _column_text(cells, header, "Unit"))

        if metric is None:
            collector.warning(
                "sla.metric",
                f"{location}: metric {_column_text(cells, header, 'Metric')!r} is not "
                f"recognised; the row is ignored.",
            )
            continue
        if target is None:
            collector.warning(
                "sla.target", f"{location}: 'Target' is empty or not a number; the row is ignored."
            )
            continue
        if unit is None:
            collector.warning(
                "sla.unit",
                f"{location}: unit {_column_text(cells, header, 'Unit')!r} is not recognised; "
                f"the row is ignored.",
            )
            continue

        slas.append(Sla(scope=scope or "all", metric=metric, target=target, unit=unit))

    if not slas:
        # Legal, not a gap - but say it was read, so nobody wonders whether it was checked.
        collector.note(
            "The 'SLA' sheet has no targets. That is allowed: no pass/fail criteria file will be "
            "written, and the generated script is unaffected either way."
        )
    return slas


# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------


def _column_value(cells: dict[int, object], header, *names: str):
    column = header.column_of(*names)
    return None if column is None else cells.get(column)


def _column_text(cells: dict[int, object], header, *names: str) -> str | None:
    return cell_text(_column_value(cells, header, *names))


def _where(sheet_name: str, row_index: int | None) -> str:
    """Name the cell to fix, not just the field that is wrong."""
    if row_index is None:
        return sheet_name
    return f"{sheet_name}, row {row_index}"

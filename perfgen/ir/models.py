"""Pydantic v2 models for the Test Plan IR.

The IR is the contract between every stage and the surface an engineer reviews by hand, so the
models are strict: `extra="forbid"` means a typo in hand-edited YAML fails loudly instead of being
silently dropped on the floor.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Stamped into every IR but never read back: nothing validates it, and it has not been bumped for
# the schema changes made so far (ExtractorType.XPATH being the first forward-only one). So it
# records intent, not compatibility - do not rely on it to detect an IR from a newer build.
SPEC_VERSION = 1


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# --------------------------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------------------------


class AuthType(StrEnum):
    NONE = "none"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    OAUTH2_PASSWORD = "oauth2_password"
    OAUTH2_PKCE = "oauth2_pkce"
    BEARER_STATIC = "bearer_static"
    API_KEY = "api_key"
    BASIC = "basic"

    @property
    def needs_token_request(self) -> bool:
        """OAuth flows acquire a token from an endpoint; the static schemes do not."""
        return self.value.startswith("oauth2_")

    @property
    def is_static_credential(self) -> bool:
        """These carry a secret straight into the header, with no token call to make.

        Their credential is read from the environment at run time, exactly like an OAuth client
        secret - the difference is only that nothing is exchanged for it first.
        """
        return self in {AuthType.BEARER_STATIC, AuthType.API_KEY, AuthType.BASIC}


class AuthStrategy(StrEnum):
    SHARED_SETUP = "shared_setup"
    PER_THREAD = "per_thread"


class Method(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class Source(StrEnum):
    RESPONSE_BODY = "response_body"
    RESPONSE_HEADER = "response_header"
    COOKIE = "cookie"


class ExtractorType(StrEnum):
    JSON_PATH = "json_path"
    # Added after json_path/regex/boundary/header, so this is a forward-only change: an IR written
    # by this version fails to load on a build that predates it, with pydantic reporting only
    # "Input should be 'json_path', 'regex', 'boundary' or 'header'". That is diagnosable but says
    # nothing about version skew, which matters when two checkouts of this tool sit side by side.
    XPATH = "xpath"
    REGEX = "regex"
    BOUNDARY = "boundary"
    HEADER = "header"


class Scope(StrEnum):
    """Where the extractor sits in the tree and how the value is shared.

    Wrong scope produces scripts that pass a single-user smoke test and fail under load, so it is
    explicit in the IR rather than inferred at emit time.
    """

    GLOBAL = "global"
    THREAD = "thread"
    ITERATION = "iteration"


class Confidence(StrEnum):
    VERIFIED = "verified"
    INFERRED = "inferred"


class TokenConfidence(StrEnum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class ProfileId(StrEnum):
    BASELINE = "baseline"
    PEAK = "peak"
    CAPACITY = "capacity"
    ENDURANCE = "endurance"


class ThroughputUnit(StrEnum):
    TPS = "tps"
    TPM = "tpm"
    TPH = "tph"

    def to_per_minute(self, value: float) -> float:
        """JMeter's Constant Throughput Timer is configured in samples per minute."""
        return {
            ThroughputUnit.TPS: value * 60.0,
            ThroughputUnit.TPM: value,
            ThroughputUnit.TPH: value / 60.0,
        }[self]


class SlaMetric(StrEnum):
    # p50/p90 are absent from the brief's list but offered by the workbook's Metric dropdown;
    # rejecting them would make a legal spec unparseable at M2.
    RESPONSE_TIME_P50 = "response_time_p50"
    RESPONSE_TIME_P90 = "response_time_p90"
    RESPONSE_TIME_P95 = "response_time_p95"
    RESPONSE_TIME_P99 = "response_time_p99"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"


class SlaUnit(StrEnum):
    MS = "ms"
    S = "s"
    PERCENT = "percent"
    TPS = "tps"
    TPM = "tpm"
    TPH = "tph"


class Severity(StrEnum):
    BLOCKING = "blocking"
    WARNING = "warning"


class AssertionType(StrEnum):
    RESPONSE_CODE = "response_code"


# --------------------------------------------------------------------------------------------
# Application and auth
# --------------------------------------------------------------------------------------------


class Application(_Base):
    name: str
    base_url: str = Field(description="scheme + host, no trailing slash")
    base_path: str | None = None
    api_reference: str | None = Field(
        default=None,
        description="Recorded for reference only. Nothing reads it; Swagger pre-fill is a non-goal",
    )
    additional_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Literal headers sent on every request, alongside the auth header. Values are written "
            "into the script as-is and are never resolved from anywhere - a credential belongs in "
            "auth.token_request.credential_refs or auth.static_credential_refs instead. Lives on "
            "the application rather than under auth because an API can demand a header with "
            "auth.type of none: Twitch's Helix needs Client-Id on every call."
        ),
    )

    @model_validator(mode="after")
    def _no_trailing_slash(self) -> Application:
        if self.base_url.endswith("/"):
            raise ValueError(f"base_url must not have a trailing slash: {self.base_url!r}")
        return self


class TokenRequest(_Base):
    method: str
    url: str
    content_type: str
    param_names: list[str] = Field(
        default_factory=list, description="names only — never values"
    )
    credential_refs: list[str] = Field(
        default_factory=list, description="secret reference names only"
    )


class TokenExtract(_Base):
    var: str = Field(description="variable/property name the token is published under")
    source: Source = Source.RESPONSE_BODY
    expr: str | None = Field(default=None, description="null until the probe determines it")
    confidence: TokenConfidence = TokenConfidence.UNKNOWN


class Auth(_Base):
    type: AuthType
    strategy: AuthStrategy = AuthStrategy.SHARED_SETUP
    token_request: TokenRequest | None = None
    token_extract: TokenExtract | None = None
    lifetime_seconds: int | None = None
    header_name: str | None = None
    value_format: str | None = Field(default=None, description='e.g. "Bearer {token}"')
    static_credential_refs: list[str] = Field(
        default_factory=list,
        description=(
            "Secret reference names carrying the credential for a static scheme "
            "(bearer_static, api_key, basic). Names only - the value is read at run time. "
            "One reference for a token or key; two for basic auth's user and password."
        ),
    )
    refresh_required: bool | None = Field(
        default=None,
        description="computed at the plan level: any enabled duration > lifetime",
    )

    @model_validator(mode="after")
    def _required_when_authenticated(self) -> Auth:
        if self.type is AuthType.NONE:
            return self
        missing = [f for f in ("header_name", "value_format") if getattr(self, f) is None]
        if missing:
            raise ValueError(f"auth.{'/'.join(missing)} required when auth.type is {self.type}")
        if self.type.needs_token_request:
            absent = [
                f for f in ("token_request", "token_extract") if getattr(self, f) is None
            ]
            if absent:
                raise ValueError(
                    f"auth.{'/'.join(absent)} required for OAuth flow {self.type}"
                )
        if self.type.is_static_credential:
            # Without a reference there is no secret to put in the header, and one is never
            # invented - the script would otherwise authenticate with nothing and 401 on every
            # request, which reads as a broken API rather than an incomplete spec.
            if not self.static_credential_refs:
                raise ValueError(
                    f"auth.static_credential_refs required for {self.type}: the credential "
                    f"has to come from somewhere"
                )
            limit = 2 if self.type is AuthType.BASIC else 1
            if len(self.static_credential_refs) > limit:
                raise ValueError(
                    f"auth.static_credential_refs for {self.type} takes at most {limit} "
                    f"reference(s), got {self.static_credential_refs}"
                )
        return self


# --------------------------------------------------------------------------------------------
# Flows and steps
# --------------------------------------------------------------------------------------------


class Extract(_Base):
    var: str
    source: Source
    extractor: ExtractorType
    expr: str
    scope: Scope
    confidence: Confidence
    evidence: str = Field(description="why this correlation is believed to exist")
    used_by: list[str] = Field(default_factory=list, description='e.g. ["F01.2.path"]')
    needs_review: bool = Field(
        default=False,
        description="set when a value appears transformed rather than copied",
    )


class Assertion(_Base):
    type: AssertionType = AssertionType.RESPONSE_CODE
    value: int


class Step(_Base):
    index: int = Field(ge=1)
    name: str
    method: Method
    path: str = Field(description="may contain {varName} placeholders")
    body: str | None = None
    content_type: str | None = Field(default=None, description="inferred from body when absent")
    expected_status: int
    headers: dict[str, str] = Field(default_factory=dict)
    extracts: list[Extract] = Field(default_factory=list)
    assertions: list[Assertion] = Field(
        default_factory=list,
        description="expected_status is authoritative; assertions are derived at emit time",
    )


class Flow(_Base):
    id: str = Field(description="F01")
    name: str
    share_pct: int = Field(ge=0, le=100)
    think_time_ms: int = Field(ge=0)
    probe_safe: bool
    headers: dict[str, str] = Field(default_factory=dict)
    steps: list[Step] = Field(min_length=1)

    @model_validator(mode="after")
    def _steps_ordered(self) -> Flow:
        indices = [s.index for s in self.steps]
        if indices != sorted(indices):
            raise ValueError(
                f"flow {self.id}: steps must be in ascending index order, got {indices}"
            )
        if len(set(indices)) != len(indices):
            raise ValueError(f"flow {self.id}: duplicate step index in {indices}")
        return self


# --------------------------------------------------------------------------------------------
# Load, SLA, gaps, provenance
# --------------------------------------------------------------------------------------------


class Throughput(_Base):
    value: float = Field(gt=0)
    unit: ThroughputUnit

    def per_minute(self) -> float:
        return self.unit.to_per_minute(self.value)


class LoadProfile(_Base):
    id: ProfileId
    enabled: bool
    users: int | None = Field(default=None, ge=1)
    ramp_up_s: int | None = Field(default=None, ge=0)
    duration_s: int | None = Field(default=None, ge=1)
    throughput: Throughput | None = None


class Sla(_Base):
    scope: str = Field(description='"all" or a flow id')
    metric: SlaMetric
    target: float
    unit: SlaUnit


class Gap(_Base):
    field: str = Field(description="dotted path, e.g. load_profiles.capacity.users")
    severity: Severity
    message: str


class ProbeProvenance(_Base):
    performed: bool = False
    timestamp: str | None = None
    steps_observed: int = 0
    skipped_flows: list[str] = Field(
        default_factory=list, description="flows with probe_safe false"
    )
    degraded: bool = Field(
        default=False, description="probe could not run at all; correlations inferred"
    )


class Provenance(_Base):
    source_workbook: str
    generated_at: str = Field(description="ISO 8601")
    probe: ProbeProvenance = Field(default_factory=ProbeProvenance)


# --------------------------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------------------------


class TestPlanIR(_Base):
    spec_version: int = SPEC_VERSION
    application: Application
    auth: Auth
    flows: list[Flow] = Field(default_factory=list)
    load_profiles: list[LoadProfile] = Field(default_factory=list)
    sla: list[Sla] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    provenance: Provenance

    @model_validator(mode="after")
    def _compute_refresh_required(self) -> TestPlanIR:
        """`refresh_required` is derived, but a disagreeing hand-edit must not pass silently."""
        computed = False
        if self.auth.lifetime_seconds is not None:
            computed = any(
                p.enabled and p.duration_s is not None and p.duration_s > self.auth.lifetime_seconds
                for p in self.load_profiles
            )
        if self.auth.refresh_required is not None and self.auth.refresh_required != computed:
            raise ValueError(
                f"auth.refresh_required is {self.auth.refresh_required} but the profiles and a "
                f"token lifetime of {self.auth.lifetime_seconds}s compute to {computed}. "
                "Omit the field to have it derived."
            )
        self.auth.refresh_required = computed
        return self

    @model_validator(mode="after")
    def _unique_flow_ids(self) -> TestPlanIR:
        ids = [f.id for f in self.flows]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise ValueError(f"duplicate flow id(s): {sorted(duplicates)}")
        return self

    @model_validator(mode="after")
    def _unique_profile_ids(self) -> TestPlanIR:
        ids = [p.id for p in self.load_profiles]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise ValueError(f"duplicate load profile id(s): {sorted(duplicates)}")
        return self

    @property
    def enabled_profiles(self) -> list[LoadProfile]:
        return [p for p in self.load_profiles if p.enabled]

    def flow(self, flow_id: str) -> Flow | None:
        return next((f for f in self.flows if f.id == flow_id), None)

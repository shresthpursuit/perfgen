"""Stable names for generated elements and JMeter properties.

Transaction Controller names must be stable and sortable so that two runs of the generator over the
same spec produce diffable output and results group predictably in a report.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from perfgen.secrets import env_var_name

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def slug(text: str) -> str:
    """Lowercase, underscore-separated, alphanumeric only."""
    return _NON_ALNUM.sub("_", text.strip().lower()).strip("_")


def transaction_name(flow_id: str, step_index: int, step_name: str) -> str:
    """`{flow_id}_{step_index:02d}_{step_name_slug}` — stable and sortable."""
    return f"{flow_id}_{step_index:02d}_{slug(step_name)}"


def users_prop(flow_id: str) -> str:
    """Per-flow, never per-profile: one JMX serves every profile via property files (D1)."""
    return f"users_{flow_id}"


def throughput_prop(flow_id: str) -> str:
    return f"tput_{flow_id}"


RAMPUP_PROP = "rampup_s"
DURATION_PROP = "duration_s"


def prop_ref(name: str, default: object) -> str:
    """`${__P(name,default)}`."""
    return f"${{__P({name},{default})}}"


def var_ref(name: str, scope_is_global: bool) -> str:
    """A `global`-scoped value lives in a JMeter property; the others are thread variables."""
    return f"${{__P({name})}}" if scope_is_global else f"${{{name}}}"


def java_hash_code(text: str) -> int:
    """Java's String.hashCode(), which JMeter uses to key assertion test strings."""
    h = 0
    for char in text:
        h = (31 * h + ord(char)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def split_base_url(base_url: str) -> tuple[str, str, str]:
    """Split a base URL into (protocol, host, port), port empty when the scheme default applies."""
    protocol, host, port, _ = split_url(base_url)
    return protocol, host, port


def split_url(url: str) -> tuple[str, str, str, str]:
    """Split a full URL into (protocol, host, port, path)."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"URL must include a scheme and host: {url!r}")
    port = "" if parts.port is None else str(parts.port)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return parts.scheme, parts.hostname, port, path


def env_var(reference_name: str) -> str:
    """`perf-client-id` -> `PERF_CLIENT_ID`, per the brief's secrets resolution rule.

    Re-exported from `perfgen.secrets` rather than reimplemented: the script the emitter writes
    and the lookup the probe performs must name the same variable, and two copies of this rule
    would eventually disagree - the probe passing while the generated script failed to
    authenticate, with nothing in either output to explain why.
    """
    return env_var_name(reference_name)


def env_lookup(reference_name: str) -> str:
    """A run-time environment lookup that works in stock JMeter.

    `${__env(...)}` is NOT a core JMeter function - it ships with the third-party jpgc Custom
    Functions plugin. An unknown function is not an error in JMeter: it is passed through as
    literal text, so a script using `__env` silently authenticates with the string
    "${__env(PERF_CLIENT_ID)}" and fails in a way that looks like a credentials problem.

    `__groovy` is core, so `System.getenv` is the portable way to read a secret at run time. Only
    the variable's name is ever written here - never its value.
    """
    return f"${{__groovy(System.getenv('{env_var(reference_name)}'))}}"


def _normalise_ref(name: str) -> str:
    return _NON_ALNUM.sub("_", name.strip().lower()).strip("_")


def match_credential_ref(param_name: str, credential_refs: list[str]) -> str | None:
    """Find the credential reference that supplies a token request parameter.

    The IR lists parameter names and credential reference names as two independent lists with no
    mapping between them, so which secret fills which parameter has to be matched by name. Three
    tiers, most specific first:

    1. the normalised names are equal;
    2. the reference ends with `_<parameter>` - `perf-client-secret` supplies `client_secret`;
    3. their final words agree - `claims-perf-id` supplies `client_id`, which tier 2 misses
       because real reference names are usually prefixed by system rather than by parameter.

    A tier that produces more than one candidate is ambiguous, and an ambiguous credential is not
    guessed at: the caller is told there is no match and says so. `grant_type` matches nothing at
    any tier, which is correct - it is a protocol constant, not a secret.
    """
    target = _normalise_ref(param_name)
    if not target:
        return None
    normalised = {ref: _normalise_ref(ref) for ref in credential_refs}

    tiers = (
        [ref for ref, norm in normalised.items() if norm == target],
        [ref for ref, norm in normalised.items() if norm.endswith(f"_{target}")],
        [
            ref
            for ref, norm in normalised.items()
            if norm.rsplit("_", 1)[-1] == target.rsplit("_", 1)[-1]
        ],
    )

    for candidates in tiers:
        unique = sorted(set(candidates))
        if len(unique) == 1:
            return unique[0]
        if len(unique) > 1:
            return None  # ambiguous: two references could supply this parameter
    return None

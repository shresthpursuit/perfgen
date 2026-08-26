"""Last check before anything is pushed: does a credential appear in the files themselves?

Defense in depth. The emitter's guarantee is that no secret value is ever written into a `.jmx`,
and that guarantee holds - but two things get past it, and one of them already has.

**A hand-edit.** The publish flow explicitly invites an engineer to edit the generated files before
running `publish`. A token pasted in to debug something is not the emitter's fault and not
something the emitter can prevent.

**A literal the specification supplied.** `application.additional_headers` is documented as literal
only, "written into the script as-is, resolved from nowhere". That is the one channel where a
user-supplied value reaches the script without ever being a secret *reference*, so nothing upstream
treats it as one. A real publish put a live `Client-Id` into a repository this way.

Two layers, because either alone misses that incident:

* **By value.** Every credential the specification declares, resolved and matched wherever it
  appears. The strong guarantee - it does not matter which field the value ended up in. Its limit
  is that a reference whose variable is unset locally cannot be checked at all, and reporting that
  silently is exactly how the incident above was missed. Unset references are named out loud.
* **By name and shape.** A field whose *name* reads like a credential, or whose *value* looks like
  one, is flagged whether or not it was ever a resolvable reference. This is the layer that catches
  a literal nobody declared.

Anything flagged blocks the publish, and there is deliberately no way to exempt it. An allowlist
keyed on the header *name* was built and then removed: a name is global across every specification,
so allowing `Client-Id` for one API would also wave through a header of that name on a different
API whose value is genuinely secret - reopening the hole this exists to close. Scoping an exemption
to name *and* value would fix that, and is cheap, but there is one case to generalise from and no
second real one yet to show what a genuine exemption needs to look like. So it waits, as XML
parsing, token refresh and credential-sourced headers each did.

The practical consequence is that a specification carrying a credential-shaped literal cannot be
published at all. That is the correct state, not a gap to route around: if such a value is a real
requirement, the work is to close the credential-sourced-headers deferral so it resolves from the
environment like every other credential, not to add a list of things nobody checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

from perfgen import secrets
from perfgen.ir.models import AuthType, TestPlanIR
from perfgen.probe.redact import Redactor, is_sensitive_key

# Field names that read like a credential but that `is_sensitive_key` does not cover. Kept here
# rather than added to it: that function drives probe-record redaction, and widening it would
# change what the probe writes to disk - a different stage, for a different reason.
# `Client-Id` normalises to `clientid` and matches none of the existing parts, which is why the
# incident this module exists for went unnoticed.
EXTRA_SENSITIVE_PARTS = ("clientid", "signature", "key")

# A value with no internal structure, long enough to be a generated credential. Deliberately
# excludes anything containing `/`, `.`, or whitespace, which is what separates a token from a
# media type (`application/x-www-form-urlencoded`), a version, or prose.
_OPAQUE_VALUE = re.compile(r"^[A-Za-z0-9_-]{20,}$")

# Credential formats recognisable on sight, whoever wrote them.
_GENERIC_PATTERNS = {
    "a JSON Web Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    "a GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    "an AWS access key id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "a literal Authorization value": re.compile(r"(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{16,}"),
}


@dataclass
class ScanReport:
    """Shaped like `perfgen.validate.ValidationReport` so both read the same in a summary."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def __str__(self) -> str:
        if self.ok and not self.warnings:
            return "Secrets scan passed."
        lines = []
        for error in self.errors:
            lines.append(f"  [ERROR]   {error}")
        for warning in self.warnings:
            lines.append(f"  [warning] {warning}")
        return "\n".join(lines)


def looks_like_credential_field(name: str) -> bool:
    """Does this field name suggest it carries a credential?"""
    if is_sensitive_key(name):
        return True
    normalised = re.sub(r"[^a-z0-9]+", "", name.strip().lower())
    return any(part in normalised for part in EXTRA_SENSITIVE_PARTS)


def looks_like_credential_value(value: str) -> bool:
    """Is this value shaped like a generated credential rather than a configuration string?"""
    if "${" in value:
        # A JMeter function or variable reference resolves at run time and carries nothing.
        return False
    return bool(_OPAQUE_VALUE.match(value.strip()))


# --------------------------------------------------------------------------------------------
# Layer 1: by value
# --------------------------------------------------------------------------------------------


def declared_references(ir: TestPlanIR) -> list[str]:
    """Every secret reference name the specification declares, in no particular order."""
    references: list[str] = list(ir.auth.static_credential_refs)
    if ir.auth.token_request is not None:
        references.extend(ir.auth.token_request.credential_refs)
        # A token parameter can be resolved by its own name when no reference matched it, so it is
        # a live credential even though it never appears in credential_refs.
        references.extend(ir.auth.token_request.param_names)
    # `{secret:...}` written inline in a PKCE login step. These never appear in credential_refs -
    # they are named in the step text - so without this the value pass has nothing to match a
    # login password against.
    references.extend(ir.auth.step_credential_refs)
    seen: dict[str, None] = {}
    for reference in references:
        seen.setdefault(reference, None)
    return list(seen)


def resolve_known_values(ir: TestPlanIR) -> tuple[list[str], list[tuple[str, str]]]:
    """Resolve what this environment can, and report what it cannot as (reference, variable)."""
    values: list[str] = []
    unresolved: list[tuple[str, str]] = []

    for reference in declared_references(ir):
        try:
            values.append(secrets.resolve(reference))
        except secrets.MissingSecret as exc:
            unresolved.append((exc.reference, exc.variable))

    if ir.auth.type is AuthType.BASIC and len(ir.auth.static_credential_refs) == 2:
        # The probe adds the encoded blob to its redactor for the same reason: the credential
        # travels as base64, and neither half matches on its own.
        import base64

        try:
            user = secrets.resolve(ir.auth.static_credential_refs[0])
            password = secrets.resolve(ir.auth.static_credential_refs[1])
        except secrets.MissingSecret:
            pass
        else:
            values.append(base64.b64encode(f"{user}:{password}".encode()).decode())

    return values, unresolved


# --------------------------------------------------------------------------------------------
# Layer 2: by name and shape
# --------------------------------------------------------------------------------------------


def _jmx_headers(text: str) -> list[tuple[str, str]]:
    """Every (name, value) pair from every HeaderManager in an emitted test plan."""
    try:
        root = etree.fromstring(text.encode("utf-8"))
    except etree.XMLSyntaxError:
        # Structural validation runs before this and reports a malformed file properly.
        return []

    pairs: list[tuple[str, str]] = []
    for element in root.iter("elementProp"):
        if element.get("elementType") != "Header":
            continue
        name = element.findtext('stringProp[@name="Header.name"]') or ""
        value = element.findtext('stringProp[@name="Header.value"]') or ""
        if name:
            pairs.append((name, value))
    return pairs


def _properties_entries(text: str) -> list[tuple[str, str]]:
    entries = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        entries.append((name.strip(), value.strip()))
    return entries


def _fields_in(path: Path, text: str) -> list[tuple[str, str]]:
    if path.suffix == ".jmx":
        return _jmx_headers(text)
    if path.suffix == ".properties":
        return _properties_entries(text)
    return []


# --------------------------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------------------------


def scan_files(files: list[Path], ir: TestPlanIR) -> ScanReport:
    """Scan everything about to be published. Any error stops the publish, with no way to override.

    There is no exemption parameter by design - see the module docstring.
    """
    report = ScanReport()

    known_values, unresolved = resolve_known_values(ir)
    redactor = Redactor(known_values)

    if unresolved:
        listing = ", ".join(f"{reference} -> {variable}" for reference, variable in unresolved)
        report.warnings.append(
            f"{len(unresolved)} of {len(unresolved) + len(known_values)} declared credential(s) "
            f"could not be checked by value, because their variables are not set in this "
            f"environment: {listing}. Anything matching only those values would not be caught by "
            f"the value pass. The name and shape checks still apply."
        )

    for path in files:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            report.errors.append(f"{path.name} could not be read to scan it: {exc}")
            continue

        if known_values and redactor.scrub(text) != text:
            report.errors.append(
                f"{path.name} contains the value of a declared credential. That value must never "
                f"reach a file - the script reads it at run time from the environment."
            )

        for label, pattern in _GENERIC_PATTERNS.items():
            for match in pattern.finditer(text):
                if "${" in match.group(0):
                    continue
                report.errors.append(
                    f"{path.name} contains what looks like {label}: "
                    f"{match.group(0)[:12]}... (truncated)"
                )

        for name, value in _fields_in(Path(path), text):
            if not value or "${" in value:
                continue
            by_name = looks_like_credential_field(name)
            by_shape = looks_like_credential_value(value)
            if by_name or by_shape:
                reason = (
                    "its name reads as a credential"
                    if by_name and not by_shape
                    else "its value is shaped like a generated credential"
                    if by_shape and not by_name
                    else "its name reads as a credential and its value is shaped like one"
                )
                report.errors.append(
                    f"{path.name} publishes {name!r} as a literal value and {reason}. There is no "
                    f"way to exempt it: take the value out of the specification. If the request "
                    f"genuinely needs this header, it has to resolve from the environment like "
                    f"every other credential - which means closing the deferral on "
                    f"credential-sourced headers, not publishing the value."
                )

    return report

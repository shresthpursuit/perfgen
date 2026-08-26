"""Resolving secret reference names to values at run time.

The workbook contains reference *names* (`perf-client-id`), never values. The probe needs the real
thing; the generated script reads it itself at run time. Nothing in between writes it down.

`env_var_name` is deliberately the single definition of the mapping. The emitter uses it to write
`${__groovy(System.getenv('PERF_CLIENT_ID'))}` into the JMX and the probe uses it to look the value
up. If those two ever disagreed, the probe would succeed and the generated script would fail
authentication with nothing to show why.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# An inline credential reference, as written in a workbook cell:
#     login={secret:pkce-login-user}&passwd={secret:pkce-login-password}&ctx={sCtx}
#
# Deliberately distinct from the `{correlatedVar}` placeholder syntax, because the two resolve at
# different times from different sources: a correlated variable is discovered from observed traffic
# and written into the script, a credential is never written down at all and is read from the
# environment when the script runs. Someone reading a cell should be able to tell which is which
# without knowing the rules.
#
# The colon is load-bearing rather than decorative. `rewrite_placeholders` matches
# `\{([A-Za-z_][A-Za-z0-9_]*)\}`, and the colon ends that character class before the closing brace,
# so the two patterns are structurally incapable of matching the same text and no ordering between
# the two rewrites has to be remembered. A `{{ref}}` form would not have that property: the inner
# `{userId}` of `{{userId}}` matches the placeholder pattern and would be rewritten inside it.
SECRET_REF = re.compile(r"\{secret:([A-Za-z_][A-Za-z0-9_.-]*)\}")

# `{secret:}` and `{secret: }` - written by someone who meant to fill it in.
MALFORMED_SECRET_REF = re.compile(r"\{secret:\s*\}")


def references_in(text: str | None) -> list[str]:
    """Every credential reference named in a string, in order, without repeats."""
    if not text:
        return []
    return list(dict.fromkeys(SECRET_REF.findall(text)))


def substitute(text: str, resolver) -> str:
    """Replace every `{secret:name}` using `resolver(name)`.

    One function for both callers, so the syntax has a single definition. The probe passes
    `resolve` and gets real values to send; the emitter passes `naming.env_lookup` and gets a
    run-time lookup to write into the script. Neither knows about the other.
    """
    if not text:
        return text
    return SECRET_REF.sub(lambda match: resolver(match.group(1)), text)


class MissingSecret(RuntimeError):
    """A referenced secret is not set. Never substituted with a default or an empty string."""

    def __init__(self, reference: str, variable: str):
        self.reference = reference
        self.variable = variable
        super().__init__(
            f"The specification references the secret {reference!r}, which is read from the "
            f"environment variable {variable}. That variable is not set.\n"
            f"  Set it for this shell:  export {variable}=...\n"
            f"  or add it to a .env file at the repository root (.env is gitignored).\n"
            f"No default is substituted - an empty credential would produce a script that runs "
            f"and fails authentication on every request."
        )


def env_var_name(reference: str) -> str:
    """`perf-client-id` -> `PERF_CLIENT_ID`.

    Uppercase, with every run of non-alphanumeric characters collapsed to a single underscore.
    """
    return _NON_ALNUM.sub("_", reference.strip().lower()).strip("_").upper()


def load_dotenv(root: str | Path | None = None) -> Path | None:
    """Load a `.env` from the repository root if one is present.

    Values already in the environment win, so an explicitly exported variable is never overridden
    by a stale file.

    Read as `utf-8-sig`, not `utf-8`, so a byte order mark is discarded rather than absorbed into
    the first key name. PowerShell's `>` and `Out-File` write a BOM by default, which is the most
    natural way for a Windows user to create this file - and the failure it caused was silent and
    badly misleading: the BOM became part of the key, so the variable read back as unset while
    sitting in plain sight in the file, and the tool reported it as never having been set.
    """
    from dotenv import load_dotenv as _load

    candidate = Path(root or Path.cwd()) / ".env"
    if not candidate.is_file():
        return None
    _load(candidate, override=False, encoding="utf-8-sig")
    return candidate


def resolve(reference: str) -> str:
    """Return the value for a reference name, or raise naming the exact variable expected."""
    variable = env_var_name(reference)
    value = os.environ.get(variable)
    if value is None or value == "":
        raise MissingSecret(reference, variable)
    return value


class MissingSecrets(RuntimeError):
    """Several referenced secrets are unset. Reported together so one run fixes them all."""

    def __init__(self, missing: list[tuple[str, str]]):
        self.missing = missing
        listing = "\n".join(f"  {reference}  ->  {variable}" for reference, variable in missing)
        super().__init__(
            "The specification references secrets that are not set in the environment:\n"
            f"{listing}\n"
            "Set them for this shell, or add them to a .env file at the repository root "
            "(.env is gitignored). No defaults are substituted."
        )


def resolve_all(references: list[str]) -> dict[str, str]:
    """Resolve every reference, reporting all the missing ones at once rather than the first."""
    resolved: dict[str, str] = {}
    missing: list[tuple[str, str]] = []

    for reference in references:
        try:
            resolved[reference] = resolve(reference)
        except MissingSecret as exc:
            missing.append((exc.reference, exc.variable))

    if len(missing) == 1:
        raise MissingSecret(*missing[0])
    if missing:
        raise MissingSecrets(missing)
    return resolved

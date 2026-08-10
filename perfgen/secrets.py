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
    """
    from dotenv import load_dotenv as _load

    candidate = Path(root or Path.cwd()) / ".env"
    if not candidate.is_file():
        return None
    _load(candidate, override=False)
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

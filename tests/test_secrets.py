"""Secret resolution.

The rule with teeth: a referenced secret that is not set fails loudly, naming the exact variable.
Never a default, never an empty string - an empty credential produces a script that runs and fails
authentication on every request, which looks like an API problem rather than a setup problem.
"""

from __future__ import annotations

import pytest

from perfgen import secrets
from perfgen.emit import naming
from perfgen.secrets import MissingSecret, MissingSecrets, env_var_name, resolve, resolve_all


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("perf-client-id", "PERF_CLIENT_ID"),
        ("claims-perf-secret", "CLAIMS_PERF_SECRET"),
        ("already_snake", "ALREADY_SNAKE"),
        ("Mixed.Case-Name", "MIXED_CASE_NAME"),
        ("  spaced  out  ", "SPACED_OUT"),
        ("多-token", "TOKEN"),
    ],
)
def test_env_var_name_mapping(reference, expected):
    assert env_var_name(reference) == expected


def test_emitter_and_probe_share_one_definition():
    """If these ever diverged, the probe would pass and the generated script would not."""
    assert naming.env_var("perf-client-id") == env_var_name("perf-client-id")


def test_resolve_reads_the_environment(monkeypatch):
    monkeypatch.setenv("PERF_CLIENT_ID", "abc123")
    assert resolve("perf-client-id") == "abc123"


def test_missing_secret_names_the_exact_variable(monkeypatch):
    monkeypatch.delenv("PERF_CLIENT_ID", raising=False)
    with pytest.raises(MissingSecret) as exc:
        resolve("perf-client-id")
    assert exc.value.variable == "PERF_CLIENT_ID"
    assert "PERF_CLIENT_ID" in str(exc.value)
    assert "perf-client-id" in str(exc.value)


def test_empty_variable_is_treated_as_missing(monkeypatch):
    """An exported-but-empty variable is the trap this exists to catch."""
    monkeypatch.setenv("PERF_CLIENT_ID", "")
    with pytest.raises(MissingSecret):
        resolve("perf-client-id")


def test_no_default_is_ever_substituted(monkeypatch):
    monkeypatch.delenv("PERF_CLIENT_ID", raising=False)
    with pytest.raises(MissingSecret) as exc:
        resolve("perf-client-id")
    assert "No default is substituted" in str(exc.value)


def test_resolve_all_reports_every_missing_secret_at_once(monkeypatch):
    monkeypatch.delenv("PERF_CLIENT_ID", raising=False)
    monkeypatch.delenv("PERF_CLIENT_SECRET", raising=False)
    with pytest.raises(MissingSecrets) as exc:
        resolve_all(["perf-client-id", "perf-client-secret"])
    message = str(exc.value)
    assert "PERF_CLIENT_ID" in message
    assert "PERF_CLIENT_SECRET" in message


def test_resolve_all_returns_values_keyed_by_reference(monkeypatch):
    monkeypatch.setenv("PERF_CLIENT_ID", "id-value")
    monkeypatch.setenv("PERF_CLIENT_SECRET", "secret-value")
    assert resolve_all(["perf-client-id", "perf-client-secret"]) == {
        "perf-client-id": "id-value",
        "perf-client-secret": "secret-value",
    }


def test_dotenv_is_loaded_when_present(tmp_path, monkeypatch):
    monkeypatch.delenv("PERF_FROM_DOTENV", raising=False)
    (tmp_path / ".env").write_text("PERF_FROM_DOTENV=from-file\n", encoding="utf-8")

    assert secrets.load_dotenv(tmp_path) is not None
    assert resolve("perf-from-dotenv") == "from-file"


def test_exported_variable_beats_the_dotenv_file(tmp_path, monkeypatch):
    """A stale file must not silently override what the operator exported for this run."""
    monkeypatch.setenv("PERF_OVERRIDE", "from-shell")
    (tmp_path / ".env").write_text("PERF_OVERRIDE=from-file\n", encoding="utf-8")

    secrets.load_dotenv(tmp_path)
    assert resolve("perf-override") == "from-shell"


def test_absent_dotenv_is_not_an_error(tmp_path):
    assert secrets.load_dotenv(tmp_path) is None


# --------------------------------------------------------------------------------------------
# Matching token parameters to credential references
#
# The IR carries param_names and credential_refs as two unrelated lists, so which secret fills
# which parameter is matched by name. Found by running the probe: real reference names are
# prefixed by system ("claims-perf-id"), not by parameter ("perf-client-id"), and the original
# suffix-only rule silently missed them.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("param", "refs", "expected"),
    [
        # Tier 1: identical names.
        ("client_id", ["client_id", "other"], "client_id"),
        # Tier 2: reference prefixed by the parameter it supplies.
        ("client_secret", ["perf-client-id", "perf-client-secret"], "perf-client-secret"),
        ("client_id", ["perf-client-id", "perf-client-secret"], "perf-client-id"),
        # Tier 3: final words agree - the real-world shape that used to be missed.
        ("client_id", ["claims-perf-id", "claims-perf-secret"], "claims-perf-id"),
        ("client_secret", ["claims-perf-id", "claims-perf-secret"], "claims-perf-secret"),
        # A protocol constant is not a credential and must match nothing.
        ("grant_type", ["claims-perf-id", "claims-perf-secret"], None),
        ("scope", ["perf-client-id"], None),
        # Nothing to match against.
        ("client_id", [], None),
    ],
)
def test_credential_reference_matching(param, refs, expected):
    assert naming.match_credential_ref(param, refs) == expected


def test_ambiguous_credentials_are_not_guessed_at():
    """Two references could supply this parameter; picking one would be a coin toss."""
    assert naming.match_credential_ref("client_id", ["alpha-id", "beta-id"]) is None

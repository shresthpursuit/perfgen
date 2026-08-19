"""The last check before a push: does a credential appear in the files themselves?

Written after a real publish put a live `Client-Id` into a repository. The value came from
`application.additional_headers`, which is documented as literal-only and resolved from nowhere -
so it was never a secret *reference*, and a value-matching scan had nothing to match it against.
`test_the_literal_client_id_that_reached_a_real_repository_is_caught` is the regression for that
incident specifically.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from perfgen.emit import emit
from perfgen.publish.secrets_scan import (
    looks_like_credential_field,
    looks_like_credential_value,
    scan_files,
)

# The value that actually reached a public repository, kept verbatim as the regression case.
LEAKED_CLIENT_ID = "wr4vhwv9u8xwbcuz0x694fmbbgrt03"


def jmx_with_headers(path: Path, headers: dict[str, str]) -> Path:
    """A minimal test plan carrying a HeaderManager, which is all this scan reads."""
    entries = "".join(
        f'<elementProp name="{name}" elementType="Header">'
        f'<stringProp name="Header.name">{name}</stringProp>'
        f'<stringProp name="Header.value">{value}</stringProp>'
        f"</elementProp>"
        for name, value in headers.items()
    )
    path.write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree>'
        f'<HeaderManager guiclass="HeaderPanel" testclass="HeaderManager" testname="H">'
        f'<collectionProp name="HeaderManager.headers">{entries}</collectionProp>'
        f"</HeaderManager><hashTree/></hashTree></jmeterTestPlan>",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("PERF_CLIENT_ID", "id-value-not-a-secret")
    monkeypatch.setenv("PERF_CLIENT_SECRET", "sup3rsecretvalue-abcdef123456")
    for leftover in ("GRANT_TYPE", "CLIENT_ID", "CLIENT_SECRET"):
        monkeypatch.delenv(leftover, raising=False)


# ------------------------------------------------------------------------------------------
# The incident


def test_the_literal_client_id_that_reached_a_real_repository_is_caught(
    tmp_path, auth_shared_token
):
    jmx = jmx_with_headers(tmp_path / "app.jmx", {"Client-Id": LEAKED_CLIENT_ID})
    report = scan_files([jmx], auth_shared_token)

    assert not report.ok
    assert any("Client-Id" in e for e in report.errors)
    assert any("allow_literal_headers" in e for e in report.errors)


def test_the_incident_value_is_caught_even_under_a_harmless_field_name(
    tmp_path, auth_shared_token
):
    """The name check alone is not enough - a credential can be called anything."""
    jmx = jmx_with_headers(tmp_path / "app.jmx", {"X-Tenant": LEAKED_CLIENT_ID})
    report = scan_files([jmx], auth_shared_token)

    assert not report.ok
    assert any("shaped like a generated credential" in e for e in report.errors)


def test_an_allowlisted_header_publishes(tmp_path, auth_shared_token):
    jmx = jmx_with_headers(tmp_path / "app.jmx", {"Client-Id": LEAKED_CLIENT_ID})
    report = scan_files([jmx], auth_shared_token, allow_literal_headers=["Client-Id"])

    assert report.ok


def test_the_allowlist_is_per_header_not_a_blanket_switch(tmp_path, auth_shared_token):
    jmx = jmx_with_headers(
        tmp_path / "app.jmx", {"Client-Id": LEAKED_CLIENT_ID, "X-Other": LEAKED_CLIENT_ID}
    )
    report = scan_files([jmx], auth_shared_token, allow_literal_headers=["Client-Id"])

    assert not report.ok
    assert any("X-Other" in e for e in report.errors)
    assert not any("'Client-Id'" in e for e in report.errors)


# ------------------------------------------------------------------------------------------
# Layer 1: by value


def test_a_resolved_secret_value_in_a_properties_file_is_caught(
    tmp_path, auth_shared_token, credentials
):
    properties = tmp_path / "baseline.properties"
    properties.write_text("users_F01=3\ntoken=sup3rsecretvalue-abcdef123456\n", encoding="utf-8")

    report = scan_files([properties], auth_shared_token)

    assert not report.ok
    assert any("value of a declared credential" in e for e in report.errors)
    # The value itself must not be echoed back into the error.
    assert not any("sup3rsecretvalue" in e for e in report.errors)


def test_credentials_that_cannot_be_resolved_are_named_rather_than_passed_over(
    tmp_path, auth_shared_token, monkeypatch
):
    """The exact hole that let the incident through while the scan reported clean."""
    declared = ("PERF_CLIENT_ID", "PERF_CLIENT_SECRET", "GRANT_TYPE", "CLIENT_ID", "CLIENT_SECRET")
    for name in declared:
        monkeypatch.delenv(name, raising=False)
    clean = tmp_path / "sla_criteria.yaml"
    clean.write_text("application: order_management\n", encoding="utf-8")

    report = scan_files([clean], auth_shared_token)

    assert report.ok, "unresolvable references are a warning, not a refusal"
    assert report.warnings
    assert "perf-client-id -> PERF_CLIENT_ID" in report.warnings[0]
    assert "could not be checked by value" in report.warnings[0]


# ------------------------------------------------------------------------------------------
# Layer 2: generic patterns


@pytest.mark.parametrize(
    "value",
    [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz",
        "AKIAIOSFODNN7EXAMPLE",
    ],
)
def test_recognisable_credential_formats_are_caught_anywhere_in_a_file(
    tmp_path, auth_shared_token, value
):
    sla = tmp_path / "sla_criteria.yaml"
    sla.write_text(f"application: x\nnote: {value}\n", encoding="utf-8")

    assert not scan_files([sla], auth_shared_token).ok


# ------------------------------------------------------------------------------------------
# Not false positives


def test_real_emitter_output_passes_untouched(tmp_path, auth_shared_token, credentials):
    result = emit(auth_shared_token, tmp_path / "out", "5.6.3")
    files = [result.jmx_path, *result.property_files]
    if result.sla_path:
        files.append(result.sla_path)

    report = scan_files(files, auth_shared_token)

    assert report.ok, str(report)


def test_a_groovy_environment_lookup_is_not_a_leak(tmp_path, auth_shared_token):
    """The emitted script is full of these by design; flagging them would make the scan useless."""
    jmx = jmx_with_headers(
        tmp_path / "app.jmx",
        {"Authorization": "Bearer ${__groovy(System.getenv('PERF_CLIENT_SECRET'))}"},
    )
    assert scan_files([jmx], auth_shared_token).ok


@pytest.mark.parametrize(
    "name,value",
    [
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Accept", "application/json"),
        ("User-Agent", "perfgen/0.1.0"),
        ("X-Correlation-Mode", "strict"),
    ],
)
def test_ordinary_headers_do_not_fire(tmp_path, auth_shared_token, name, value):
    jmx = jmx_with_headers(tmp_path / "app.jmx", {name: value})
    assert scan_files([jmx], auth_shared_token).ok, f"{name}: {value} should not fire"


def test_property_files_of_load_parameters_do_not_fire(tmp_path, auth_shared_token):
    properties = tmp_path / "baseline.properties"
    properties.write_text(
        "# baseline profile\nrampup_s=5\nduration_s=60\nusers_F01=2\ntput_F01=120.0\n",
        encoding="utf-8",
    )
    assert scan_files([properties], auth_shared_token).ok


# ------------------------------------------------------------------------------------------
# The predicates


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Client-Id", True),
        ("clientId", True),
        ("X-Signature", True),
        ("X-Key", True),
        ("Authorization", True),
        ("X-Api-Key", True),
        ("client_secret", True),
        ("Content-Type", False),
        ("Accept", False),
        ("User-Agent", False),
    ],
)
def test_credential_field_names(name, expected):
    assert looks_like_credential_field(name) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (LEAKED_CLIENT_ID, True),
        ("ghp_abcdefghijklmnopqrstuvwxyz01", True),
        ("application/x-www-form-urlencoded", False),  # has a slash
        ("perfgen/0.1.0", False),
        ("5.6.3", False),
        ("strict", False),  # too short
        ("${__P(authToken)}", False),
        ("Bearer ${__P(authToken)}", False),
    ],
)
def test_credential_value_shapes(value, expected):
    assert looks_like_credential_value(value) is expected

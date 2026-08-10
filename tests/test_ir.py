"""IR models and YAML round-trip.

The IR is the review surface, so it fails loudly rather than absorbing mistakes: an unknown key is
a typo, and a hand-edited derived value that disagrees with the data is a contradiction worth
stopping on.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from perfgen.ir.io import ir_to_yaml, load_ir
from perfgen.ir.models import (
    Application,
    Auth,
    AuthType,
    TestPlanIR,
    ThroughputUnit,
)


def test_round_trip_is_lossless(auth_shared_token):
    reloaded = TestPlanIR.model_validate(auth_shared_token.model_dump(mode="json"))
    assert reloaded == auth_shared_token


def test_yaml_round_trip_via_disk(tmp_path, auth_shared_token):
    path = tmp_path / "ir.yaml"
    path.write_text(ir_to_yaml(auth_shared_token), encoding="utf-8")
    assert load_ir(path) == auth_shared_token


def test_yaml_uses_block_scalars_for_multiline_strings(auth_shared_token):
    """Evidence strings are prose; a re-wrapped blob makes review diffs unreadable."""
    auth_shared_token.flows[0].steps[0].extracts[0].evidence = "line one\nline two"
    assert "|-\n" in ir_to_yaml(auth_shared_token) or "|\n" in ir_to_yaml(auth_shared_token)


def test_unknown_field_is_rejected():
    """extra='forbid': a typo in hand-edited YAML must not be silently dropped."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Application(name="x", base_url="https://x.example", base_pth="/typo")


def test_trailing_slash_on_base_url_is_rejected():
    with pytest.raises(ValidationError, match="trailing slash"):
        Application(name="x", base_url="https://x.example/")


def test_api_reference_is_stored_and_defaults_to_null():
    assert Application(name="x", base_url="https://x.example").api_reference is None
    app = Application(
        name="x", base_url="https://x.example", api_reference="https://x.example/swagger.json"
    )
    assert app.api_reference == "https://x.example/swagger.json"


def test_auth_none_needs_no_header_fields():
    assert Auth(type=AuthType.NONE).header_name is None


def test_authenticated_spec_requires_header_fields():
    with pytest.raises(ValidationError, match="header_name"):
        Auth(type=AuthType.BEARER_STATIC)


def test_oauth_requires_a_token_request():
    with pytest.raises(ValidationError, match="token_request"):
        Auth(
            type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            header_name="Authorization",
            value_format="Bearer {token}",
        )


def test_static_auth_needs_no_token_request():
    auth = Auth(
        type=AuthType.API_KEY, header_name="X-API-Key", value_format="{token}"
    )
    assert auth.token_request is None


def test_refresh_required_is_derived(auth_shared_token):
    assert auth_shared_token.auth.refresh_required is False  # 1800s < 3600s lifetime

    data = auth_shared_token.model_dump(mode="json")
    data["load_profiles"][0]["duration_s"] = 7200
    data["auth"]["refresh_required"] = None
    assert TestPlanIR.model_validate(data).auth.refresh_required is True


def test_disagreeing_refresh_required_is_rejected(auth_shared_token):
    """A stale hand-edit must not silently suppress the expiry warning."""
    data = auth_shared_token.model_dump(mode="json")
    data["auth"]["refresh_required"] = True  # actually False for these durations
    with pytest.raises(ValidationError, match="Omit the field to have it derived"):
        TestPlanIR.model_validate(data)


def test_disabled_profile_needs_no_duration(simple_flow):
    assert all(p.duration_s is None for p in simple_flow.load_profiles if not p.enabled)


def test_duplicate_flow_ids_are_rejected(simple_flow):
    data = simple_flow.model_dump(mode="json")
    data["flows"].append(data["flows"][0])
    with pytest.raises(ValidationError, match="duplicate flow id"):
        TestPlanIR.model_validate(data)


def test_out_of_order_steps_are_rejected(simple_flow):
    data = simple_flow.model_dump(mode="json")
    data["flows"][0]["steps"][0]["index"] = 9
    with pytest.raises(ValidationError, match="ascending index order"):
        TestPlanIR.model_validate(data)


@pytest.mark.parametrize(
    ("unit", "value", "expected_per_minute"),
    [
        (ThroughputUnit.TPS, 2, 120),
        (ThroughputUnit.TPM, 30, 30),
        (ThroughputUnit.TPH, 1200, 20),
    ],
)
def test_throughput_converts_to_samples_per_minute(unit, value, expected_per_minute):
    assert unit.to_per_minute(value) == pytest.approx(expected_per_minute)


def test_probe_provenance_records_skips_and_degradation(auth_shared_token):
    assert auth_shared_token.provenance.probe.skipped_flows == ["F02"]
    assert auth_shared_token.provenance.probe.degraded is False


def test_extracts_carry_confidence_and_evidence(auth_shared_token):
    extract = auth_shared_token.flows[0].steps[0].extracts[0]
    assert extract.confidence
    assert extract.evidence.strip()


def test_no_secret_values_in_the_ir(auth_shared_token):
    """The IR holds reference names only, never resolved secrets."""
    text = ir_to_yaml(auth_shared_token)
    assert "perf-client-id" in text  # the reference name is fine
    for forbidden in ("password", "secret_value", "Bearer ey"):
        assert forbidden not in text

"""Gap detection, including D3.

The rule that matters: the tool never invents a missing input value. A script that runs but
measures the wrong thing is worse than no script.
"""

from __future__ import annotations

from perfgen.ir.gaps import blocking, detect_gaps, format_gaps
from perfgen.ir.models import LoadProfile, ProfileId, Severity, Throughput, ThroughputUnit


def _profile_gap(ir, field_suffix):
    return next((g for g in detect_gaps(ir) if g.field.endswith(field_suffix)), None)


def test_no_gaps_on_a_complete_spec(simple_flow):
    assert detect_gaps(simple_flow) == []


def test_throughput_without_users_is_blocking(simple_flow):
    """D3: throughput alone cannot size a thread group, and a thread count is never invented."""
    profile = simple_flow.load_profiles[0]
    profile.users = None
    profile.throughput = Throughput(value=1200, unit=ThroughputUnit.TPH)

    gap = _profile_gap(simple_flow, "baseline.users")
    assert gap is not None
    assert gap.severity is Severity.BLOCKING
    assert "throughput alone cannot size a thread group" in gap.message


def test_neither_users_nor_throughput_is_blocking(simple_flow):
    simple_flow.load_profiles[0].users = None
    gap = _profile_gap(simple_flow, "baseline.users")
    assert gap is not None
    assert gap.severity is Severity.BLOCKING


def test_blocking_gap_names_the_sheet_and_row(simple_flow):
    """The user has to know which cell to fill in, not just which field is missing."""
    simple_flow.load_profiles = [
        LoadProfile(id=ProfileId.CAPACITY, enabled=True, duration_s=600, ramp_up_s=60)
    ]
    gap = _profile_gap(simple_flow, "capacity.users")
    assert gap is not None
    assert "Load profiles, row 4 (Capacity / overload)" in gap.message
    assert "Concurrent users" in gap.message


def test_disabled_profile_with_no_values_is_not_a_gap(simple_flow):
    """Capacity is legitimately left blank when it is not required."""
    simple_flow.load_profiles.append(
        LoadProfile(id=ProfileId.CAPACITY, enabled=False)
    )
    assert not [g for g in detect_gaps(simple_flow) if "capacity" in g.field]


def test_missing_duration_on_an_enabled_profile_is_blocking(simple_flow):
    simple_flow.load_profiles[0].duration_s = None
    gap = _profile_gap(simple_flow, "baseline.duration_s")
    assert gap is not None
    assert gap.severity is Severity.BLOCKING


def test_missing_rampup_is_only_a_warning(simple_flow):
    simple_flow.load_profiles[0].ramp_up_s = None
    gap = _profile_gap(simple_flow, "baseline.ramp_up_s")
    assert gap is not None
    assert gap.severity is Severity.WARNING
    assert not blocking(detect_gaps(simple_flow))


def test_no_enabled_profile_is_blocking(simple_flow):
    for profile in simple_flow.load_profiles:
        profile.enabled = False
    gaps = blocking(detect_gaps(simple_flow))
    assert any(g.field == "load_profiles" for g in gaps)


def test_share_of_load_not_totalling_100_is_a_warning(auth_shared_token):
    auth_shared_token.flows[0].share_pct = 50
    gap = next(g for g in detect_gaps(auth_shared_token) if g.field == "flows.share_pct")
    assert gap.severity is Severity.WARNING
    assert "totals 90" in gap.message


def test_token_lifetime_shorter_than_a_test_warns_about_refresh(auth_shared_token):
    """Endurance-style runs outlive the token; the script has no refresh mechanism."""
    auth_shared_token.load_profiles[0].duration_s = 7200  # 2h against a 3600s lifetime
    auth_shared_token.auth.refresh_required = None
    revalidated = auth_shared_token.model_validate(auth_shared_token.model_dump())
    assert revalidated.auth.refresh_required is True

    gap = next(g for g in detect_gaps(revalidated) if g.field == "auth.refresh_required")
    assert gap.severity is Severity.WARNING


def test_missing_token_expression_is_blocking(auth_shared_token):
    """Until the probe finds it, the script cannot read a token out of the auth response."""
    auth_shared_token.auth.token_extract.expr = None
    gap = next(g for g in detect_gaps(auth_shared_token) if g.field == "auth.token_extract.expr")
    assert gap.severity is Severity.BLOCKING


def test_format_gaps_puts_blocking_first(simple_flow):
    simple_flow.load_profiles[0].users = None
    simple_flow.load_profiles[0].ramp_up_s = None
    text = format_gaps(detect_gaps(simple_flow))
    assert text.index("BLOCKING") < text.index("warning")


def test_format_gaps_when_empty():
    assert format_gaps([]) == "No gaps."

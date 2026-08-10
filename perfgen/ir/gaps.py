"""Gap detection over a built IR.

Gaps are collected, never raised — a missing input should produce a clear report of everything that
is missing, not an exception on the first one. Blocking gaps stop the run with a non-zero exit.
"""

from __future__ import annotations

from perfgen.ir.models import Gap, ProfileId, Severity, TestPlanIR

# The sheet row each profile occupies in the workbook, so a gap message can name the cell to fill
# in rather than an abstract field path.
_PROFILE_ROW: dict[ProfileId, tuple[int, str]] = {
    ProfileId.BASELINE: (2, "Baseline"),
    ProfileId.PEAK: (3, "Peak load"),
    ProfileId.CAPACITY: (4, "Capacity / overload"),
    ProfileId.ENDURANCE: (5, "Endurance"),
}


def detect_gaps(ir: TestPlanIR, *, pre_probe: bool = False) -> list[Gap]:
    """Return gaps implied by the IR's own contents.

    These are structural gaps the emitter cares about. The workbook parser adds its own for labels
    it could not find, and both end up in the same `gaps` list.

    `pre_probe` marks the stage: straight after parsing, a token extractor with no expression is
    expected - the probe determines it next - so it is a note rather than a blocker. By emit time
    the same hole means the script cannot read a token at all.
    """
    gaps: list[Gap] = []
    gaps.extend(_load_profile_gaps(ir))
    gaps.extend(_flow_gaps(ir))
    gaps.extend(_auth_gaps(ir, pre_probe=pre_probe))
    return gaps


def _load_profile_gaps(ir: TestPlanIR) -> list[Gap]:
    gaps: list[Gap] = []
    for profile in ir.load_profiles:
        if not profile.enabled:
            continue
        row, label = _PROFILE_ROW[profile.id]
        if profile.users is None:
            # D3: blocking even when a throughput target is present. JMeter cannot build a thread
            # group without a thread count, and a Constant Throughput Timer only paces threads that
            # already exist — deriving one from throughput would be inventing a value.
            detail = (
                "a throughput target is set, but throughput alone cannot size a thread group"
                if profile.throughput is not None
                else "neither concurrent users nor a throughput target is set"
            )
            gaps.append(
                Gap(
                    field=f"load_profiles.{profile.id}.users",
                    severity=Severity.BLOCKING,
                    message=(
                        f"Load profiles, row {row} ({label}): 'Concurrent users' is empty and "
                        f"{detail}. Fill it in - the framework will not choose a number for you."
                    ),
                )
            )
        if profile.duration_s is None:
            gaps.append(
                Gap(
                    field=f"load_profiles.{profile.id}.duration_s",
                    severity=Severity.BLOCKING,
                    message=(
                        f"Load profiles, row {row} ({label}): 'Duration (min)' is empty. "
                        "An enabled profile needs a duration."
                    ),
                )
            )
        if profile.ramp_up_s is None:
            gaps.append(
                Gap(
                    field=f"load_profiles.{profile.id}.ramp_up_s",
                    severity=Severity.WARNING,
                    message=(
                        f"Load profiles, row {row} ({label}): 'Ramp-up (s)' is empty. "
                        "All threads will start at once."
                    ),
                )
            )
    if not ir.enabled_profiles:
        gaps.append(
            Gap(
                field="load_profiles",
                severity=Severity.BLOCKING,
                message=(
                    "No load profile is marked Required on the 'Load profiles' sheet. "
                    "At least one is needed to generate a script."
                ),
            )
        )
    return gaps


def _flow_gaps(ir: TestPlanIR) -> list[Gap]:
    gaps: list[Gap] = []
    if not ir.flows:
        gaps.append(
            Gap(
                field="flows",
                severity=Severity.BLOCKING,
                message="The 'Flows' sheet has no rows. At least one flow is needed.",
            )
        )
        return gaps

    total = sum(f.share_pct for f in ir.flows)
    if total != 100:
        gaps.append(
            Gap(
                field="flows.share_pct",
                severity=Severity.WARNING,
                message=(
                    f"'Share of load %' totals {total}, not 100, across "
                    f"{len(ir.flows)} flow(s). Thread counts are apportioned from the total as "
                    "given, so the split will not match what was intended."
                ),
            )
        )
    return gaps


def _auth_gaps(ir: TestPlanIR, *, pre_probe: bool = False) -> list[Gap]:
    gaps: list[Gap] = []
    if ir.auth.refresh_required:
        gaps.append(
            Gap(
                field="auth.refresh_required",
                severity=Severity.WARNING,
                message=(
                    f"A test runs longer than the token lifetime of "
                    f"{ir.auth.lifetime_seconds}s. The generated script does not refresh the "
                    "token and will start failing mid-run when it expires."
                ),
            )
        )
    if ir.auth.token_extract is not None and ir.auth.token_extract.expr is None:
        gaps.append(
            Gap(
                field="auth.token_extract.expr",
                severity=Severity.WARNING if pre_probe else Severity.BLOCKING,
                message=(
                    "The token extractor has no expression yet. The probe determines it by "
                    "calling the token endpoint and looking at the response."
                    if pre_probe
                    else "The token extractor has no expression, so the generated script cannot "
                    "read a token out of the auth response. Run the probe first."
                ),
            )
        )
    return gaps


def blocking(gaps: list[Gap]) -> list[Gap]:
    return [g for g in gaps if g.severity is Severity.BLOCKING]


def format_gaps(gaps: list[Gap]) -> str:
    """Render gaps for the terminal, blocking first."""
    if not gaps:
        return "No gaps."
    ordered = sorted(gaps, key=lambda g: (g.severity is not Severity.BLOCKING, g.field))
    lines = []
    for gap in ordered:
        marker = "BLOCKING" if gap.severity is Severity.BLOCKING else "warning "
        lines.append(f"  [{marker}] {gap.field}\n             {gap.message}")
    return "\n".join(lines)

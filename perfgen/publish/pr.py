"""Opening - or updating - the pull request that carries a published script.

A direct call to the GitHub REST API with `httpx`, which is already a dependency. No `gh` CLI: it
is not guaranteed present on this machine and less so in the environment this is headed for.

The body's most important job is the same as the run summary's: make what was *guessed* impossible
to skim past. It is repurposed from the same data (`perfgen.summary.collect_flagged`), not from the
rendered terminal banner, which is 78-column ASCII and would read as noise in markdown.

The review section always renders. A blank space where it would have been reads as "nothing was
checked", which is the more dangerous of the two possible misreadings - so a fully verified script
says so explicitly, and a script with no correlations at all says *that*, because "nothing to
verify" is not a clean bill of health.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from perfgen.emit.emitter import plan_profile
from perfgen.ir.models import TestPlanIR
from perfgen.summary import collect_flagged, count_correlations

GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"


class PublishApiError(RuntimeError):
    """The GitHub API refused a request. Carries its own message, never the token."""


@dataclass
class PullRequest:
    number: int
    url: str
    created: bool


# --------------------------------------------------------------------------------------------
# The API
# --------------------------------------------------------------------------------------------


def _detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip()[:400]
    message = payload.get("message", "") if isinstance(payload, dict) else ""
    errors = payload.get("errors", []) if isinstance(payload, dict) else []
    parts = [message] if message else []
    for error in errors if isinstance(errors, list) else []:
        if isinstance(error, dict):
            text = error.get("message") or f"{error.get('field', '')} {error.get('code', '')}"
            if text.strip():
                parts.append(text.strip())
    return "; ".join(parts) or response.text.strip()[:400]


def _check(response: httpx.Response, action: str, base_branch: str = "") -> dict:
    if response.status_code < 400:
        return response.json()

    detail = _detail(response)
    hint = ""
    if response.status_code == 422 and "base" in detail.lower():
        hint = (
            f"\nThe pipeline repository may have no {base_branch!r} branch to merge into. A "
            f"repository with no commits has no branches at all - give it an initial commit on "
            f"{base_branch!r}, or point publish.base_branch at one that exists."
        )
    elif response.status_code in (401, 403):
        hint = (
            "\nThe token was rejected. It needs write access to this repository, and for a "
            "fine-grained token that means Contents: read and write plus Pull requests: read and "
            "write."
        )
    raise PublishApiError(f"{action} failed ({response.status_code}): {detail}{hint}")


def _client(token: str, base_url: str, transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
        },
        transport=transport,
        timeout=30.0,
    )


def open_or_update_pr(
    *,
    owner: str,
    repo: str,
    branch: str,
    base_branch: str,
    title: str,
    body: str,
    token: str,
    base_url: str = GITHUB_API,
    transport: httpx.BaseTransport | None = None,
) -> PullRequest:
    """Open a PR for `branch`, or update the one that is already open for it.

    Republishing an application must not leave a second PR behind, so an existing open PR for the
    same head branch is updated in place - it already has the new commits from the force-push, and
    only the body needs refreshing.
    """
    with _client(token, base_url, transport) as client:
        existing = client.get(
            f"/repos/{owner}/{repo}/pulls",
            params={"head": f"{owner}:{branch}", "state": "open"},
        )
        open_prs = _check(existing, "Looking up existing pull requests")

        if open_prs:
            number = open_prs[0]["number"]
            updated = client.patch(
                f"/repos/{owner}/{repo}/pulls/{number}", json={"title": title, "body": body}
            )
            data = _check(updated, f"Updating pull request #{number}", base_branch)
            return PullRequest(number=data["number"], url=data["html_url"], created=False)

        created = client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={"title": title, "head": branch, "base": base_branch, "body": body},
        )
        data = _check(created, "Opening a pull request", base_branch)
        return PullRequest(number=data["number"], url=data["html_url"], created=True)


# --------------------------------------------------------------------------------------------
# The body
# --------------------------------------------------------------------------------------------


def pr_title(ir: TestPlanIR) -> str:
    return f"perfgen: {ir.application.name} performance script"


def _review_section(ir: TestPlanIR) -> list[str]:
    """Always rendered, in one of three states, because they mean different things."""
    flagged = collect_flagged(ir)
    total = count_correlations(ir)
    lines = ["## Review status", ""]

    if flagged:
        lines.append(f"**{len(flagged)} of {total} correlation(s) in this script are guesses.**")
        lines.append("")
        lines.append(
            "These were not confirmed against observed traffic. A wrong extractor does not crash "
            "the test - it runs, passes, and measures nothing. Check each one before trusting any "
            "number this script produces."
        )
        lines.append("")
        for item in flagged:
            lines.append(
                f"- **`{item.var}`** &mdash; {item.flow_id} step {item.step_index}, "
                f"{item.step_name} (confidence: {item.confidence})"
            )
            for segment in item.evidence.splitlines():
                lines.append(f"  > {segment}" if segment.strip() else "  >")
            lines.append("")
    elif total:
        lines.append(
            f"**0 of {total} correlation(s) need review.** All {total} were verified against "
            f"traffic observed during the probe."
        )
    else:
        lines.append(
            "**This script has no correlations.** There was nothing to verify - which is not the "
            "same as everything having passed."
        )

    if ir.provenance.probe.degraded:
        lines.append("")
        lines.append(
            "> **The probe did not run.** Nothing in this script was verified against the real "
            "service; every correlation is inferred from names in the specification."
        )
    return lines


def _profile_section(ir: TestPlanIR) -> list[str]:
    profiles = ir.enabled_profiles
    if not profiles:
        return ["## Load profiles", "", "No load profile is enabled."]

    lines = ["## Load profiles", ""]
    for profile in profiles:
        parts = []
        if profile.users is not None:
            parts.append(f"{profile.users} users")
        if profile.ramp_up_s is not None:
            parts.append(f"{profile.ramp_up_s}s ramp-up")
        if profile.duration_s is not None:
            parts.append(f"{profile.duration_s}s duration")
        if profile.throughput is not None:
            parts.append(
                f"{profile.throughput.value:g} {profile.throughput.unit.value} "
                f"({profile.throughput.per_minute():g}/min)"
            )
        lines.append(f"**{profile.id.value}** &mdash; {', '.join(parts) or 'no parameters set'}")
        lines.append("")

        if ir.flows:
            plan = plan_profile(profile, ir.flows)
            for flow in ir.flows:
                users = plan.users_by_flow.get(flow.id, 0)
                detail = f"{users} user(s)"
                if flow.id in plan.tput_per_minute_by_flow:
                    detail += f", {plan.tput_per_minute_by_flow[flow.id]:g}/min"
                lines.append(f"- `{flow.id}` {flow.name} &mdash; {flow.share_pct}%: {detail}")
            lines.append("")
    return lines


def render_pr_body(
    ir: TestPlanIR,
    *,
    files: list[str],
    perfgen_commit: str | None = None,
    spec_commit: str | None = None,
    skipped: list[str] | None = None,
) -> str:
    """The PR description a reviewer reads before approving."""
    probe = ir.provenance.probe
    facts = [
        ("Application", ir.application.name),
        ("Base URL", f"`{ir.application.base_url}`"),
        ("Source specification", f"`{ir.provenance.source_workbook}`"),
        ("Generated", ir.provenance.generated_at),
        ("Probe", f"performed, {probe.steps_observed} step(s) observed" if probe.performed
         else "not performed"),
    ]
    if perfgen_commit:
        facts.append(("perfgen commit", f"`{perfgen_commit}`"))
    if spec_commit:
        facts.append(("Specification commit", f"`{spec_commit}`"))

    lines = [f"# {ir.application.name}", ""]
    lines.append("| | |")
    lines.append("|---|---|")
    for label, value in facts:
        lines.append(f"| {label} | {value} |")
    lines.append("")

    lines.extend(_review_section(ir))
    lines.append("")
    lines.extend(_profile_section(ir))

    lines.append("## Files")
    lines.append("")
    for path in files:
        lines.append(f"- `{path}`")
    if skipped:
        lines.append("")
        lines.append(
            f"Not published (local run artifacts): {', '.join(f'`{s}`' for s in skipped)}"
        )
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Generated by `perfgen`, then reviewed and run locally by the publishing engineer before "
        "this pull request was opened. perfgen does not execute the script and has no opinion on "
        "whether it is a good test; before pushing it confirmed only that the `.jmx` parses and "
        "that no `${var}` reference dangles."
    )
    return "\n".join(lines)


def source_commits(
    workbook: str | Path | None, repo_root: Path | None = None
) -> tuple[str | None, str | None]:
    """perfgen's own HEAD and the last commit touching the source spec, when available.

    Both are best-effort context for a reviewer. A working copy with no git history, or a spec that
    is untracked, is an ordinary situation and simply omits the row.
    """
    from perfgen.publish.git_ops import git_output

    root = repo_root or Path(__file__).resolve().parents[2]
    head = git_output(["rev-parse", "--short", "HEAD"], cwd=root)
    spec = None
    if workbook:
        spec = git_output(
            ["log", "-1", "--format=%h", "--", str(workbook)], cwd=root
        )
    return head, spec

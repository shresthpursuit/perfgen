"""Getting the validated files onto a branch of the pipeline repository.

Plain `git` through `subprocess`, not a Python git library and not the `gh` CLI. A library would
add a dependency to wrap the same binary, and `gh` is not guaranteed present here or in the
stricter environment this is headed for. Shelling out also gives exact control over how the token
reaches git, which matters more than convenience: see `_CREDENTIAL_HELPER`.

The branch is deterministic per application (`perfgen/<slug>`) and always cut fresh from the base
branch, then force-pushed. A republish therefore *replaces* what was there rather than stacking on
top of a stale copy, and the open PR for that branch simply picks up the new commit. Publishing the
same application twice must never leave two PRs behind.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from perfgen.probe.redact import Redactor

_TOKEN_ENV = "PERFGEN_GIT_TOKEN"

# The token is handed to git through the child process environment and read back by this helper.
# The two alternatives both write it somewhere it must never be: embedding it in the remote URL
# puts it in .git/config on disk, and passing it as an argument puts it in the process list. The
# empty `credential.helper=` that precedes this one clears any system helper - on Windows, the
# Credential Manager would otherwise answer first and never consult ours.
_CREDENTIAL_HELPER = (
    '!f() { echo "username=x-access-token"; echo "password=$PERFGEN_GIT_TOKEN"; }; f'
)


class GitError(RuntimeError):
    """A git command failed. The message carries git's own stderr, with the token scrubbed."""


@dataclass
class PushResult:
    branch: str
    files: list[str] = field(default_factory=list)
    committed: bool = True
    commit_sha: str = ""
    skipped: list[str] = field(default_factory=list)
    matches_base: bool = False
    """The branch content is already identical to the base branch.

    True means a previous publish was merged and nothing has changed since - so there is nothing
    to open a pull request about. GitHub refuses that create with `422 No commits between ...`,
    which is a correct answer to a question worth not asking.
    """


def _clear_readonly(path: Path) -> None:
    """Drop the read-only attribute from a tree, deepest first.

    OneDrive's Files On-Demand turns synced folders into cloud placeholders and marks them
    read-only, and `os.rmdir` on a read-only directory is refused outright - `PermissionError:
    [WinError 5]`, raised after the contents have already gone, which reads confusingly like a
    lock. A real publish hit exactly this: the checkout sat inside a synced folder. Retrying
    cannot help, because nothing about it is transient.
    """
    for target in sorted(path.rglob("*"), reverse=True) + [path]:
        # Best effort. If one really is undeletable, rmtree reports it properly below.
        with contextlib.suppress(OSError):
            os.chmod(target, stat.S_IWRITE)


def remove_tree(path: Path, attempts: int = 5, delay_s: float = 0.2) -> None:
    """`shutil.rmtree`, hardened for Windows, where two different things go wrong.

    The read-only attribute is permanent and handled by clearing it first (see `_clear_readonly`).
    A sharing violation is transient - a search indexer or antivirus scanner holding a file opened
    moments ago - and is handled by retrying. Failing a whole publish over a lock that clears
    itself in 200ms would be the wrong trade; one that never clears still raises.
    """
    for attempt in range(attempts):
        try:
            _clear_readonly(path)
            shutil.rmtree(path)
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay_s * (attempt + 1))


def branch_name(app_slug: str) -> str:
    return f"perfgen/{app_slug}"


def github_remote_url(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}.git"


# --------------------------------------------------------------------------------------------
# Running git
# --------------------------------------------------------------------------------------------


def _run_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    token: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """One place every git invocation goes through, so the token handling is not repeated."""
    env = dict(os.environ)
    # A missing or rejected credential must fail, not block the run waiting on a prompt nobody is
    # watching - this may run unattended.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"

    command = ["git"]
    if token is not None:
        env[_TOKEN_ENV] = token
        command += ["-c", "credential.helper=", "-c", f"credential.helper={_CREDENTIAL_HELPER}"]
    command += args

    proc = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if check and proc.returncode != 0:
        redactor = Redactor([token] if token else [])
        detail = (redactor.scrub(proc.stderr) or "").strip() or (
            redactor.scrub(proc.stdout) or ""
        ).strip()
        raise GitError(f"git {' '.join(args)} failed ({proc.returncode}):\n{detail}")
    return proc


def git_output(args: list[str], *, cwd: Path | None = None) -> str | None:
    """Run a read-only git command, returning None rather than raising when it fails.

    For provenance lookups, where "this is not a git repository" is an ordinary answer.
    """
    try:
        proc = _run_git(args, cwd=cwd, check=False)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


# --------------------------------------------------------------------------------------------
# The checkout
# --------------------------------------------------------------------------------------------


def _is_repo_for(path: Path, remote_url: str) -> bool:
    if not (path / ".git").exists():
        return False
    current = git_output(["remote", "get-url", "origin"], cwd=path)
    return current == remote_url


def _prepare_checkout(remote_url: str, checkout_path: Path, token: str | None) -> Path:
    """Clone the pipeline repo, or refresh the clone we already have.

    A full clone, deliberately: pushing from a shallow one is refused by some server
    configurations, and a partial clone needs a filter the local bare repos in the test suite do
    not serve. If a pipeline repo ever grows big enough for this to hurt, that is the moment to
    revisit it - not before.
    """
    checkout_path = Path(checkout_path)
    if checkout_path.exists() and not _is_repo_for(checkout_path, remote_url):
        # Points somewhere else, or is not a repo at all. It is ours and gitignored, so replacing
        # it is safe and beats guessing what a half-configured checkout meant.
        remove_tree(checkout_path)

    if not checkout_path.exists():
        checkout_path.parent.mkdir(parents=True, exist_ok=True)
        _run_git(["clone", remote_url, str(checkout_path)], token=token)
    else:
        _run_git(["fetch", "origin"], cwd=checkout_path, token=token)
    return checkout_path


def _checkout_branch(repo: Path, branch: str, base_branch: str) -> None:
    base_ref = f"origin/{base_branch}"
    base_exists = (
        _run_git(["rev-parse", "--verify", "--quiet", base_ref], cwd=repo, check=False).returncode
        == 0
    )

    if not base_exists:
        # Refused rather than worked around. A branch could be started from nothing here, but a
        # pull request needs a base to merge into - so that push would land a branch nobody can
        # open a PR for, and the failure would surface later and further from its cause. A
        # repository with no commits has no branches at all, which is the usual reason to be here.
        raise GitError(
            f"The pipeline repository has no {base_branch!r} branch.\n"
            f"A repository with no commits has no branches at all, and a pull request needs a "
            f"base to merge into. Give it an initial commit on {base_branch!r} - GitHub's "
            f"'Add a README' button is enough - or point publish.base_branch at a branch that "
            f"exists.\n"
            f"Nothing was pushed."
        )

    _run_git(["checkout", "-B", branch, base_ref], cwd=repo)
    # Cut fresh every time: whatever a previous publish left on this branch is not history worth
    # building on, and the push is a force-push anyway.
    _run_git(["reset", "--hard", base_ref], cwd=repo)


# --------------------------------------------------------------------------------------------
# Publishing
# --------------------------------------------------------------------------------------------

# What lands in the pipeline repo. Selected by name rather than copying the folder wholesale
# because step 2 of the flow has the engineer running JMeter against this same directory, which
# leaves results.jtl and jmeter.log next to the script. Those are a local run's output, sometimes
# large, and never part of the deliverable.
PUBLISHED_SUFFIXES = (".jmx", ".properties")
PUBLISHED_NAMES = ("sla_criteria.yaml",)


def select_files(app_dir: Path) -> tuple[list[Path], list[Path]]:
    """Split an output folder into what gets published and what does not."""
    published: list[Path] = []
    skipped: list[Path] = []
    for entry in sorted(Path(app_dir).iterdir()):
        if not entry.is_file():
            skipped.append(entry)
        elif entry.suffix in PUBLISHED_SUFFIXES or entry.name in PUBLISHED_NAMES:
            published.append(entry)
        else:
            skipped.append(entry)
    return published, skipped


def publish_files(
    *,
    files: list[Path],
    app_slug: str,
    remote_url: str,
    checkout_path: Path,
    target_path_prefix: str,
    base_branch: str,
    commit_message: str,
    committer_name: str,
    committer_email: str,
    token: str | None = None,
    skipped: list[Path] | None = None,
) -> PushResult:
    """Put `files` at `{target_path_prefix}/{app_slug}/` on `perfgen/{app_slug}` and push it."""
    branch = branch_name(app_slug)
    repo = _prepare_checkout(remote_url, Path(checkout_path), token)
    _checkout_branch(repo, branch, base_branch)

    relative = f"{target_path_prefix.strip('/')}/{app_slug}"
    destination = repo / relative
    if destination.exists():
        remove_tree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for source in files:
        shutil.copy2(source, destination / source.name)

    _run_git(["add", "-A", "--", relative], cwd=repo)

    # Whether this republish changes anything is decided against the *remote branch*, not against
    # the base. The branch is cut fresh from base every time, so "differs from base" is true on
    # every publish and would say nothing. Comparing the staged tree to what is already on
    # origin/<branch> answers the question that matters: would this push change the PR at all?
    staged_tree = _run_git(["write-tree"], cwd=repo).stdout.strip()
    remote_tree = git_output(["rev-parse", f"origin/{branch}^{{tree}}"], cwd=repo)
    base_tree = git_output(["rev-parse", f"origin/{base_branch}^{{tree}}"], cwd=repo)
    if remote_tree is not None and remote_tree == staged_tree:
        return PushResult(
            branch=branch,
            files=[f"{relative}/{f.name}" for f in files],
            committed=False,
            commit_sha=git_output(["rev-parse", f"origin/{branch}"], cwd=repo) or "",
            skipped=[f.name for f in (skipped or [])],
            matches_base=base_tree == staged_tree,
        )

    # mkstemp hands back an open descriptor; on Windows the file cannot be removed while it is
    # held, so close it before writing through the path.
    handle, name = tempfile.mkstemp(suffix=".txt", text=True)
    os.close(handle)
    message_file = Path(name)
    try:
        # -F, never -m. The house rule exists because inline quoting has produced a commit titled
        # `@x` here before; a message file has no quoting to get wrong.
        message_file.write_text(commit_message, encoding="utf-8")
        _run_git(
            [
                "-c",
                f"user.name={committer_name}",
                "-c",
                f"user.email={committer_email}",
                "commit",
                "--cleanup=whitespace",
                "-F",
                str(message_file),
            ],
            cwd=repo,
        )
    finally:
        message_file.unlink(missing_ok=True)

    _run_git(
        ["push", "--force", "origin", f"{branch}:refs/heads/{branch}"], cwd=repo, token=token
    )

    return PushResult(
        branch=branch,
        files=[f"{relative}/{f.name}" for f in files],
        committed=True,
        commit_sha=git_output(["rev-parse", "HEAD"], cwd=repo) or "",
        skipped=[f.name for f in (skipped or [])],
    )

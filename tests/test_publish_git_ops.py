"""Pushing to a pipeline repository, against a local bare repo standing in for GitHub.

No network. `git` treats a filesystem path as a remote like any other, so a bare repo in tmp_path
exercises clone, branch, commit and force-push for real - the parts worth testing here are the
branching and republish semantics, not HTTPS transport.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from perfgen.publish.git_ops import (
    GitError,
    branch_name,
    github_remote_url,
    publish_files,
    select_files,
)


def git(*args: str, cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.returncode == 0, f"git {' '.join(args)} failed:\n{proc.stderr}"
    return proc.stdout.strip()


@pytest.fixture
def bare_repo(tmp_path: Path) -> Path:
    """An empty bare repository - a GitHub repo created with no initial commit."""
    path = tmp_path / "pipeline.git"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(path)], check=True, capture_output=True
    )
    return path


@pytest.fixture
def seeded_repo(bare_repo: Path, tmp_path: Path) -> Path:
    """The same, with an initial commit on main - a repository that can receive a PR."""
    seed = tmp_path / "seed"
    git("clone", str(bare_repo), str(seed), cwd=tmp_path)
    (seed / "README.md").write_text("pipeline\n", encoding="utf-8")
    git("add", "README.md", cwd=seed)
    git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-m", "init", cwd=seed)
    git("push", "origin", "main", cwd=seed)
    return bare_repo


@pytest.fixture
def app_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "outputs" / "order_management"
    directory.mkdir(parents=True)
    (directory / "order_management.jmx").write_text("<jmeterTestPlan/>", encoding="utf-8")
    (directory / "baseline.properties").write_text("users_F01=3\n", encoding="utf-8")
    (directory / "sla_criteria.yaml").write_text(
        "application: order_management\n", encoding="utf-8"
    )
    return directory


def publish(app_dir: Path, remote: Path, tmp_path: Path, **overrides):
    files, skipped = select_files(app_dir)
    kwargs = dict(
        files=files,
        app_slug=app_dir.name,
        remote_url=str(remote),
        checkout_path=tmp_path / "checkout",
        target_path_prefix="tests/generated",
        base_branch="main",
        commit_message="Publish the order management performance script\n",
        committer_name="perfgen",
        committer_email="perfgen@users.noreply.github.com",
        skipped=skipped,
    )
    kwargs.update(overrides)
    return publish_files(**kwargs)


def files_on_branch(bare: Path, branch: str) -> list[str]:
    listing = git("ls-tree", "-r", "--name-only", branch, cwd=bare)
    return sorted(line for line in listing.splitlines() if line)


# ------------------------------------------------------------------------------------------


def test_publishing_creates_the_branch_at_the_configured_prefix(seeded_repo, app_dir, tmp_path):
    result = publish(app_dir, seeded_repo, tmp_path)

    assert result.branch == "perfgen/order_management"
    assert result.committed is True
    assert files_on_branch(seeded_repo, "perfgen/order_management") == [
        "README.md",
        "tests/generated/order_management/baseline.properties",
        "tests/generated/order_management/order_management.jmx",
        "tests/generated/order_management/sla_criteria.yaml",
    ]


def test_the_branch_name_is_deterministic_per_application():
    assert branch_name("order_management") == "perfgen/order_management"


def test_republishing_updates_the_same_branch_rather_than_adding_another(
    seeded_repo, app_dir, tmp_path
):
    publish(app_dir, seeded_repo, tmp_path)
    (app_dir / "order_management.jmx").write_text("<jmeterTestPlan version='2'/>", encoding="utf-8")
    second = publish(app_dir, seeded_repo, tmp_path)

    listing = git("branch", "--list", cwd=seeded_repo).splitlines()
    assert sorted(b.strip().lstrip("* ") for b in listing) == ["main", "perfgen/order_management"]

    blob = git(
        "show",
        "perfgen/order_management:tests/generated/order_management/order_management.jmx",
        cwd=seeded_repo,
    )
    assert "version='2'" in blob

    # Cut fresh from main every time, so the branch carries one commit rather than a growing
    # stack. A reviewer opening the PR sees the script, not its edit history.
    assert git("rev-list", "--count", "main..perfgen/order_management", cwd=seeded_repo) == "1"
    assert second.committed is True


def test_republishing_unchanged_files_makes_no_new_commit(seeded_repo, app_dir, tmp_path):
    """A republish that changes nothing must not churn the branch the PR is watching."""
    first = publish(app_dir, seeded_repo, tmp_path)
    second = publish(app_dir, seeded_repo, tmp_path)

    assert second.committed is False
    assert second.commit_sha == first.commit_sha
    # Still exactly the one commit the first publish put there.
    assert git("rev-list", "--count", "main..perfgen/order_management", cwd=seeded_repo) == "1"


def test_a_file_removed_since_the_last_publish_is_removed_from_the_branch(
    seeded_repo, app_dir, tmp_path
):
    publish(app_dir, seeded_repo, tmp_path)
    (app_dir / "sla_criteria.yaml").unlink()
    publish(app_dir, seeded_repo, tmp_path)

    assert (
        "tests/generated/order_management/sla_criteria.yaml"
        not in files_on_branch(seeded_repo, "perfgen/order_management")
    )


def test_a_repository_with_no_base_branch_is_refused_before_anything_is_pushed(
    bare_repo, app_dir, tmp_path
):
    """An empty repo cannot receive a PR, so pushing a branch to it would strand the work."""
    with pytest.raises(GitError) as exc:
        publish(app_dir, bare_repo, tmp_path)

    assert "'main'" in str(exc.value)
    assert "Nothing was pushed" in str(exc.value)
    assert git("branch", "--list", cwd=bare_repo) == ""


def test_a_stale_checkout_pointing_elsewhere_is_replaced(seeded_repo, app_dir, tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "leftover.txt").write_text("from another repo", encoding="utf-8")

    publish(app_dir, seeded_repo, tmp_path, checkout_path=checkout)

    assert not (checkout / "leftover.txt").exists()
    assert (checkout / ".git").exists()


# ------------------------------------------------------------------------------------------
# What gets published


def test_local_jmeter_run_artifacts_are_not_published(app_dir):
    """Step 2 has the engineer running JMeter in this folder. Its output is not the deliverable."""
    (app_dir / "results.jtl").write_text("timeStamp,elapsed\n", encoding="utf-8")
    (app_dir / "jmeter.log").write_text("INFO  o.a.j.JMeter: started\n", encoding="utf-8")

    published, skipped = select_files(app_dir)

    assert [f.name for f in published] == [
        "baseline.properties",
        "order_management.jmx",
        "sla_criteria.yaml",
    ]
    assert sorted(f.name for f in skipped) == ["jmeter.log", "results.jtl"]


def test_skipped_files_are_reported_back_rather_than_dropped_silently(
    seeded_repo, app_dir, tmp_path
):
    (app_dir / "results.jtl").write_text("timeStamp,elapsed\n", encoding="utf-8")
    result = publish(app_dir, seeded_repo, tmp_path)

    assert result.skipped == ["results.jtl"]
    assert "tests/generated/order_management/results.jtl" not in result.files


def test_every_published_path_is_under_the_application_folder(seeded_repo, app_dir, tmp_path):
    result = publish(app_dir, seeded_repo, tmp_path)
    assert all(p.startswith("tests/generated/order_management/") for p in result.files)


def test_the_remote_url_is_built_from_owner_and_repo():
    assert (
        github_remote_url("shresthpursuit", "approved-scripts")
        == "https://github.com/shresthpursuit/approved-scripts.git"
    )


def test_the_token_never_reaches_the_checkout_on_disk(seeded_repo, app_dir, tmp_path):
    """The hard constraint: a credential is never written to disk, including into .git/config."""
    token = "ghp_thisisatesttokenvalue0000000000000000"
    publish(app_dir, seeded_repo, tmp_path, token=token)

    checkout = tmp_path / "checkout"
    for path in checkout.rglob("*"):
        if path.is_file():
            assert token not in path.read_bytes().decode("utf-8", errors="replace"), path

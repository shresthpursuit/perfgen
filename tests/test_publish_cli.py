"""`perfgen publish` end to end, with git and the GitHub API stubbed out.

The load-bearing test is the one proving a dangling `${var}` is refused before any git command runs.
Step 2 of the publish flow explicitly invites hand-editing the `.jmx`, so the structural check is
the only thing standing between a typo'd variable name and a pipeline repo - and it has to stop the
command *before* a branch exists, not clean up after one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from perfgen.__main__ import main
from perfgen.config import PublishConfig
from perfgen.emit import emit
from perfgen.ir.io import dump_ir
from perfgen.publish.git_ops import PushResult
from perfgen.publish.pr import PullRequest


@pytest.fixture
def workspace(tmp_path, auth_shared_token):
    """An IR on disk plus the output folder a previous `perfgen run` would have left."""
    ir_dir = tmp_path / "ir"
    ir_dir.mkdir()
    dump_ir(auth_shared_token, ir_dir / "order_management.yaml")
    result = emit(auth_shared_token, tmp_path / "outputs", "5.6.3")

    config = tmp_path / "config.yaml"
    config.write_text(
        "publish:\n"
        '  pipeline_repo: "owner/pipeline"\n'
        '  target_path_prefix: "tests/generated"\n'
        '  base_branch: "main"\n'
        f"  checkout_path: {(tmp_path / 'checkout').as_posix()}\n"
        f"paths:\n  ir: {ir_dir.as_posix()}\n"
        f"  outputs: {(tmp_path / 'outputs').as_posix()}\n",
        encoding="utf-8",
    )
    return {
        "config": str(config),
        "app_dir": str(result.jmx_path.parent),
        "jmx": result.jmx_path,
        "ir_dir": ir_dir,
    }


@pytest.fixture
def stub_publish(monkeypatch):
    """Stand in for git and GitHub, recording whether they were reached at all."""
    calls = {"push": [], "pr": []}

    def fake_publish_files(**kwargs):
        calls["push"].append(kwargs)
        slug = kwargs["app_slug"]
        return PushResult(
            branch=f"perfgen/{slug}",
            files=[f"tests/generated/{slug}/{f.name}" for f in kwargs["files"]],
            committed=True,
            commit_sha="abc1234",
            skipped=[f.name for f in (kwargs.get("skipped") or [])],
        )

    def fake_open_or_update_pr(**kwargs):
        calls["pr"].append(kwargs)
        return PullRequest(number=11, url="https://github.com/owner/pipeline/pull/11", created=True)

    monkeypatch.setattr("perfgen.__main__.publish_files", fake_publish_files)
    monkeypatch.setattr("perfgen.__main__.open_or_update_pr", fake_open_or_update_pr)
    monkeypatch.setenv("PERFGEN_PUBLISH_TOKEN", "ghp_testtokenvalue000000000000000000000")
    return calls


# ------------------------------------------------------------------------------------------
# The gate


def test_a_dangling_variable_reference_is_refused_before_any_git_command(
    workspace, stub_publish, capsys
):
    jmx = workspace["jmx"]
    anchor = b'<stringProp name="Argument.value">'
    original = jmx.read_bytes()
    assert anchor in original, "fixture no longer has the element this test edits"
    jmx.write_bytes(original.replace(anchor, anchor + b"${neverProduced}", 1))

    exit_code = main(["--config", workspace["config"], "publish", workspace["app_dir"]])
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "neverProduced" in text
    assert "no branch was created" in text
    assert stub_publish["push"] == []
    assert stub_publish["pr"] == []


def test_a_malformed_jmx_is_refused_before_any_git_command(workspace, stub_publish, capsys):
    workspace["jmx"].write_text("<jmeterTestPlan><broken>", encoding="utf-8")

    exit_code = main(["--config", workspace["config"], "publish", workspace["app_dir"]])

    assert exit_code == 1
    assert stub_publish["push"] == []
    assert stub_publish["pr"] == []


def test_a_missing_ir_is_refused_and_names_the_path_it_looked_for(
    workspace, stub_publish, capsys
):
    (workspace["ir_dir"] / "order_management.yaml").unlink()

    exit_code = main(["--config", workspace["config"], "publish", workspace["app_dir"]])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "order_management.yaml" in err
    assert "--ir" in err
    assert stub_publish["push"] == []


def test_a_missing_output_folder_is_refused(tmp_path, workspace, stub_publish, capsys):
    exit_code = main(
        ["--config", workspace["config"], "publish", str(tmp_path / "outputs" / "nope")]
    )
    assert exit_code == 1
    assert stub_publish["push"] == []


def test_an_unset_token_is_refused_and_names_the_variable(
    workspace, stub_publish, monkeypatch, tmp_path, capsys
):
    # publish calls secrets.load_dotenv(), which reads `.env` from the working directory. On a
    # machine that has a real one - anybody who has actually published - that would put the token
    # straight back and this test would silently stop testing anything. Run somewhere without one.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PERFGEN_PUBLISH_TOKEN")

    exit_code = main(["--config", workspace["config"], "publish", workspace["app_dir"]])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "PERFGEN_PUBLISH_TOKEN" in err
    assert stub_publish["push"] == []


def test_an_unset_pipeline_repo_is_refused(workspace, stub_publish, tmp_path, capsys):
    config = tmp_path / "empty_repo.yaml"
    config.write_text(
        'publish:\n  pipeline_repo: ""\n'
        f"  checkout_path: {(tmp_path / 'checkout').as_posix()}\n"
        f"paths:\n  ir: {workspace['ir_dir'].as_posix()}\n",
        encoding="utf-8",
    )

    exit_code = main(["--config", str(config), "publish", workspace["app_dir"]])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "publish.pipeline_repo" in err
    assert stub_publish["push"] == []


def test_a_credential_shaped_literal_is_refused_before_any_git_command(
    workspace, stub_publish, capsys
):
    """The incident this scan exists for: a live Client-Id published as a literal header."""
    jmx = workspace["jmx"]
    original = jmx.read_bytes()
    anchor = b'<stringProp name="Header.name">Authorization</stringProp>'
    assert anchor in original
    injected = (
        b'<stringProp name="Header.name">Client-Id</stringProp>'
        b'<stringProp name="Header.value">wr4vhwv9u8xwbcuz0x694fmbbgrt03</stringProp>'
        b"</elementProp><elementProp name=\"Authorization\" elementType=\"Header\">" + anchor
    )
    jmx.write_bytes(original.replace(anchor, injected, 1))

    exit_code = main(["--config", workspace["config"], "publish", workspace["app_dir"]])
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "Client-Id" in text
    assert "no way to exempt it" in text
    assert stub_publish["push"] == []
    assert stub_publish["pr"] == []


def test_an_already_merged_branch_reports_cleanly_instead_of_failing(
    workspace, stub_publish, monkeypatch, capsys
):
    """GitHub answers a create here with 422. The command should not have asked."""
    from perfgen.publish.git_ops import PushResult

    def merged_push(**kwargs):
        stub_publish["push"].append(kwargs)
        return PushResult(
            branch=f"perfgen/{kwargs['app_slug']}",
            files=[f"tests/generated/{kwargs['app_slug']}/{f.name}" for f in kwargs["files"]],
            committed=False,
            commit_sha="abc1234",
            matches_base=True,
        )

    monkeypatch.setattr("perfgen.__main__.publish_files", merged_push)
    monkeypatch.setattr("perfgen.__main__.open_or_update_pr", lambda **kw: None)

    exit_code = main(["--config", workspace["config"], "publish", workspace["app_dir"]])
    text = capsys.readouterr().out

    assert exit_code == 0
    assert "already merged" in text
    assert "Nothing to publish" in text


# ------------------------------------------------------------------------------------------
# The happy path


def test_a_valid_script_is_pushed_and_a_pr_is_opened(workspace, stub_publish, capsys):
    exit_code = main(["--config", workspace["config"], "publish", workspace["app_dir"]])
    text = capsys.readouterr().out

    assert exit_code == 0
    assert len(stub_publish["push"]) == 1
    assert len(stub_publish["pr"]) == 1
    assert "https://github.com/owner/pipeline/pull/11" in text


def test_the_pushed_file_set_is_the_jmx_properties_and_sla_only(workspace, stub_publish):
    app_dir = Path(workspace["app_dir"])
    (app_dir / "results.jtl").write_text("timeStamp,elapsed\n", encoding="utf-8")

    main(["--config", workspace["config"], "publish", workspace["app_dir"]])

    names = sorted(f.name for f in stub_publish["push"][0]["files"])
    assert "results.jtl" not in names
    assert any(n.endswith(".jmx") for n in names)
    assert "sla_criteria.yaml" in names


def test_the_ir_is_read_but_never_published(workspace, stub_publish):
    main(["--config", workspace["config"], "publish", workspace["app_dir"]])

    pushed = [f.name for f in stub_publish["push"][0]["files"]]
    assert not any(name.endswith(".yaml") and name != "sla_criteria.yaml" for name in pushed)
    # ...but its contents reached the PR body.
    assert "Review status" in stub_publish["pr"][0]["body"]


def test_the_branch_and_base_come_from_config(workspace, stub_publish):
    main(["--config", workspace["config"], "publish", workspace["app_dir"]])

    assert stub_publish["push"][0]["target_path_prefix"] == "tests/generated"
    assert stub_publish["push"][0]["base_branch"] == "main"
    assert stub_publish["pr"][0]["branch"] == "perfgen/order_management"
    assert stub_publish["pr"][0]["base_branch"] == "main"


def test_the_token_is_passed_to_git_and_the_api_but_never_printed(workspace, stub_publish, capsys):
    main(["--config", workspace["config"], "publish", workspace["app_dir"]])
    output = capsys.readouterr()

    token = "ghp_testtokenvalue000000000000000000000"
    assert stub_publish["push"][0]["token"] == token
    assert stub_publish["pr"][0]["token"] == token
    assert token not in output.out
    assert token not in output.err


def test_the_commit_message_is_a_sentence_not_a_quoting_accident(workspace, stub_publish):
    main(["--config", workspace["config"], "publish", workspace["app_dir"]])

    message = stub_publish["push"][0]["commit_message"]
    assert message.startswith("Publish the Order management performance script")
    assert "@" not in message.splitlines()[0]


# ------------------------------------------------------------------------------------------
# Config


def test_pipeline_repo_must_be_owner_slash_repo():
    assert PublishConfig(pipeline_repo="a/b").owner_and_repo() == ("a", "b")
    with pytest.raises(ValueError):
        PublishConfig(pipeline_repo="justarepo").owner_and_repo()
    with pytest.raises(ValueError):
        PublishConfig(pipeline_repo="").owner_and_repo()
    with pytest.raises(ValueError):
        PublishConfig(pipeline_repo="a/b/c").owner_and_repo()


def test_publish_defaults_match_the_shipped_config():
    defaults = PublishConfig()
    assert defaults.target_path_prefix == "tests/generated"
    assert defaults.base_branch == "main"
    assert defaults.credential_ref == "perfgen-publish-token"
    assert defaults.checkout_path == Path(".perfgen/pipeline")

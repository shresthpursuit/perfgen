"""Publishing a reviewed script into the pipeline repository.

This is the one stage perfgen does not decide anything in. `perfgen run` generates a script; a
performance engineer reads it, edits it, runs it, and decides it is good. Running `perfgen publish`
*is* that approval - there is no separate flag, and nothing here re-litigates whether the test is a
good test.

What it does check is structural: the `.jmx` still parses and no `${var}` dangles. Step 2 invites
hand-editing the XML, and a typo'd variable name is exactly what a human reading XML misses. That
check is free (`perfgen.validate`) and it judges the file, not the test.

Everything a credential touches goes through `auth.resolve_publish_token`, deliberately. See its
docstring.
"""

from __future__ import annotations

from perfgen.publish.auth import resolve_publish_token
from perfgen.publish.git_ops import (
    GitError,
    PushResult,
    branch_name,
    github_remote_url,
    publish_files,
    select_files,
)
from perfgen.publish.pr import (
    PublishApiError,
    PullRequest,
    open_or_update_pr,
    pr_title,
    render_pr_body,
    source_commits,
)

__all__ = [
    "GitError",
    "PublishApiError",
    "PullRequest",
    "PushResult",
    "branch_name",
    "github_remote_url",
    "open_or_update_pr",
    "pr_title",
    "publish_files",
    "render_pr_body",
    "resolve_publish_token",
    "select_files",
    "source_commits",
]

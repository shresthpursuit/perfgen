"""The pull request: create-vs-update, and what the body tells a reviewer.

No real GitHub calls - `httpx.MockTransport`, the same pattern the probe tests use for the API
under test.

The body assertions are deliberately about *presence of a positive statement*, not absence of a
warning. A reviewer skimming a PR with no review section cannot tell "everything passed" from
"nothing was checked", and those mean very different things.
"""

from __future__ import annotations

import json

import httpx
import pytest

from perfgen.ir.models import Confidence, Extract, ExtractorType, Scope, Source
from perfgen.publish.pr import (
    PublishApiError,
    open_or_update_pr,
    pr_title,
    render_pr_body,
)
from perfgen.summary import count_correlations


class FakeGitHub:
    """Records requests and answers them from a script."""

    def __init__(self, open_prs: list[dict] | None = None):
        self.open_prs = open_prs or []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path

        if request.method == "GET" and path.endswith("/pulls"):
            return httpx.Response(200, json=self.open_prs)
        if request.method == "POST" and path.endswith("/pulls"):
            return httpx.Response(
                201, json={"number": 7, "html_url": "https://github.com/o/r/pull/7"}
            )
        if request.method == "PATCH":
            number = int(path.rsplit("/", 1)[-1])
            return httpx.Response(
                200, json={"number": number, "html_url": f"https://github.com/o/r/pull/{number}"}
            )
        return httpx.Response(404, json={"message": f"unexpected {request.method} {path}"})

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def body_sent(self) -> dict:
        writes = [r for r in self.requests if r.method in ("POST", "PATCH")]
        return json.loads(writes[-1].content)


def call(github: FakeGitHub, **overrides):
    kwargs = dict(
        owner="o",
        repo="r",
        branch="perfgen/order_management",
        base_branch="main",
        title="perfgen: Order Management performance script",
        body="body text",
        token="ghp_test",
        transport=github.transport,
    )
    kwargs.update(overrides)
    return open_or_update_pr(**kwargs)


# ------------------------------------------------------------------------------------------
# Create vs update


def test_a_branch_with_no_open_pr_gets_one_opened():
    github = FakeGitHub(open_prs=[])
    result = call(github)

    assert result.created is True
    assert result.number == 7
    assert result.url == "https://github.com/o/r/pull/7"
    assert [r.method for r in github.requests] == ["GET", "POST"]


def test_republishing_updates_the_existing_pr_instead_of_opening_a_second():
    github = FakeGitHub(open_prs=[{"number": 3, "html_url": "https://github.com/o/r/pull/3"}])
    result = call(github, body="refreshed body")

    assert result.created is False
    assert result.number == 3
    assert [r.method for r in github.requests] == ["GET", "PATCH"]
    assert github.body_sent()["body"] == "refreshed body"


def test_the_existing_pr_is_looked_up_by_head_branch():
    github = FakeGitHub()
    call(github)

    lookup = github.requests[0]
    assert lookup.url.params["head"] == "o:perfgen/order_management"
    assert lookup.url.params["state"] == "open"


def test_the_token_is_sent_as_a_bearer_credential():
    github = FakeGitHub()
    call(github, token="ghp_secret_value")
    assert github.requests[0].headers["authorization"] == "Bearer ghp_secret_value"


def test_a_missing_base_branch_is_explained_rather_than_reported_as_422():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(
            422,
            json={
                "message": "Validation Failed",
                "errors": [{"field": "base", "code": "invalid"}],
            },
        )

    with pytest.raises(PublishApiError) as exc:
        call(FakeGitHub(), transport=httpx.MockTransport(handler))

    assert "no 'main' branch" in str(exc.value)
    assert "initial commit" in str(exc.value)


def test_a_rejected_token_says_which_permissions_are_needed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Resource not accessible by integration"})

    with pytest.raises(PublishApiError) as exc:
        call(FakeGitHub(), transport=httpx.MockTransport(handler))

    assert "Contents: read and write" in str(exc.value)


# ------------------------------------------------------------------------------------------
# The body


def files_for(slug: str) -> list[str]:
    return [
        f"tests/generated/{slug}/{slug}.jmx",
        f"tests/generated/{slug}/baseline.properties",
    ]


def test_the_title_names_the_application(auth_shared_token):
    assert pr_title(auth_shared_token) == "perfgen: Order management performance script"


def test_a_flagged_correlation_leads_with_the_count_and_quotes_its_evidence(auth_shared_token):
    ir = auth_shared_token
    step = ir.flows[0].steps[0]
    step.extracts.append(
        Extract(
            var="orderId",
            source=Source.RESPONSE_BODY,
            extractor=ExtractorType.JSON_PATH,
            expr="$.id",
            scope=Scope.THREAD,
            confidence=Confidence.INFERRED,
            evidence="No traffic was observed. Guessed from the placeholder {orderId}.",
        )
    )

    total = count_correlations(ir)
    body = render_pr_body(ir, files=files_for("order_management"))

    assert "## Review status" in body
    assert f"**1 of {total} correlation(s) in this script are guesses.**" in body
    assert "No traffic was observed. Guessed from the placeholder {orderId}." in body
    assert "`orderId`" in body


def test_a_fully_verified_script_says_so_explicitly_rather_than_leaving_a_blank(
    auth_shared_token,
):
    """Silence where the review section would be reads as 'nothing was checked'."""
    ir = auth_shared_token
    step = ir.flows[0].steps[0]
    step.extracts.append(
        Extract(
            var="orderId",
            source=Source.RESPONSE_BODY,
            extractor=ExtractorType.JSON_PATH,
            expr="$.id",
            scope=Scope.THREAD,
            confidence=Confidence.VERIFIED,
            evidence="Observed in the response to step 1 and sent in step 2.",
        )
    )

    total = count_correlations(ir)
    body = render_pr_body(ir, files=files_for("order_management"))

    assert "## Review status" in body
    assert f"**0 of {total} correlation(s) need review.**" in body
    assert "are guesses" not in body


def test_a_script_with_no_correlations_is_not_reported_as_verified(auth_shared_token):
    """Nothing to verify is not a clean bill of health, and must not read like one."""
    for flow in auth_shared_token.flows:
        for step in flow.steps:
            step.extracts.clear()

    body = render_pr_body(auth_shared_token, files=files_for("order_management"))

    assert "**This script has no correlations.**" in body
    assert "not the same as everything having passed" in body
    assert "need review" not in body


def test_a_degraded_probe_is_stated_on_top_of_the_correlation_count(auth_shared_token):
    auth_shared_token.provenance.probe.degraded = True
    body = render_pr_body(auth_shared_token, files=files_for("order_management"))

    assert "**The probe did not run.**" in body


def test_the_body_lists_the_published_files_and_the_load_profiles(auth_shared_token):
    body = render_pr_body(auth_shared_token, files=files_for("order_management"))

    assert "## Files" in body
    assert "`tests/generated/order_management/order_management.jmx`" in body
    assert "## Load profiles" in body
    for profile in auth_shared_token.enabled_profiles:
        assert f"**{profile.id.value}**" in body


def test_the_body_apportions_users_per_flow(auth_shared_token):
    body = render_pr_body(auth_shared_token, files=files_for("order_management"))
    for flow in auth_shared_token.flows:
        assert f"`{flow.id}`" in body
        assert f"{flow.share_pct}%" in body


def test_skipped_local_artifacts_are_named_in_the_body(auth_shared_token):
    body = render_pr_body(
        auth_shared_token, files=files_for("order_management"), skipped=["results.jtl"]
    )
    assert "`results.jtl`" in body


def test_the_body_records_provenance_and_says_perfgen_did_not_run_the_script(auth_shared_token):
    body = render_pr_body(
        auth_shared_token,
        files=files_for("order_management"),
        perfgen_commit="abc1234",
        spec_commit="def5678",
    )

    assert auth_shared_token.provenance.source_workbook in body
    assert "abc1234" in body
    assert "def5678" in body
    assert "perfgen does not execute the script" in body

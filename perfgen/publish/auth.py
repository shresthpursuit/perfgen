"""The single point where a pipeline-repo credential is obtained.

Isolated on purpose. This POC pushes to a company GitHub account with a personal access token; the
real target is a client environment with materially stricter compliance, where the credential will
be a GitHub App installation token or an OIDC-federated one. That swap has to be an edit to this
function body and nothing else - so `git_ops` and `pr` take a `str` and are never told where it
came from, and nothing else in the package calls `perfgen.secrets`.

For now it is one line, reusing the already-audited resolution path rather than introducing a
second secret mechanism: `credential_ref` is a reference *name* (`perfgen-publish-token`), mapped
to an environment variable (`PERFGEN_PUBLISH_TOKEN`) by the same `env_var_name` the emitter and the
probe share.
"""

from __future__ import annotations

from perfgen import secrets
from perfgen.config import Config


def resolve_publish_token(config: Config) -> str:
    """Return the credential for the pipeline repository.

    Raises `perfgen.secrets.MissingSecret` when it is not set - whose message already names the
    exact environment variable and how to set it. No default is substituted: an empty token would
    produce a push that fails authentication with nothing to show why.
    """
    return secrets.resolve(config.publish.credential_ref)


def token_variable_name(config: Config) -> str:
    """The environment variable the token is read from, for messages that must name it."""
    return secrets.env_var_name(config.publish.credential_ref)

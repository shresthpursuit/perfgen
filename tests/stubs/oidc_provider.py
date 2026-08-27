"""A local OIDC provider that genuinely verifies PKCE.

Written because two real targets could not close M7's gate. A live Entra tenant enforces
device-compliance conditional access and answers `AADSTS50058` instead of a code; a public mock
provider manufactures its code in the browser with `btoa(JSON.stringify(...))` and never sees
`code_challenge` at all. Neither could prove the token exchange, and neither could ever have proved
the emitted `.jmx` obtaining a token on the wire - that needs a provider on this machine.

**The point of this stub is that it can fail.** One that accepted any `code_verifier` would turn
the gate green while proving nothing, which is worse than having no gate: it would look like
evidence. So the verification is the feature and everything else is scaffolding around it:

    expected = base64url(sha256(code_verifier)) with padding stripped
    reject with invalid_grant unless expected == the challenge stored at /authorize

Three further rejections, each one a way a broken script slips past a lax server: a missing
verifier, a reused code, and a `redirect_uri` that does not match the one the code was issued for
(RFC 6749 section 4.1.3).

The login form is deliberately load-bearing too. `/login` rejects a request whose `loginToken` or
`sessionNonce` does not match the session, so a correlation perfgen fails to find makes the login
fail rather than quietly succeed. The two values sit in different shapes on purpose - one in a
hidden input, one in a JSON blob inside a `<script>` - so both of the tool's extraction paths are
exercised by a passing run rather than merely by unit tests.

Standard library only, so there is nothing to install.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

DEFAULT_PORT = 8477

# The stub reads the same variables perfgen resolves `{secret:stub-login-user}` from, so the
# credentials exist in neither the workbook, this file, nor the repository.
USER_ENV = "STUB_LOGIN_USER"
PASSWORD_ENV = "STUB_LOGIN_PASSWORD"


def base64url_sha256(value: str) -> str:
    """The S256 transformation from RFC 7636, which is the whole reason this stub exists."""
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@dataclass
class Session:
    """One authorize request, awaiting a login."""

    code_challenge: str
    redirect_uri: str
    client_id: str
    state: str
    login_token: str
    nonce: str


@dataclass
class IssuedCode:
    """A code that has been minted and not yet redeemed."""

    session: Session
    redeemed: bool = False


@dataclass
class Store:
    sessions: dict[str, Session] = field(default_factory=dict)
    codes: dict[str, IssuedCode] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


# HTML5, deliberately not well-formed XML: void elements are left unclosed, exactly as a real
# login page writes them. An earlier version self-closed everything, which made the page valid XML
# - so it parsed structurally, the whole `<script>` became a single text leaf, and the nonce inside
# it was invisible to correlation. No real identity provider serves XHTML; a stub that does would
# have exercised a path the tool never meets and skipped the one it always does.
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in</title>
</head>
<body>
<h1>Stub identity provider</h1>
<script type="text/javascript">
//<![CDATA[
$Config={{"sessionNonce":"{nonce}","pgid":"StubSignIn","apiVersion":2}};
//]]>
</script>
<form method="POST" action="/login" id="loginForm">
  <input type="hidden" name="loginToken" value="{login_token}">
  <input type="hidden" name="state" value="{state}">
  <label>Username <input type="text" name="username"></label>
  <br>
  <label>Password <input type="password" name="password"></label>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "perfgen-stub-oidc/1.0"

    # --- plumbing ------------------------------------------------------------------------

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        if getattr(self.server, "verbose", False):  # pragma: no cover - operator convenience
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status: int, markup: str) -> None:
        self._send(status, markup.encode("utf-8"), "text/html; charset=utf-8")

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _error(self, code: str, description: str, status: int = 400) -> None:
        """An OAuth error, in the shape RFC 6749 section 5.2 specifies."""
        self._json(status, {"error": code, "error_description": description})

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    # --- routes --------------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server's interface
        path = urlsplit(self.path).path
        if path == "/authorize":
            self._authorize(dict_from_query(self.path))
        elif path == "/.well-known/openid-configuration":
            base = f"http://{self.headers.get('Host')}"
            self._json(
                200,
                {
                    "issuer": base + "/",
                    "authorization_endpoint": base + "/authorize",
                    "token_endpoint": base + "/token",
                    "code_challenge_methods_supported": ["S256"],
                    "response_types_supported": ["code"],
                },
            )
        else:
            self._error("not_found", f"no route for GET {path}", status=404)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/login":
            self._login(self._form())
        elif path == "/token":
            self._token(self._form())
        else:
            self._error("not_found", f"no route for POST {path}", status=404)

    # --- /authorize ----------------------------------------------------------------------

    def _authorize(self, params: dict[str, str]) -> None:
        if params.get("response_type") != "code":
            return self._error("unsupported_response_type", "only response_type=code is served")

        challenge = params.get("code_challenge", "")
        method = params.get("code_challenge_method", "")
        if not challenge:
            return self._error("invalid_request", "code_challenge is required")
        if method != "S256":
            # `plain` is refused deliberately. Accepting it would let an implementation that never
            # hashes anything pass a gate whose entire purpose is to prove that it does.
            return self._error(
                "invalid_request", f"code_challenge_method must be S256, got {method!r}"
            )
        if not params.get("redirect_uri"):
            return self._error("invalid_request", "redirect_uri is required")

        session = Session(
            code_challenge=challenge,
            redirect_uri=params["redirect_uri"],
            client_id=params.get("client_id", ""),
            state=params.get("state", ""),
            login_token=secrets.token_urlsafe(24),
            nonce=secrets.token_urlsafe(18),
        )
        with self.store.lock:
            self.store.sessions[session.login_token] = session

        self._html(
            200,
            LOGIN_PAGE.format(
                nonce=session.nonce, login_token=session.login_token, state=session.state
            ),
        )

    # --- /login --------------------------------------------------------------------------

    def _login(self, form: dict[str, str]) -> None:
        with self.store.lock:
            session = self.store.sessions.get(form.get("loginToken", ""))

        # Both correlated values are checked, so a correlation perfgen failed to find fails the
        # login rather than passing unnoticed. They sit in different shapes in the page - one a
        # hidden input, one inside a script - so a passing run exercises both extraction paths.
        if session is None:
            return self._error("invalid_request", "loginToken does not match any session")
        if form.get("sessionNonce") != session.nonce:
            return self._error("invalid_request", "sessionNonce does not match the session")

        expected_user = os.environ.get(USER_ENV)
        expected_password = os.environ.get(PASSWORD_ENV)
        if not expected_user or not expected_password:
            return self._error(
                "server_error",
                f"the stub needs {USER_ENV} and {PASSWORD_ENV} set to check credentials",
                status=500,
            )
        if form.get("username") != expected_user or form.get("password") != expected_password:
            return self._error("access_denied", "username or password is wrong", status=401)

        code = secrets.token_urlsafe(24)
        with self.store.lock:
            self.store.codes[code] = IssuedCode(session=session)
            self.store.sessions.pop(session.login_token, None)

        query = urlencode({"code": code, "state": session.state})
        self._send(
            302,
            b"",
            "text/plain",
            extra={"Location": f"{session.redirect_uri}?{query}"},
        )

    # --- /token --------------------------------------------------------------------------

    def _token(self, form: dict[str, str]) -> None:
        if form.get("grant_type") != "authorization_code":
            return self._error("unsupported_grant_type", "only authorization_code is served")

        with self.store.lock:
            issued = self.store.codes.get(form.get("code", ""))
            if issued is not None and issued.redeemed:
                # Single use. A replayed code is how a script that mishandles state still looks
                # like it works.
                return self._error("invalid_grant", "authorization code has already been redeemed")
            if issued is not None:
                issued.redeemed = True

        if issued is None:
            return self._error("invalid_grant", "unknown authorization code")

        session = issued.session
        if form.get("redirect_uri") != session.redirect_uri:
            return self._error(
                "invalid_grant", "redirect_uri does not match the one the code was issued for"
            )

        verifier = form.get("code_verifier")
        if not verifier:
            return self._error("invalid_grant", "code_verifier is required")

        # The check the whole stub exists for.
        if base64url_sha256(verifier) != session.code_challenge:
            return self._error(
                "invalid_grant", "code_verifier does not match code_challenge"
            )

        self._json(
            200,
            {
                "access_token": "stub." + secrets.token_urlsafe(32),
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid",
            },
        )


def dict_from_query(path: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(path).query, keep_blank_values=True).items()}


class StubProvider:
    """Runs the provider on a background thread.

    Threading matters: the emitted script runs concurrent virtual users, and a single-threaded
    server would serialise them into a queue that looks like latency.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, verbose: bool = False):
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.store = Store()  # type: ignore[attr-defined]
        self._server.verbose = verbose  # type: ignore[attr-defined]
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> str:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> StubProvider:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="A local OIDC provider that verifies PKCE.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--verbose", action="store_true", help="log every request")
    args = parser.parse_args()

    provider = StubProvider(host=args.host, port=args.port, verbose=args.verbose)
    url = provider.start()
    print(f"stub OIDC provider on {url}")
    print(f"  authorize: {url}/authorize")
    print(f"  token:     {url}/token")
    for name in (USER_ENV, PASSWORD_ENV):
        print(f"  {name}: {'set' if os.environ.get(name) else 'NOT SET - /login will 500'}")
    print("Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        provider.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

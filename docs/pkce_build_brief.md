# Build brief: PKCE support (M7)

## Context, and a correction

`CLAUDE.md` currently records PKCE as refused at parse time, on the reasoning that it "needs a
browser redirect and an interactive login." That reasoning conflated two different things and was
wrong in an important way: the *cryptographic* half of PKCE is pure computation with no browser
involved, and the *login* half is a sequence of ordinary HTTP requests. Both are automatable. A
working hand-built JMeter script proving this exists and is the reference for this work.

That entry gets amended, not ignored.

**The reference script is committed at `docs/reference/pkce_entra_reference.jmx` and is confirmed
working** — it produces a real access token against a live Entra tenant. Read it in full before
designing; it will contain details this brief has not called out.

## What the reference script does

The reference authenticates against Microsoft Entra (`login.microsoftonline.com`) with no browser
and no human, in five stages:

1. **setUp thread group** — JSR223 generates a `code_verifier` (32 random bytes, base64url, no
   padding), a second JSR223 derives the `code_challenge` (SHA-256 of the verifier, base64url).
   Both promoted to JMeter properties so the main thread group can read them.
2. **`GET /authorize`** with `response_type=code`, `client_id`, `scope`, `redirect_uri`,
   `code_challenge`, `code_challenge_method=S256`. Returns an **HTML login page**, not a redirect.
3. **`POST /GetCredentialType`** — carries `sCtx` and `sFT` scraped out of that HTML page.
4. **`POST /login`** with username, password, and `canary`/`ctx`/`flowToken` values, also scraped
   from HTML. Responds `302` with `code=` in the `Location` header.
5. **`POST /token`** — `grant_type=authorization_code`, `code`, `code_verifier`, `client_id`,
   `redirect_uri`. Returns the access token.

Stages 1, 2 and 5 are RFC-defined and identical for every IdP. Stages 3 and 4 are Entra's own
login contract and differ completely for Okta, Auth0, Ping or anything custom.

## Three findings from reviewing that script — read before designing

**The code extraction works by accident.** `redirect_uri` is a custom scheme
(`msal<guid>://auth`) that JMeter cannot follow, so the `302` survives and a header-scoped
`RegexExtractor` finds `code=`. Point the same flow at an app registered with an `https://`
redirect URI and JMeter follows the redirect, the header disappears, and extraction silently
returns "Not Found". **The generated script must set `follow_redirects=false` explicitly on
whichever step produces the code.** Never rely on the URI scheme to do it.

**Verifier and challenge are generated per thread, not shared.** The confirmed-working reference
places the two JSR223 samplers and the whole auth sequence inside the *same* thread group as the
load flows, so every virtual user derives its own verifier/challenge pair. This is what a real
client does, and it sidesteps the question of whether an IdP enforces single-use challenges
entirely. Generate per thread; do not build a shared setUp-group variant.

The reference still calls `__setProperty` on the resulting `accessToken`. That is not a
cross-thread-group bridge for the PKCE values — it exists so that *later* thread groups running
the actual API load can read the token. Preserve that intent when emitting: the token must be
reachable by the flow thread groups.

**The reference has a live bug worth not reproducing.** Its canary extractor writes
`canaryvalue_var`, but one header manager sends `canary: ${canary_var}` — a variable nothing
creates, so that header goes out as literal `${canary_var}` text. Entra tolerates it. perfgen's
existing structural validation would have caught it, which is a good argument for generating this
rather than hand-maintaining it. Do not port the typo.

---

## Scope: two halves, one milestone

These were considered as separate milestones and deliberately merged. A PKCE flow without an
interactive login step is a case that does not occur in practice — the grant type exists precisely
because a human normally logs in. Shipping the crypto half alone would be a feature for a
situation nobody has. Both halves land together, gated on one real end-to-end run.

### Half A — the PKCE skeleton (deterministic)

Standard, RFC-defined, identical for every IdP.

### Half B — raw-text correlation scanning

The blocker that makes Half A useful. Entra's `/authorize` returns HTML with `"sCtx":"..."`,
`"sFT":"..."`, `"canary":"..."` embedded in a JavaScript config blob. perfgen's correlation scan
handles JSON, XML and form-encoded; an HTML body currently reports as `UnreadableBody` and
contributes zero candidates. Without text scanning, the probe cannot discover the values the login
steps need.

---

## Design decisions

**Login steps are declared, not discovered.** The workbook states the login sequence; the
framework discovers the *values*. Discovery would mean parsing an HTML form, guessing which fields
are credentials and guessing the submit target — heuristics stacked on heuristics, which is where
every defect on this project has originated. Declaring keeps the division that already works
everywhere else in this tool: the human supplies structure, the machine supplies correlations.

**Redirect URI, scope and authorize URL are spec input and cannot be discovered.** They are
registration facts held by the IdP, not runtime-discoverable ones — Entra rejects any `/authorize`
whose `redirect_uri` does not exactly match a pre-registered value, so there is no first request to
observe without already knowing it. Missing means a blocking gap.

**Protocol constants are hardcoded; everything else is spec-driven.** Same reasoning already
applied to `grant_type=client_credentials`: a value fixed by RFC 7636/6749 is not an assumption
about the application under test.

Hardcode: `response_type=code`, `code_challenge_method=S256`, `grant_type=authorization_code`,
32 verifier bytes, SHA-256, base64url without padding.

Never hardcode: tenant identifiers (they sit inside the authorize and token paths), `client_id`,
`scope`, `redirect_uri`, authorize/token URLs, credentials, cookies, headers, the login step
sequence, or any extractor expression.

---

## Half A — implementation

### Workbook: new Application fields, required only when `Auth type` is `OAuth2 PKCE`

| Field | Notes |
|---|---|
| `Authorize endpoint URL` | Full URL. Tenant/realm identifiers live inside this path — never a separate field. |
| `Redirect URI` | Must exactly match what is registered with the IdP. |
| `Scope` | Space-separated if multiple. |

`Token endpoint URL` and `Credential reference names` already exist and are reused.

The login sequence needs a real username and password. These are credential references like every
other secret in this tool — `pkce-login-user` and `pkce-login-password`, resolved from the
environment, never literals in the workbook or the emitted script. Note this is the one part of
PKCE that genuinely cannot be automated away: no browser is needed, but a real account's
credentials are inherent to a password-based login step.

The reference also seeds three cookies on `login.microsoftonline.com` before the flow starts.
Those are IdP-specific and discovered by observation, so they belong in the spec, not in code —
reuse the existing `Additional required headers` pattern with an equivalent optional
`Seed cookies` field (`name: value` per line, plus a domain). If the field is empty, emit no
Cookie Manager entries.

**Gap message must be actionable, not just "field required."** A missing redirect URI should name
where to obtain it: the team owning the app registration; in Azure, App registrations →
Authentication → Redirect URIs, with scope and tenant from the same place. This is the difference
between a spec that gets completed and one that stalls.

### IR

`auth.authorize_url`, `auth.redirect_uri`, `auth.scope`, and the auth-flow step list (below).
Validated as required when `auth.type is OAUTH2_PKCE`.

### Emitter

```
Thread Group (N threads)
├── JSR223 Sampler: verifier   (32 random bytes, base64url, no padding)
├── JSR223 Sampler: challenge  (SHA-256 of verifier, base64url)
├── HTTP Cookie Manager        (seed cookies, if the spec declares any)
├── Transaction Controller: authenticate
│   ├── GET {authorize_url} + RFC params + spec params
│   ├── [declared auth flow steps — Half B correlations wire these]
│   │   └── the code-producing step: follow_redirects = FALSE
│   │       └── Extractor: code= from the Location header
│   └── POST {token_url}
│       ├── grant_type=authorization_code, code, code_verifier, client_id, redirect_uri
│       ├── Extractor: access_token from response body
│       └── JSR223 PostProcessor: props.put(accessToken, ...)
└── ... normal flow steps, using the token
```

Use `props.put(...)` in a JSR223 post-processor for the token. Do **not** reproduce the
reference's `__setProperty` BeanShell assertions — same effect, fewer elements, and BeanShell is
legacy. Verifier and challenge stay as thread variables; only the token needs promoting.

---

## Half B — implementation

### New workbook sheet: `Auth flow steps`

Same columns as `Flow steps` (`Step no`, `Step name`, `Method`, `Endpoint path`,
`Request body or parameters`, `Expected status`). Only read when `Auth type` is `OAuth2 PKCE`.
These steps run between authorize and token exchange, in the setUp/auth portion of the tree, not
inside the load flows.

Use `{placeholder}` syntax exactly as `Flow steps` already does — correlation discovers what fills
them.

### Raw-text scanning in `perfgen/correlate/scan.py`

When no structured parser can read a body, fall back to raw-text substring scanning rather than
recording an `UnreadableBody` and stopping.

Structured parsing hands you a *location* (`$.data[0].id`) for free, and that location becomes the
extractor expression. Raw text gives a byte offset, which is useless as an extractor. So this half
must **synthesise an extractor expression from surrounding context** — e.g. seeing
`"sCtx":"AQAB…"` and producing `"sCtx":"([^"]+)"`.

Requirements:

- Prefer a **boundary-based** expression (left/right context) over a hand-built regex where
  possible — JMeter's Boundary Extractor exists for exactly this and avoids regex-escaping bugs.
- When a regex is genuinely needed, escape the context properly and pin the match number.
- An HTML page is full of coincidentally repeated strings. The existing low-entropy and
  client-originated filters both still apply and must not be weakened. Expect to need an
  additional guard against context that appears many times in one body.
- `UnreadableBody` reporting stays for bodies where even text scanning finds nothing.

---

## Tests

- Crypto: a known verifier produces the known SHA-256 base64url challenge (pin against an
  RFC 7636 test vector, not a self-generated value).
- Emitter: `follow_redirects` is `false` on the code-producing step — assert on the emitted tree,
  and add a test that fails if it is ever flipped.
- Emitter: no BeanShell elements anywhere in PKCE output.
- Parser: PKCE spec missing redirect URI / scope / authorize URL is blocking, with the actionable
  message; PKCE spec with all fields parses cleanly and is no longer refused.
- Auth flow steps: parsed, ordered, placeholders detected.
- Text scanning: an HTML fixture containing the reference's `sCtx`/`sFT`/`canary` shape yields
  candidates with usable extractor expressions; the existing bait-traffic tests still reject
  `true`/`USD`/`200`/echoed client values unchanged; a context string appearing many times in one
  body does not produce a confident extractor.
- The full existing suite stays green — particularly the seven-auth-type coverage matrix, which
  currently asserts PKCE is refused and will need updating rather than deleting.

## Gate — the real one

Generate a PKCE spec workbook for the reference Entra flow, run `perfgen run` end to end, and
confirm from real traffic:

1. The probe completes authorize → login steps → token exchange and records a real access token.
2. `code_verifier` and `code_challenge` correlate correctly — the token call carries the verifier
   matching the challenge sent to `/authorize`.
3. `sCtx`, `sFT` and `canary` are discovered by correlation from the HTML body, marked
   `verified`, not guessed from placeholder names.
4. The emitted `.jmx` runs in real JMeter and obtains a token on the wire.
5. No credential value appears in the `.jmx`, the IR, the probe record, or any log.

Paste the actual probe record, the actual extractor expressions, and the actual JMeter result —
not a description of them.

Credentials for the reference tenant are supplied via `.env` as usual and never committed.

## Not building

- Discovering the login sequence automatically. Declared only.
- Any browser automation or headless browser.
- IdP-specific logic of any kind — no Entra branches in the code. If something cannot be expressed
  as declared steps plus discovered correlations, raise it rather than special-casing it.
- Per-thread verifier generation.
- Closing the credential-sourced-headers deferral, which remains separate.

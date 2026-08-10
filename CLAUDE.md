# perfgen

Reads a filled-in Excel API specification and emits a runnable Apache JMeter `.jmx`. Spreadsheet in,
`.jmx` out. Full specification: `docs/BUILD_BRIEF.md`.

**This is a compiler, not an agent chain.** Exactly one LLM call site: adjudicating correlation
candidates (M4). Parsing, HTTP, string matching and XML emission are deterministic code.
`Excel spec → parse → Test Plan IR (YAML) → probe run → correlate → emit .jmx`

The IR is the load-bearing artifact — the review surface (engineers fix YAML, never generated XML)
and the test surface (emitter tested against hand-written IR fixtures, no LLM, no network). Each
stage writes its artifact to disk before the next reads it and is independently re-runnable.

## Hard constraints

- **No secret values ever written** to disk, IR, logs, or JMX. Reference names only; the JMX reads
  credentials via `${__env(...)}` or a property at run time.
- **The LLM never emits XML.**
- **Never invent a missing input value.** Missing required input is a `gaps` entry, not a default.
  Blocking gaps mean a clear message and a non-zero exit.
- **Every extractor carries `confidence` and `evidence`.**

## Milestones — walking skeleton; each runs end to end, no half-wired stages

1. **M1** — IR + emitter + structural validation. No LLM, no Excel, no HTTP. Gate: a generated
   script must open and run in JMeter at 1 thread before M2 starts.
2. **M2** — workbook parser, gap reporting, non-zero exit on blocking gaps.
3. **M3** — probe runner; traffic captured to disk; `probe_safe: false` never executed.
4. **M4** — correlation: deterministic candidate scan (both filters), then one LLM call.
5. **M5** — CLI, config file, output layout, run summary.

## Amendments to the brief (authoritative where they conflict)

- **D1 — one JMX, profile-agnostic properties.** Thread counts are per-flow properties
  (`${__P(users_F01,15)}`), never profile-named. One `.properties` file per enabled profile into
  `outputs/{application_name}/`. Per-flow defaults apportioned from total users by `share_pct` via
  largest-remainder so they sum exactly. Constant Throughput Timer takes samples **per minute**
  (`tps×60`, `tpm×1`, `tph÷60`). Supersedes the brief's `${__P(users_baseline,25)}` example.
- **D2 — think time inside the Transaction Controller**, with
  `<boolProp name="TransactionController.includeTimers">false</boolProp>` written explicitly on
  every controller; never rely on the default. JMeter timers are scoped, not sequential — a timer
  fires before every sampler in its scope, so sibling timers stack.
- **D3 — an enabled load profile with a throughput target but no user count is a `blocking` gap**,
  naming the sheet and row to fill in. Never default the thread count.
- `application.api_reference` is stored in the IR with no behaviour attached.

## Non-goals — do not build, scaffold, stub, or leave hooks for

Azure Load Test, CI/CD or GitHub Actions files, git/PR automation. UI or browser testing. Result
analysis, reporting, dashboards. Test data generation or CSV Data Set wiring. Vector DBs,
embeddings, RAG. Retry logic in generated scripts. Per-sample SLA assertions — they mark
slow-but-successful responses as errors and corrupt the error rate, so SLAs go to a separate
criteria file. Token refresh. Multi-agent frameworks. **OpenAPI/Swagger pre-fill of Flow steps.**
If you think one is needed, ask first.

## Stack
Python 3.11+, `pydantic` v2, `openpyxl`, `httpx`, `jinja2` + `lxml`, `pyyaml`, `pytest`, `ruff`; LLM
via the Claude Agent SDK. JMeter version is pinned in `config.yaml` — emitter templates are
version-sensitive, guarded by a golden-file test.

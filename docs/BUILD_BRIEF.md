# Build brief: API performance test script generator

Build a Python tool that reads a filled-in Excel specification describing an API, its business
flows and its load requirements, and emits a working Apache JMeter test script (`.jmx`) with
dynamic value correlation wired in.

Scope is deliberately minimal: **spreadsheet in, `.jmx` out.** Nothing else.

Read this whole brief, confirm the milestone plan back to me, then start at M1.

---

## 1. What this is and why

Performance test scripting is manual and slow. The hard part is not writing HTTP samplers — it is
correlation: finding values the server generates in one response that must be carried into a later
request (tokens, record IDs, references) and wiring extractors for them. That currently needs a
specialist.

The target user is **not** a performance tester. They know their API and their expected load, and
have never opened JMeter. They fill in a spreadsheet; they get a runnable script.

### Central design decision

**This is a compiler, not an agent chain.** An LLM must never generate JMeter XML. JMX is deeply
nested `hashTree`-paired XML where one mispaired tag produces a file JMeter silently refuses to
open. XML emission is deterministic template code.

There is exactly **one** LLM call site in this tool: adjudicating correlation candidates. Parsing,
HTTP, string matching and XML emission are ordinary deterministic code with right answers.

### Data flow

```
Excel spec ──▶ parse ──▶ Test Plan IR (YAML) ──▶ probe run ──▶ correlate ──▶ emit .jmx
```

The **Test Plan IR** is the load-bearing artifact: human-readable, human-editable, committed to
git. It is the review surface (an engineer fixes YAML, never generated XML) and the test surface
(the emitter is unit-tested against hand-written IR fixtures with no LLM and no network).

---

## 2. Input: the specification workbook

Two workbooks ship in `data/specs/`:

- **`template.xlsx`** — the blank form the user fills in. It contains no example rows.
- **`sample_filled.xlsx`** — a complete worked example, for reference only. Never submitted.

An `.xlsx` with the sheets below. Header row is row 1 on every sheet.

**Application** — attribute/value pairs with section divider rows. Locate the value by finding the
label in the `Attribute` column and reading the cell under the `Value` **column header** — the sheet
also carries `Required`, `Notes` and `Example` columns. **The `Example` column is guidance for the
user and is never parsed**; on free-text rows it deliberately differs from `Value`, so a parser
reading the wrong column produces wrong output rather than failing. Fields:
`Application name`, `Base URL`, `Base path`, `API reference location`, `Auth type`,
`Token endpoint URL`, `Token request method`, `Token request content type`,
`Token request parameters` (newline-separated names), `Token lifetime (seconds)`,
`Auth header name`, `Auth header value format`, `Credential reference names` (newline-separated),
`Account model`.

**Flows** — `Flow ID`, `Flow name`, `Share of load %`, `Think time between calls (s)`,
`Safe to run against this environment`.

**Flow steps** — `Flow ID`, `Step no`, `Step name`, `Method`, `Endpoint path`,
`Request body or parameters`, `Expected status`.

**Load profiles** — one row per test type (`Baseline`, `Peak load`, `Capacity / overload`,
`Endurance`): `Test type`, `Required`, `Concurrent users`, `Ramp-up (s)`, `Duration (min)`,
`Target throughput`, `Throughput unit`.

**SLA** — `Applies to`, `Metric`, `Target`, `Unit`.

### Parsing rule that matters

**Locate fields by matching label text, never by cell coordinate.** Users insert rows, rename tabs
and reorder sections. Coordinate-based parsing breaks silently on the second file you receive.
Match the label string (case-insensitive, whitespace-normalised), read the cell in the column whose
row-1 header is `Value` — not simply the adjacent cell, since `Example` sits on the same row — and
record every label you expected but could not find. Locate table columns the same way, by header
text rather than position.

---

## 3. The Test Plan IR

The contract between every stage. Pydantic v2 models, serialised to YAML.

```yaml
spec_version: 1

application:
  name: str
  base_url: str                     # scheme + host, no trailing slash
  base_path: str | null
  api_reference: str | null         # stored only; no behaviour attached

auth:
  type: none | oauth2_client_credentials | oauth2_password | oauth2_pkce
        | bearer_static | api_key | basic
  strategy: shared_setup | per_thread     # derived from Account model
  token_request:
    method: str
    url: str
    content_type: str
    param_names: [str]              # names only — never values
    credential_refs: [str]          # secret reference names only
  token_extract:
    source: response_body | response_header | cookie
    expr: str | null                # null until the probe determines it
    confidence: verified | inferred | unknown
  lifetime_seconds: int | null
  header_name: str
  value_format: str                 # e.g. "Bearer {token}"
  refresh_required: bool            # computed: any enabled duration > lifetime

flows:
  - id: str                         # F01
    name: str
    share_pct: int
    think_time_ms: int
    probe_safe: bool
    steps:
      - index: int
        name: str
        method: GET | POST | PUT | PATCH | DELETE
        path: str                   # may contain {varName} placeholders
        body: str | null
        content_type: str | null    # inferred from body when absent
        expected_status: int
        extracts:
          - var: str
            source: response_body | response_header | cookie
            extractor: json_path | regex | boundary | header
            expr: str
            scope: global | thread | iteration
            confidence: verified | inferred
            evidence: str           # why this correlation is believed to exist
            used_by: [str]          # e.g. ["F01.2.path"]
        assertions:
          - type: response_code
            value: int

load_profiles:
  - id: baseline | peak | capacity | endurance
    enabled: bool
    users: int | null
    ramp_up_s: int | null
    duration_s: int
    throughput:
      value: number
      unit: tps | tpm | tph
    # users and throughput are both optional individually;
    # both absent on an enabled profile is a blocking gap

sla:
  - scope: str                      # "all" or a flow id
    metric: response_time_p95 | response_time_p99 | error_rate | throughput
    target: number
    unit: ms | s | percent | tps | tpm | tph

gaps:
  - field: str
    severity: blocking | warning
    message: str

provenance:
  source_workbook: str
  generated_at: str                 # ISO 8601
  probe:
    performed: bool
    timestamp: str | null
    steps_observed: int
```

### Scope semantics

`scope` decides where the extractor sits in the JMeter tree and how the value is shared:

- `global` — JVM-wide. Written by a JSR223 post-processor calling `props.put(...)`, read as
  `${__P(name)}`. Used for a shared auth token.
- `thread` — per virtual user, persisting across iterations.
- `iteration` — re-extracted every iteration. Default for record IDs.

Wrong scope produces scripts that pass a single-user smoke test and fail under load, so it is
explicit in the IR rather than inferred at emit time.

---

## 4. Stage specifications

### 4.1 Parse — deterministic, no LLM

Workbook → IR. Every field in this workbook is a dropdown value, a URL, a number or a
newline-separated list, so this is plain parsing. Fill everything structurally present. Every
missing required field becomes a `gaps` entry. Do not raise on missing data — collect and continue.

**Never invent a value.** If concurrency and throughput are both absent on an enabled load
profile, that is a blocking gap, not an opportunity to assume 50 users. An invented thread count
produces a script that runs, validates, and measures the wrong thing. Blocking gaps mean a clear
message and a non-zero exit.

**D3 — concurrency absent on an enabled profile is blocking even when throughput is present.**
JMeter cannot build a thread group without a thread count, and a Constant Throughput Timer only
paces threads that already exist; deriving a thread count from a throughput target would be
inventing a value. The gap message names the sheet and row to fill in, e.g.
`Load profiles, row 4 (Capacity / overload): Concurrent users`.

### 4.2 Probe — deterministic

Execute the auth request, then each flow once, single-threaded, in step order, using credentials
resolved from the configured secret store. Record for every call: request method, URL, headers,
body; response status, headers, cookies, body.

**Never execute a flow whose `probe_safe` is false.** Skip it, record the skip in provenance, and
mark its correlations `inferred`.

If the probe cannot run at all (no credentials, environment unreachable), continue in degraded
mode: infer correlations from `{placeholder}` names in paths, mark every extractor
`confidence: inferred`, and say so prominently in the run summary and in a comment in the JMX.

### 4.3 Correlate — deterministic scan, then one LLM call

**Candidate detection is deterministic.** Flatten every response into `(json_path, value)` leaf
pairs plus header and cookie values. For each later request, scan its path, query string, headers
and body for exact string matches against that index.

Two filters, both required, or the output is noise:

1. **Discard low-entropy values** — short strings, booleans, common enums (`USD`, `true`,
   `active`), small integers, and any value appearing across many distinct responses.
2. **Discard client-originated values** — if a value appears in request N *and* response N, the
   server echoed it back; it came from the client and is static, not a correlation. Only
   server-originated values are candidates.

**Then one LLM call adjudicates** the survivors: name the variable, choose the extractor type,
choose the scope, resolve cases where the same value appears at several JSON paths, and flag
values that appear *transformed* rather than copied (base64-wrapped, hashed, concatenated,
recomputed timestamps). Transformed values are emitted as `confidence: inferred` with a
`needs_review` note, never as a confident extractor — a wrong extractor fails silently under load.

Every extractor written to the IR carries `confidence` and `evidence`.

### 4.4 Emit — deterministic

IR → `.jmx`. Jinja2 templates per element type, assembled with lxml so `hashTree` pairing is
structurally guaranteed rather than hoped for. One template per element, each unit-tested.

```
Test Plan
├── User Defined Variables            (base URL, load params as ${__P(...)})
├── HTTP Cookie Manager
├── HTTP Cache Manager
├── setUp Thread Group                (only when auth.strategy == shared_setup)
│   ├── HTTP Request: acquire token
│   ├── Extractor → token variable
│   ├── JSR223 PostProcessor → props.put("authToken", ...)
│   └── Response Assertion (status)
└── Thread Group per flow             (threads apportioned by share_pct)
    ├── HTTP Header Manager           (auth header + statics)
    ├── Transaction Controller per step   (includeTimers = false)
    │   ├── HTTP Request
    │   ├── Extractors for that step
    │   ├── Response Assertion
    │   └── Constant Timer (think time)
    └── Throughput timer              (only when a throughput target is set)
```

Emitter rules:

- **All load parameters as JMeter properties**, named per flow and **never per profile**:
  `${__P(users_F01,15)}`. One JMX serves all four load profiles, driven by property files — a
  profile-named property such as `users_baseline` would hardcode one profile into the thread-count
  field and require editing the JMX to run another. Never emit four near-identical scripts — they
  drift the moment one correlation is fixed.
- **The emitter writes one `.properties` file per enabled profile** to
  `outputs/{application_name}/{profile_id}.properties`; inline defaults in the JMX are the baseline
  profile's values. Run as `jmeter -q baseline.properties -t plan.jmx`.
- **Apportion per-flow thread counts from total users by `share_pct` using largest-remainder**, so
  the per-flow counts sum exactly to the total. Throughput is apportioned the same way. The Constant
  Throughput Timer is configured in **samples per minute** (`tps × 60`, `tpm × 1`, `tph ÷ 60`), with
  "calculate throughput based on" set to *all active threads in current thread group*.
- **Think time goes inside the Transaction Controller, and every controller carries an explicit
  `<boolProp name="TransactionController.includeTimers">false</boolProp>`.** Do not rely on the
  element default. JMeter timers are scoped, not sequential — a timer fires before every sampler in
  its scope, so timers emitted as siblings at thread-group level stack, and a 3-step flow with 3s
  think time would pause 9s before every request. Keeping the timer inside the controller scopes it
  to one sampler; `includeTimers=false` keeps the delay out of the transaction's elapsed time, so
  the p95 the SLA is judged on stays measurable.
- **When `auth.strategy == per_thread`**, auth moves inside each thread group and the token
  variable becomes `scope: thread`. No setUp group.
- **When `auth.refresh_required` is true**, warn loudly in the run summary and add a comment in
  the JMX. A refresh mechanism is out of scope for now.
- **Never emit Duration Assertions for SLA targets.** A per-sample duration assertion marks
  slow-but-successful responses as errors, corrupting the error rate and distorting the load
  profile exactly when the system is degrading. Write SLAs to a separate criteria file instead.
- **Transaction Controller names must be stable and sortable**:
  `{flow_id}_{step_index:02d}_{step_name_slug}`.
- Set connection and response timeouts, keep-alive, and `Content-Type` consistently on every
  sampler.

### 4.5 Validate — deterministic

Structural only: the file parses, `hashTree` elements pair correctly, and every `${var}` referenced
has a producing extractor or a defined variable. Report failures clearly.

---

## 5. Build order

Build a walking skeleton. Do not build stage by stage in the order shown above — M1 is where you will
discover the JMeter XML quirks that reshape the IR schema, and discovering them at M4 means
rewriting everything upstream.

**M1 — IR + emitter. No LLM, no Excel, no HTTP.**
Pydantic IR models. Two hand-written IR YAML fixtures: one flow with no correlations, and one flow
with a shared auth token plus one iteration-scoped extract. The emitter. Structural validation.
**Verify by opening the output in JMeter and running it at 1 thread. Do not proceed until a
generated script actually runs.**

**M2 — workbook parser.** Real spec file → IR. Correlations still hand-written in the fixture.
Gap reporting working end to end, including non-zero exit on blocking gaps.

**M3 — probe runner.** Traffic capture, record persisted to disk, `probe_safe` respected.

**M4 — correlation engine.** Candidate scan with both filters, then LLM adjudication. This is
where the tool stops being a template filler.

**M5 — CLI, config file, output layout, run summary.**

At every milestone the tool must run end to end. No half-wired stages.

---

## 6. Explicit non-goals

Do not build these. Do not scaffold them, stub them, or leave hooks for them. If you think one is
needed, ask first.

- **Azure Load Test integration, CI/CD pipeline files, GitHub Actions workflows, git or PR
  automation.** The tool writes `.jmx` files to a local output directory. That is the end of it.
- Any UI or browser-based testing. API only.
- Test result analysis, reporting, dashboards.
- Test data generation or CSV Data Set wiring. Where a spec field is parameterised, emit a named
  placeholder so a data set can be attached later — nothing more.
- **OpenAPI/Swagger pre-fill of the Flow steps sheet.** `API reference location` is recorded in the
  IR for reference and nothing reads it.
- Vector databases, embeddings, RAG. The inputs fit in context; retrieval would make the model's
  view of them lossy rather than better.
- Retry logic inside generated scripts.
- Per-sample SLA assertions.
- Token refresh mechanisms.
- A multi-agent framework. One LLM call site, with a schema-validated output.

---

## 7. Stack and conventions

- Python 3.11+
- `pydantic` v2 (IR), `openpyxl` (workbook), `httpx` (probe), `jinja2` + `lxml` (emission),
  `pyyaml`, `pytest`, `ruff`
- LLM access via the Claude Agent SDK
- Config in a YAML file at the repo root:

```yaml
llm:
  provider: claude-code
  model: ""            # blank = default
  temperature: 0.2
probe:
  enabled: true
  timeout_s: 30
secrets:
  provider: env
jmeter:
  version: "5.6.3"     # currently latest; update on upgrade — see note below
paths:
  specs: data/specs
  ir: data/ir
  probe_records: data/probe
  outputs: outputs
  logs: logs
```

- Outputs namespaced per application: `outputs/{application_name}/`
- Every stage writes its artifact to disk before the next reads it, and each stage is
  independently re-runnable from the previous stage's output.

### Secrets

The workbook contains only reference *names* (e.g. `perf-client-id`). The probe needs real values.

- With `provider: env`, resolve a reference name to an environment variable by uppercasing it and
  replacing non-alphanumeric characters with underscores: `perf-client-id` → `PERF_CLIENT_ID`.
- Support an optional `.env` file at the repo root via `python-dotenv`. **Add `.env` to
  `.gitignore` in the same commit that introduces the loader**, before any such file can exist.
- If a referenced secret is not set, fail with a message naming the exact environment variable
  expected. Never fall back to a default or an empty string.

### JMeter version

The target is whatever JMeter release is current; today that is 5.6.3. Element class names and
element structure differ across releases, so the emitter templates are version-sensitive. Keep the
version in config, and keep a single golden-file test that fails loudly if emitted output stops
matching the pinned version's expected structure — so an upgrade surfaces as a failing test rather
than as scripts that silently will not open.

### Hard constraints

- **No secret values are ever written to disk, into the IR, into logs, or into the JMX.** Only
  reference names. The JMX reads credentials via `${__env(...)}` or a property at run time.
- **The LLM never emits XML.**
- **The tool never invents a missing input value.**
- **Every extractor carries `confidence` and `evidence`.**

### Testing

- The emitter is unit-tested against IR fixtures with no LLM and no network.
- The workbook parser is tested against a deliberately mangled spec: inserted rows, renamed
  sections, reordered columns, missing required fields.
- The workbook parser is also tested against `sample_filled.xlsx`, whose `Value` column differs
  from its `Example` column on every free-text row — a parser reading the wrong column fails this
  fixture rather than passing by coincidence.
- The correlation filters are tested against a synthetic traffic record containing known
  false-positive bait (`"true"`, `"USD"`, `200`, an echoed client value).
- Golden-file tests on emitted JMX, compared structurally rather than by string equality.

---

## 8. Before you start

Confirm back to me:

1. Your understanding of the milestone plan.
2. Anything in the IR schema you think is wrong or missing.
3. Any assumption you had to make that this brief did not settle.

Then start with M1.
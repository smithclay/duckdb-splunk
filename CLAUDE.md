# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A DuckDB extension (`read_splunk_logs` table function + `splunk` secret type) that queries logs from
a Splunk instance's REST search API and returns rows in the flat 18-column `duckdb-otlp`
`read_otlp_logs` schema. It was ported from the sibling reference extension at
`~/workspace/duckdb-datadog` — when a pattern here is unclear, that repo is the canonical template
for extension structure, the secret pattern, retry/backoff, RAII yyjson helpers, and projection
pushdown.

## Build / test

Requires the git submodules (`duckdb`, `extension-ci-tools`) — `git submodule update --init --recursive`.

This repo builds against **system OpenSSL via Homebrew, not vcpkg** (vcpkg is declared in
`vcpkg.json` for CI but is not installed locally). You must pass `OPENSSL_ROOT_DIR` or the build
won't find OpenSSL:

```bash
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
make            # == make release; builds ./build/release/duckdb + the loadable extension (first build compiles DuckDB from source, ~10 min)
make test       # runs the offline SQL logic tests (test/sql/*.test); fully offline, no Splunk needed
```

Incremental rebuilds after editing `src/` are fast (~15s) since DuckDB itself is cached. There is no
"run a single test" flag for the SQL logic tests — there is one `.test` file (`test/sql/splunk.test`);
add cases to it. Its `require splunk` line loads the just-built loadable extension.

Artifacts: `./build/release/duckdb` (shell with extension preloaded),
`./build/release/extension/splunk/splunk.duckdb_extension`.

## End-to-end test (Docker)

`test/e2e/run_e2e.sh` runs the full round trip against a local Splunk container: HEC ingest of a
uniquely-marked event → search REST API → `read_splunk_logs` → assert OTLP mapping. It starts/reuses
the container via `test/e2e/start_splunk.sh` (or `docker compose up -d`). Two hard-won constraints
are baked into those scripts — **do not reintroduce**:

- **No `SPLUNK_LICENSE_URI=Free`.** The Splunk *Free* license disables the `Auth` feature, so the
  management/search REST API returns **HTTP 401** for every credentialed request. The scripts use
  the default 60-day Enterprise trial instead.
- **`--platform linux/amd64`.** Splunk publishes no arm64 image; on Apple Silicon it runs under
  emulation.

Local Splunk: UI `http://localhost:8000`, mgmt/search `https://localhost:8089` (self-signed →
`INSECURE_TLS true`), HEC `https://localhost:8088/services/collector/event`. Default creds
`admin` / `changeme12345`, HEC token `tero-dev-token`.

## Architecture

Four source files under `src/` (+ headers in `src/include/`):

- `splunk_extension.cpp` — entry point; registers the secret type and the table function.
- `splunk_secret.cpp` — the `splunk` KeyValueSecret (`URL`, `USERNAME`/`PASSWORD`, `TOKEN` +
  `TOKEN_TYPE`, `INSECURE_TLS`). `PASSWORD`/`TOKEN` are redacted. `GetSplunkCredentials` resolves a
  named secret or the first `splunk` secret, and validates auth at bind time.
- `splunk_client.cpp` — `SplunkClient`: one keep-alive httplib connection, `POST
  /services/search/v2/jobs/export` with a form-encoded body, and the retry loop (429/5xx/transport,
  exponential backoff, ~100ms-granular cancellation via `context.interrupted`). Auth goes only in
  the `Authorization` header (basic, `Bearer <jwt>`, or `Splunk <token>` per `TOKEN_TYPE`) — never
  the URL/argv.
- `logs_table.cpp` — the bulk. Request building, NDJSON response parsing, and the Splunk→OTLP mapping.

### The single most important thing to understand

**Splunk does not extract `_json`/HEC event fields at search time.** A search result's `_raw` holds
the entire JSON payload as a string; individual fields (`level`, `trace_id`, `service`, custom
fields) are *not* returned as top-level result fields unless the query explicitly references them.
So `MapEvent` **parses `_raw` as JSON** and treats its keys as an additional field source. Field
lookups resolve across `{ top-level extracted field, nested "fields" object, parsed _raw }` in that
priority order (`LookupStr`). Losing this behavior silently NULLs out severity/trace/service for
normal HEC data even though the E2E "returned a row".

### Other load-bearing details in `logs_table.cpp`

- **Output schema is exactly 18 columns** matching `read_otlp_logs`; `GetLogsSchema` and the `COL_*`
  indices must stay in sync (`D_ASSERT` guards the count). Attribute columns are VARCHAR JSON
  strings (flat table, not OTLP pdata maps) — a deliberate representational divergence from the
  collector. Resource-attribute *keys*, however, do align with the collector (`host.name` +
  `com.splunk.*`, see `kResourceKeys`) for interop.
- **Projection pushdown** (`function.projection_pushdown = true`): `MapEvent` only computes projected
  columns. `_raw` parse, severity lookup, and `_time` parse are each lazily **memoized** per row so a
  `count(*)` or `GROUP BY service_name` pays nothing for `log_attributes`/`_raw`.
- **Buffered one-shot fetch:** `FetchAll` issues a single export request and buffers the whole
  response + all mapped rows before emitting. `max_rows` is the only memory bound (0 = unlimited).
  There is no pagination/checkpointing (unlike the collector's `splunksearchapireceiver`).
- **Query normalization:** `NormalizeSearchQuery` prepends `search ` unless the query already starts
  with `search ` or a leading pipe (generating command like `| tstats`).
- **Error surfacing:** `ThrowIfSearchError` raises on export lines carrying a `messages` entry of
  type `ERROR`/`FATAL`, so a bad SPL query fails loudly instead of looking like zero matches.
- **`kResourceKeys` is the single source of truth** for which Splunk metadata becomes
  `resource_attributes`; `IsInternalField` consults it so those keys are excluded from
  `log_attributes` (no field is duplicated across both bags).

### Bind-time vs scan-time

Parameter validation (`max_rows >= 0`, `timeout >= 1`, `retries >= 0`, unknown params) and
credential/secret resolution happen in `SplunkLogsBind` — no network call. The first
`SplunkLogsScan` triggers the single `FetchAll`. `MaxThreads() == 1`.

## Dependencies

OpenSSL (TLS) via `find_package`. HTTP (cpp-httplib) and JSON (yyjson) reuse DuckDB's bundled copies
under `duckdb/third_party/` — nothing extra is pulled in. `CPPHTTPLIB_OPENSSL_SUPPORT` selects the
separately-namespaced `duckdb_httplib_openssl` build so symbols don't clash with core DuckDB's
non-SSL httplib.

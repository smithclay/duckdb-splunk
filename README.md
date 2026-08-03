# duckdb-splunk

A DuckDB extension that reads logs/events from a [Splunk](https://www.splunk.com/) instance
directly into DuckDB tables via the Splunk REST search API. Rows conform to the
[duckdb-otlp](https://github.com/smithclay/otlp2records) `read_otlp_logs` schema, so Splunk events
drop straight into an OTLP-shaped lakehouse alongside data from Datadog
([duckdb-datadog](https://github.com/smithclay/duckdb-datadog)) and other OTLP sources.

The extension supports a completely local end-to-end test using **Splunk Docker** — no Splunk Cloud
account required.

## Quick start (local Splunk Docker)

Start a local Splunk (first boot takes ~1–2 minutes):

```shell
docker compose up -d
# or: test/e2e/start_splunk.sh   (starts + waits until the management API is ready)
```

| Endpoint             | URL                                                    | Auth                          |
|----------------------|--------------------------------------------------------|-------------------------------|
| Web UI               | `http://localhost:8000`                                | `admin` / `changeme12345`     |
| Management/search    | `https://localhost:8089`                               | `admin` / `changeme12345`     |
| HEC ingest           | `https://localhost:8088/services/collector/event`      | HEC token `tero-dev-token`    |

The management port serves a **self-signed certificate**, so local usage needs `INSECURE_TLS true`.

> **License note:** the container runs on the default 60-day Splunk **Enterprise trial** license, not
> the Splunk *Free* license. The Free license disables the `Auth` feature, which makes the REST
> search API reject credentialed requests with HTTP 401 — so basic-auth search (the E2E path) would
> not work under Free. `docker-compose.yml` / `start_splunk.sh` therefore deliberately omit
> `SPLUNK_LICENSE_URI=Free`.

```sql
LOAD splunk;

-- Store Splunk credentials once (kept out of query text; PASSWORD/TOKEN redacted in duckdb_secrets()).
CREATE SECRET splunk_local (
    TYPE splunk,
    URL 'https://localhost:8089',
    USERNAME 'admin',
    PASSWORD 'changeme12345',
    INSECURE_TLS true          -- required for the self-signed local Docker cert
);

-- Read a window of events into a table.
CREATE TABLE logs AS
SELECT * FROM read_splunk_logs(
    query    => 'index=main service=checkout error',
    earliest => '-15m',
    latest   => 'now',
    max_rows => 1000
);
```

## Splunk catalog

Attach a Splunk instance as a read-only DuckDB catalog to query each index as a table in its
`logs` schema:

```sql
LOAD splunk;

CREATE SECRET splunk_prod (
    TYPE splunk,
    URL 'https://splunk.example.com:8089',
    TOKEN '<token>'
);

ATTACH 'splunk:' AS sp (
    TYPE splunk,
    SECRET 'splunk_prod'
);

SELECT * FROM sp.logs.main LIMIT 10;

-- Index names are preserved exactly; quote names that are not plain SQL identifiers.
SELECT * FROM sp.logs."security-events" LIMIT 10;
```

Without `INDEXES`, `ATTACH` calls Splunk's `GET /services/data/indexes` endpoint once and caches the
indexes visible to the selected credential for the lifetime of the attachment. If the endpoint is
unavailable—for example, because the role cannot list indexes or the Splunk deployment does not
expose it—supply the index names explicitly:

```sql
ATTACH 'splunk:' AS sp (
    TYPE splunk,
    SECRET 'splunk_prod',
    INDEXES ['main', 'security-events']
);
```

When `INDEXES` is present, attachment makes no network request. Duplicate names are ignored while
input order and spelling are preserved. Omitting `SECRET` uses the same first in-scope `splunk`
secret selection as `read_splunk_logs`.

Every catalog table has the same 18-column schema as `read_splunk_logs` and searches exactly one
index over the reader's default window, `earliest = '-15m'` through `latest = 'now'`. The catalog is
read-only. Use `read_splunk_logs` when you need custom SPL, a different time window, a row cap,
retry budget, or timeout.

## Credentials (`CREATE SECRET`)

Two auth styles are supported. Either `TOKEN`, or `USERNAME` + `PASSWORD`, is required.

Basic auth (the must-have path, used by the Docker E2E):

```sql
CREATE SECRET splunk_local (
    TYPE splunk,
    URL 'https://localhost:8089',
    USERNAME 'admin',
    PASSWORD 'changeme12345',
    INSECURE_TLS true
);
```

Token auth (a Splunk authentication token). `TOKEN_TYPE` selects the HTTP scheme: `Bearer` (the
default; for JWT authentication tokens) or `Splunk` (for the older authtoken / session-key scheme):

```sql
CREATE SECRET splunk_token (
    TYPE splunk,
    URL 'https://my-splunk.example.com:8089',
    TOKEN '<token>',
    TOKEN_TYPE 'Bearer',   -- or 'Splunk'
    INSECURE_TLS false
);
```

| Secret field   | Required                    | Default                    | Notes                                        |
|----------------|-----------------------------|----------------------------|----------------------------------------------|
| `URL`          | no                          | `https://localhost:8089`   | Management/search API base (no trailing path).|
| `USERNAME`     | with `PASSWORD`             | —                          | Basic auth.                                  |
| `PASSWORD`     | with `USERNAME`             | —                          | **Redacted** in `duckdb_secrets()`.          |
| `TOKEN`        | or `USERNAME`+`PASSWORD`    | —                          | Takes precedence over basic auth. **Redacted**.|
| `TOKEN_TYPE`   | no                          | `Bearer`                   | `Bearer` → `Authorization: Bearer <token>`; `Splunk` → `Authorization: Splunk <token>`.|
| `INSECURE_TLS` | no                          | `false`                    | `true` disables TLS verification (self-signed).|

- With a named `secret => 'splunk_local'` parameter, that specific secret is used.
- With no `secret` parameter, the first secret of type `splunk` is used.

## `read_splunk_logs`

```sql
SELECT * FROM read_splunk_logs(
    query    => 'index=main service=checkout error',
    earliest => '-15m',
    latest   => 'now',
    max_rows => 1000
);
```

The function queries `POST /services/search/v2/jobs/export` on the management port with
form-encoded parameters (`search`, `earliest_time`, `latest_time`, `output_mode=json`) and parses
the newline-delimited JSON export stream. Credentials travel in the `Authorization` header, never
in the query string.

### Parameters

| Parameter  | Type    | Default              | Description |
|------------|---------|----------------------|-------------|
| `query`    | VARCHAR | `*`                  | Splunk search body. `search ` is prepended automatically unless the query already starts with `search ` or a leading pipe (`\| tstats ...`). |
| `earliest` | VARCHAR | `-15m`               | Splunk earliest time (`-15m`, `-1h`, ISO-ish values Splunk accepts). |
| `latest`   | VARCHAR | `now`                | Splunk latest time. |
| `max_rows` | BIGINT  | `0` (unlimited)      | Caps rows returned; also sent as the export `count`. Must be `>= 0`. |
| `timeout`  | BIGINT  | `60`                 | Per-request connection/read timeout, in seconds. Must be `>= 1`. |
| `retries`  | BIGINT  | `4`                  | Retry budget for transient failures (HTTP 429/5xx, network errors); 0 disables retrying. Must be `>= 0`. |
| `secret`   | VARCHAR | first `splunk` secret| Name of a specific secret to use. |

Transient failures are retried automatically: HTTP 429 waits out the server-advised `Retry-After`,
and HTTP 5xx or dropped connections retry with exponential backoff. Retry waits honor query
cancellation, so interrupting a query (Ctrl+C) takes effect within ~100ms. TLS verification
failures are never retried. Only the columns a query actually selects are decoded from the response
(projection pushdown): a `count(*)` or `GROUP BY service_name` never pays the per-row
`log_attributes` JSON serialization.

### Output schema

Matches duckdb-otlp `read_otlp_logs` (18 columns):

| Column | Type | Splunk source |
|--------|------|---------------|
| `time_unix_nano` | TIMESTAMP_NS | `_time` |
| `observed_time_unix_nano` | TIMESTAMP_NS | `_time` |
| `trace_id` | VARCHAR | `trace_id` |
| `span_id` | VARCHAR | `span_id` |
| `service_name` | VARCHAR | `service`, `service_name`, or `fields.service` |
| `service_namespace` | VARCHAR | (null) |
| `service_instance_id` | VARCHAR | (null) |
| `severity_number` | INTEGER | mapped from severity text |
| `severity_text` | VARCHAR | `level`, `severity`, `status`, or `fields.level` |
| `event_name` | VARCHAR | (null) |
| `body` | VARCHAR | `_raw` or `message` |
| `resource_attributes` | VARCHAR (JSON) | `host`→`host.name`, `source`→`com.splunk.source`, `sourcetype`→`com.splunk.sourcetype`, `index`→`com.splunk.index`, `splunk_server`→`com.splunk.server` |
| `scope_name` | VARCHAR | (null) |
| `scope_version` | VARCHAR | (null) |
| `scope_attributes` | VARCHAR | (null) |
| `log_attributes` | VARCHAR (JSON) | remaining (non-internal) event fields |
| `dropped_attributes_count` | INTEGER | (null) |
| `flags` | INTEGER | (null) |

Severity text → `severity_number` (OTLP): `trace`→1, `debug`→5, `info`/`notice`/`ok`→9,
`warn`/`warning`→13, `error`/`err`→17, `critical`/`crit`/`alert`/`emergency`/`fatal`→21,
unknown/missing→0.

Resource-attribute keys follow the OpenTelemetry Collector's Splunk conventions (`host.name` plus
`com.splunk.*`, matching `splunkhecreceiver`'s `hec_metadata_to_otel_attrs` defaults), so these rows
interoperate with collector-produced OTLP data. Because attribute columns are JSON strings, query
them with DuckDB's JSON functions, e.g. `SELECT resource_attributes->>'$."com.splunk.index"' FROM
logs` or `SELECT log_attributes->>'$.marker' FROM logs`.

The parser is defensive about Splunk's export JSON shapes: it handles per-line
`{"result": {...}}` objects, a buffered `{"results": [...]}` array, and flat event objects, and
tolerates missing optional fields.

## DuckDB-WASM (browser)

The extension builds for WASM with `make wasm_mvp`, `make wasm_eh`, or `make wasm_threads`, using
`extension_config_wasm.cmake`. Browser builds use DuckDB-WASM's fetch-backed HTTP transport and do
not link OpenSSL or native sockets. Both token and username/password authentication are supported.

Splunk deployments commonly do not allow cross-origin browser requests. In that case, point `URL`
at a same-origin or CORS-enabled proxy route; the extension preserves its path prefix before adding
`/services/...`:

```sql
CREATE SECRET splunk_browser (
    TYPE splunk,
    URL 'https://your-app.example.com/api/splunk',
    TOKEN '<token>',
    TOKEN_TYPE 'Bearer'
);
```

The proxy must forward the path and query string to the Splunk management API, permit the
`Authorization` and `Content-Type` request headers, and answer `OPTIONS` preflight for `GET` and
`POST`. Browser fetch owns TLS verification, cancellation, and retry behavior, so `INSECURE_TLS`
has no effect in a WASM build. The browser transport currently exposes the completed response body;
rows are decoded incrementally from that body rather than being materialized into a second full
in-memory row set. Native builds stream from the response socket with a bounded two-vector buffer.

## Building

Native dependencies are minimal: only OpenSSL (via vcpkg). HTTP (cpp-httplib) and JSON (yyjson)
reuse the copies DuckDB already bundles. WASM builds use DuckDB's browser HTTP transport and do not
install OpenSSL.

```shell
git submodule update --init --recursive   # duckdb + extension-ci-tools

# vcpkg provides OpenSSL
git clone https://github.com/Microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake

make            # builds ./build/release/duckdb and the loadable extension
make test       # runs the offline SQL tests in test/sql/
```

Built artifacts:
- `./build/release/duckdb` — DuckDB shell with the extension preloaded.
- `./build/release/extension/splunk/splunk.duckdb_extension` — the loadable binary.

## Testing

### Offline SQL tests

`make test` runs `test/sql/splunk.test`, which covers extension loading, the `splunk` secret type
(including PASSWORD/TOKEN redaction), function registration, the 18-column OTLP output schema, and
bind-time parameter validation. These tests are **fully offline** — no running Splunk container is
needed.

### End-to-end test

`test/e2e/run_e2e.sh` exercises the full round trip against a real (local, Dockerized) Splunk:

```shell
make release                 # build the duckdb binary + extension first
test/e2e/run_e2e.sh          # starts/reuses Splunk Docker, ingests, reads back, asserts
```

It:
1. Ensures the DuckDB binary exists.
2. Starts (or reuses) the local Splunk Docker container and waits until the management API is ready.
3. Ingests one uniquely-marked event through the HEC.
4. Polls `read_splunk_logs` until the marker is searchable (default timeout 150s, configurable via
   `POLL_TIMEOUT`).
5. Asserts the table function returns ≥1 correctly mapped 18-column OTLP row.
6. Attaches the same secret with `INDEXES ['main']` and verifies `sp.logs.main` returns the same
   indexed event through the catalog interface.

Configuration is via environment variables (all optional; see the header of `run_e2e.sh`):
`SPLUNK_URL`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`, `SPLUNK_HEC_TOKEN`, `SPLUNK_INSECURE_TLS`,
`DUCKDB_BIN`, `POLL_TIMEOUT`, `POLL_INTERVAL`.

## Splunk Docker vs Splunk Cloud

- **Docker (local):** self-signed cert on the management port → use `INSECURE_TLS true`. Basic auth
  (`admin` / `changeme12345`) is the simplest path. Default single-node, `index=main`.
- **Cloud / production:** use a verified TLS endpoint (`INSECURE_TLS false`, the default) and prefer
  a Splunk **authentication token** (`TOKEN`) over embedding a password. The management/search API
  may sit behind a different host/port (e.g. `https://<stack>.splunkcloud.com:8089`) or require
  allow-listing; confirm the search REST endpoint is reachable.

## Security notes

- **TLS:** local Docker uses `INSECURE_TLS true` only because of its self-signed cert. Production
  users should keep TLS verification on (the default `INSECURE_TLS false`).
- **Secrets are redacted:** `PASSWORD` and `TOKEN` never appear in `duckdb_secrets()` / `SHOW
  SECRETS`, and are sent only in the HTTP `Authorization` header — never in the URL, query string,
  or error messages.
- **Command line hygiene:** the E2E script keeps the HEC token and DuckDB secret out of process
  arguments by using 600-mode temp files.
- **Always set time bounds:** pass `earliest`/`latest` (and consider `max_rows`) to keep searches
  bounded rather than scanning an entire index.

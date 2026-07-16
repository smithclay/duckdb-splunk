#!/usr/bin/env bash
#
# End-to-end test for the duckdb-splunk extension.
#
# It proves the full round trip against a real (local, Dockerized) Splunk:
#   build -> HEC ingest of a uniquely-marked event -> Splunk search REST API -> read_splunk_logs
#   and the attached Splunk catalog -> OTLP-shaped DuckDB rows.
#
# The script starts (or reuses) a local Splunk Docker container, sends one uniquely-tagged event
# via the HTTP Event Collector, then reads it back through read_splunk_logs() and sp.logs.main and
# asserts the round-trip worked and both interfaces are OTLP-shaped. Because Splunk indexing has
# latency, it polls.
#
# Configuration comes from the environment (all optional; defaults target local Splunk Docker):
#   SPLUNK_URL           management/search API URL      (default: https://localhost:8089)
#   SPLUNK_USERNAME      basic-auth username            (default: admin)
#   SPLUNK_PASSWORD      basic-auth password            (default: changeme12345)
#   SPLUNK_HEC_TOKEN     HEC ingest token               (default: tero-dev-token)
#   SPLUNK_HEC_URL       HEC ingest endpoint            (default: https://localhost:8088/services/collector/event)
#   SPLUNK_INSECURE_TLS  skip TLS verification          (default: true, for the self-signed cert)
#
#   DUCKDB_BIN       path to the duckdb shell (default: ./build/release/duckdb)
#   POLL_TIMEOUT     seconds to wait for the event to become searchable (default: 150)
#   POLL_INTERVAL    seconds between polls (default: 10)
#   START_SPLUNK     set to 0 to skip auto-starting the container (default: 1)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_DIR}"

DUCKDB_BIN="${DUCKDB_BIN:-./build/release/duckdb}"
SPLUNK_URL="${SPLUNK_URL:-https://localhost:8089}"
SPLUNK_USERNAME="${SPLUNK_USERNAME:-admin}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-changeme12345}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-tero-dev-token}"
SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-https://localhost:8088/services/collector/event}"
SPLUNK_INSECURE_TLS="${SPLUNK_INSECURE_TLS:-true}"
POLL_TIMEOUT="${POLL_TIMEOUT:-150}"
POLL_INTERVAL="${POLL_INTERVAL:-10}"
START_SPLUNK="${START_SPLUNK:-1}"

log()  { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[e2e] PASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[e2e] FAIL\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
command -v curl >/dev/null 2>&1 || fail "curl is required"
[ -x "${DUCKDB_BIN}" ] || fail "duckdb binary not found/executable at '${DUCKDB_BIN}' (run 'make release' first, or set DUCKDB_BIN)"

# Secret-bearing temp files (curl header config, duckdb SQL) are removed on exit.
CURL_CFG=""
SQL_FILE=""
cleanup() {
	rm -f "${CURL_CFG}" "${SQL_FILE}" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Ensure Splunk is running and ready
# ---------------------------------------------------------------------------
if [ "${START_SPLUNK}" = "1" ]; then
	log "Ensuring local Splunk Docker is up..."
	SPLUNK_PASSWORD="${SPLUNK_PASSWORD}" SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN}" SPLUNK_MGMT_URL="${SPLUNK_URL}" \
		"${SCRIPT_DIR}/start_splunk.sh"
else
	log "START_SPLUNK=0; assuming Splunk is already running at ${SPLUNK_URL}"
fi

# ---------------------------------------------------------------------------
# 2. Send a uniquely-marked event via the Splunk HTTP Event Collector (HEC)
# ---------------------------------------------------------------------------
MARKER="duckdbe2e-$(date +%s)-${RANDOM}"

# Keep the HEC token off curl's argv (visible in ps) by passing it via a 600-mode config file.
CURL_CFG="$(mktemp -t duckdb_splunk_e2e.XXXXXX.curl)"
chmod 600 "${CURL_CFG}"
printf 'header = "Authorization: Splunk %s"\n' "${SPLUNK_HEC_TOKEN}" > "${CURL_CFG}"

log "Sending test event with marker '${MARKER}' to ${SPLUNK_HEC_URL}"
hec_payload=$(cat <<JSON
{
  "event": {
    "message": "duckdb-splunk e2e test ${MARKER}",
    "service": "duckdb-splunk-e2e",
    "level": "error",
    "marker": "${MARKER}",
    "trace_id": "abc123",
    "span_id": "def456"
  },
  "sourcetype": "_json",
  "index": "main"
}
JSON
)

hec_status=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "${SPLUNK_HEC_URL}" \
	-K "${CURL_CFG}" \
	-H "Content-Type: application/json" \
	-d "${hec_payload}")
if [ "${hec_status}" != "200" ]; then
	fail "HEC ingest returned HTTP ${hec_status} (expected 200); check the HEC token and that HEC is enabled"
fi
ok "event accepted by HEC (HTTP ${hec_status})"

# ---------------------------------------------------------------------------
# 3. Read it back through the extension, polling until it is searchable
# ---------------------------------------------------------------------------
# A unique full-text marker phrase is the most reliable match regardless of field extraction.
SPLUNK_QUERY="index=main \"${MARKER}\""

# A temp SQL file keeps the secret off the process command line (removed by cleanup trap).
SQL_FILE="$(mktemp -t duckdb_splunk_e2e.XXXXXX.sql)"
chmod 600 "${SQL_FILE}"

# The credentials live in one place; both the poll and the assertion query reuse this.
SECRET_SQL="CREATE OR REPLACE SECRET splunk_e2e (TYPE splunk, URL '${SPLUNK_URL}', USERNAME '${SPLUNK_USERNAME}', PASSWORD '${SPLUNK_PASSWORD}', INSECURE_TLS ${SPLUNK_INSECURE_TLS});"

run_duckdb_scalar() { # $1 = SQL producing a single value
	# `.output /dev/null` around CREATE SECRET suppresses its `Success = true` result row, which
	# would otherwise be prepended to (and corrupt) the scalar value we read back.
	cat > "${SQL_FILE}" <<SQL
.output /dev/null
${SECRET_SQL}
.output
$1
SQL
	"${DUCKDB_BIN}" -unsigned -noheader -list -init /dev/null < "${SQL_FILE}"
}

count_sql="SELECT count(*) FROM read_splunk_logs(query => '${SPLUNK_QUERY}', earliest => '-15m', latest => 'now');"

log "Polling read_splunk_logs for the event (timeout ${POLL_TIMEOUT}s)..."
elapsed=0
found=0
while [ "${elapsed}" -lt "${POLL_TIMEOUT}" ]; do
	# `|| true` so a transient duckdb/API error during polling doesn't abort the run under set -e.
	count="$(run_duckdb_scalar "${count_sql}" 2>/dev/null | tr -d '[:space:]')" || true
	if [[ "${count}" =~ ^[0-9]+$ ]] && [ "${count}" -ge 1 ]; then
		found=1
		break
	fi
	log "  not indexed yet (matches=${count:-0}); retrying in ${POLL_INTERVAL}s (${elapsed}/${POLL_TIMEOUT}s)"
	sleep "${POLL_INTERVAL}"
	elapsed=$((elapsed + POLL_INTERVAL))
done
[ "${found}" -eq 1 ] || fail "event with marker '${MARKER}' never became searchable within ${POLL_TIMEOUT}s"
ok "read_splunk_logs returned the event (matches=${count})"

# ---------------------------------------------------------------------------
# 4. Assert the row is OTLP-shaped and mapped correctly
# ---------------------------------------------------------------------------
# Materialize the matching rows once into a temp table, then run every assertion against that local
# table (one scan keeps the test simple and light on the search API).
cat > "${SQL_FILE}" <<SQL
.output /dev/null
${SECRET_SQL}
CREATE TEMP TABLE e2e_rows AS
    SELECT * FROM read_splunk_logs(query => '${SPLUNK_QUERY}', earliest => '-15m', latest => 'now');
ATTACH 'splunk:' AS sp (TYPE splunk, SECRET 'splunk_e2e', INDEXES ['main']);
CREATE TEMP TABLE e2e_catalog_rows AS
    SELECT * FROM sp.logs.main WHERE body LIKE '%${MARKER}%';
.output
SELECT (SELECT count(*) FROM (DESCRIBE e2e_rows))::VARCHAR || '|' ||
  (SELECT (count(*) >= 1
    AND bool_and(service_name = 'duckdb-splunk-e2e')
    AND bool_and(severity_text = 'error')
    AND bool_and(severity_number = 17)
    AND bool_and(body LIKE '%${MARKER}%')
    AND bool_and(time_unix_nano IS NOT NULL)
    AND bool_and(log_attributes LIKE '%${MARKER}%')
    AND bool_and(log_attributes LIKE '%abc123%')) FROM e2e_rows)::VARCHAR || '|' ||
  (SELECT (count(*) >= 1
    AND bool_and(service_name = 'duckdb-splunk-e2e')
    AND bool_and(severity_number = 17)
    AND bool_and(body LIKE '%${MARKER}%')) FROM e2e_catalog_rows)::VARCHAR;
.print ---SAMPLE---
SELECT time_unix_nano, service_name, severity_text, severity_number, body FROM e2e_rows LIMIT 1;
.print ---LOGATTRS---
SELECT log_attributes FROM e2e_rows LIMIT 1;
SQL
assert_out="$("${DUCKDB_BIN}" -unsigned -noheader -list -init /dev/null < "${SQL_FILE}")"

summary_line="$(printf '%s\n' "${assert_out}" | head -n1 | tr -d '[:space:]')"
column_count="${summary_line%%|*}"
remaining="${summary_line#*|}"
checks="${remaining%%|*}"
catalog_checks="${summary_line##*|}"

[ "${column_count}" = "18" ] || fail "expected 18 OTLP columns, got '${column_count}'"
ok "output schema has the 18 OTLP columns"
[ "${checks}" = "true" ] || fail "row content assertions failed (got '${checks}')"
ok "row content maps correctly (service_name, severity error->17, body, timestamp, log_attributes)"
[ "${catalog_checks}" = "true" ] || fail "catalog row content assertions failed (got '${catalog_checks}')"
ok "sp.logs.main returns the same indexed event through the catalog interface"

log "Sample row:"
printf '%s\n' "${assert_out}" | sed -n '/---SAMPLE---/,/---LOGATTRS---/p' | sed '1d;$d'
log "log_attributes:"
printf '%s\n' "${assert_out}" | sed -n '/---LOGATTRS---/,$p' | tail -n +2

ok "end-to-end test succeeded"

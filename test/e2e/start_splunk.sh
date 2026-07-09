#!/usr/bin/env bash
#
# Start (or reuse) a local Splunk container for duckdb-splunk development and E2E tests, then wait
# until its management API is ready.
#
# It reuses a running `splunk` container if one is already up, restarts a stopped one, and otherwise
# launches a fresh container. Idempotent: safe to run repeatedly.
#
# Environment overrides:
#   SPLUNK_CONTAINER   container name (default: splunk)
#   SPLUNK_IMAGE       image (default: splunk/splunk:latest)
#   SPLUNK_PASSWORD    admin password (default: changeme12345)
#   SPLUNK_HEC_TOKEN   HEC token (default: tero-dev-token)
#   SPLUNK_MGMT_URL    management API URL (default: https://localhost:8089)
#   READY_TIMEOUT      seconds to wait for the management API (default: 240)

set -euo pipefail

SPLUNK_CONTAINER="${SPLUNK_CONTAINER:-splunk}"
SPLUNK_IMAGE="${SPLUNK_IMAGE:-splunk/splunk:latest}"
# Splunk only publishes linux/amd64 images; on Apple Silicon / arm64 this runs under emulation.
SPLUNK_PLATFORM="${SPLUNK_PLATFORM:-linux/amd64}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-changeme12345}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-tero-dev-token}"
SPLUNK_MGMT_URL="${SPLUNK_MGMT_URL:-https://localhost:8089}"
READY_TIMEOUT="${READY_TIMEOUT:-240}"

log()  { printf '\033[1;34m[splunk]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[splunk] ERROR\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker is required"

# Reuse or (re)start the container.
if docker ps --format '{{.Names}}' | grep -qx "${SPLUNK_CONTAINER}"; then
	log "container '${SPLUNK_CONTAINER}' already running; reusing it"
elif docker ps -a --format '{{.Names}}' | grep -qx "${SPLUNK_CONTAINER}"; then
	log "starting existing stopped container '${SPLUNK_CONTAINER}'"
	docker start "${SPLUNK_CONTAINER}" >/dev/null
else
	log "launching new Splunk container '${SPLUNK_CONTAINER}' from ${SPLUNK_IMAGE} (platform ${SPLUNK_PLATFORM})"
	# NOTE: we deliberately do NOT set SPLUNK_LICENSE_URI=Free. The Splunk *Free* license disables
	# the "Auth" feature, which makes the management/search REST API reject all credentialed requests
	# with HTTP 401 — breaking basic-auth search. Omitting it uses the default 60-day Enterprise
	# trial, which has authentication enabled (the E2E must-have path).
	docker run -d \
		--name "${SPLUNK_CONTAINER}" \
		--platform "${SPLUNK_PLATFORM}" \
		-p 8000:8000 \
		-p 8088:8088 \
		-p 8089:8089 \
		-e "SPLUNK_START_ARGS=--accept-license" \
		-e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
		-e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
		-e "SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}" \
		"${SPLUNK_IMAGE}" >/dev/null
fi

# Wait for the management API to accept authenticated requests (Splunk first-boot takes a while).
log "waiting for management API at ${SPLUNK_MGMT_URL} (timeout ${READY_TIMEOUT}s)..."
elapsed=0
until curl -skf -u "admin:${SPLUNK_PASSWORD}" "${SPLUNK_MGMT_URL}/services/server/info?output_mode=json" >/dev/null 2>&1; do
	if [ "${elapsed}" -ge "${READY_TIMEOUT}" ]; then
		fail "Splunk management API not ready after ${READY_TIMEOUT}s (check: docker logs ${SPLUNK_CONTAINER})"
	fi
	sleep 5
	elapsed=$((elapsed + 5))
	printf '\033[1;34m[splunk]\033[0m   still waiting (%ss/%ss)\n' "${elapsed}" "${READY_TIMEOUT}"
done

log "Splunk is ready."
log "  UI:         http://localhost:8000  (admin / ${SPLUNK_PASSWORD})"
log "  Management:  ${SPLUNK_MGMT_URL}"
log "  HEC:         https://localhost:8088/services/collector/event  (token ${SPLUNK_HEC_TOKEN})"

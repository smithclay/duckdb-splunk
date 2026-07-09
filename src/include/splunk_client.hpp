#pragma once

#include "duckdb.hpp"

//! Forward-declared so the (large) httplib header stays out of this public header. The namespace
//! name matches cpp-httplib's OpenSSL build, which CMake selects globally via CPPHTTPLIB_OPENSSL_SUPPORT.
namespace duckdb_httplib_openssl {
class Client;
}

namespace duckdb {
class ClientContext;

//! Minimal client for the Splunk REST search API (POST /services/search/v2/jobs/export). It knows
//! how to authenticate (basic auth or token) and POST a form-encoded export search; parsing the
//! newline-delimited JSON response and mapping it to OTLP lives in the table function. A single
//! keep-alive connection is reused across calls.
struct SplunkClient {
	//! Management/search API base, e.g. "https://localhost:8089". Requests go to <url>/services/...
	string url = "https://localhost:8089";
	string username;
	string password;
	//! Splunk authentication token. When set, basic auth is not used; the token is sent per
	//! `token_type`.
	string token;
	//! Auth scheme for `token`: "Bearer" (JWT auth tokens) or "Splunk" (authtoken/session key).
	//! Case-insensitive; defaults to "Bearer".
	string token_type = "Bearer";
	//! Skip TLS certificate/hostname verification (self-signed local Splunk Docker).
	bool insecure_tls = false;
	//! Per-request connection/read timeout.
	uint64_t timeout_seconds = 60;
	//! Retry budget for transient failures: HTTP 429, HTTP 5xx, and transport errors (connection
	//! reset, timeout) share this budget with exponential backoff. 0 disables retrying.
	//! Non-transient failures (4xx other than 429, TLS certificate verification) are never retried.
	uint64_t retries = 4;

	// Owns a live keep-alive connection (the unique_ptr below), so the type is non-copyable. It is
	// only ever default-constructed in place inside the table function's bind data. The constructor
	// and destructor are declared here and defined out-of-line so the unique_ptr may hold a
	// forward-declared (incomplete) Client; both must live where Client is complete.
	SplunkClient();
	~SplunkClient();

	//! POST a form-encoded export search and return the raw (newline-delimited JSON) response body.
	//! `form_body` is the already-URL-encoded application/x-www-form-urlencoded request body.
	//! Transparently retries transient failures (429 / 5xx / transport errors) up to `retries`
	//! times, sleeping in small slices so query interrupts (Ctrl+C) cancel the wait promptly.
	//! Throws IOException when retries are exhausted or the failure is not transient, and
	//! InterruptException if the query was cancelled.
	string ExportSearch(ClientContext &context, const string &form_body) const;

private:
	//! Lazily created on first use and reused (HTTP keep-alive). Mutable because ExportSearch is
	//! const — it runs against the const bind data shared by all scans — yet must cache the socket.
	//! Reset (and re-established) after a transport error, since the failure may have left the
	//! pooled socket broken.
	mutable unique_ptr<duckdb_httplib_openssl::Client> connection;

	//! Return the shared connection, creating and configuring it (auth, TLS, timeouts) on the first
	//! call.
	duckdb_httplib_openssl::Client &GetConnection() const;
};

} // namespace duckdb

#pragma once

#include "duckdb.hpp"

#include <functional>

#ifndef __EMSCRIPTEN__
#include <mutex>

//! Forward-declared so the (large) httplib header stays out of this public header. The namespace
//! name matches cpp-httplib's OpenSSL build, which CMake selects globally via CPPHTTPLIB_OPENSSL_SUPPORT.
namespace duckdb_httplib_openssl {
class Client;
}
#endif

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

	//! Copy configuration (not a live connection) into `target`.
	void CopyConfigTo(SplunkClient &target) const;

	//! POST a form-encoded export search and pass response bytes to `on_chunk` as they arrive. Native
	//! builds stream directly from the socket; browser builds use DuckDB-WASM's fetch-backed HTTPUtil
	//! and deliver its completed body as one chunk. Returning false cancels the request.
	void ExportSearch(ClientContext &context, const string &form_body,
	                  const std::function<bool(const char *, idx_t)> &on_chunk) const;

	//! Stop an in-flight native request. A no-op in browser builds.
	void Cancel() const;

	//! GET the indexes visible to the authenticated user as a JSON collection.
	string ListIndexes(ClientContext &context) const;

private:
#ifndef __EMSCRIPTEN__
	//! Lazily created on first use and reused (HTTP keep-alive). Mutable because ExportSearch is
	//! const — it runs against the const bind data shared by all scans — yet must cache the socket.
	//! Reset (and re-established) after a transport error, since the failure may have left the
	//! pooled socket broken.
	mutable unique_ptr<duckdb_httplib_openssl::Client> connection;
	mutable std::mutex connection_mutex;

	//! Return the shared connection, creating and configuring it (auth, TLS, timeouts) on the first
	//! call.
	duckdb_httplib_openssl::Client &GetConnection() const;
#endif

	//! Execute an authenticated GET or form POST with the shared retry policy.
	string AuthenticatedRequest(ClientContext &context, const string &path, const string *form_body,
	                            bool index_discovery) const;
};

} // namespace duckdb

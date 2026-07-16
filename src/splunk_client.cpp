#include "splunk_client.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"

#include <chrono>
#include <thread>

// Use DuckDB's bundled cpp-httplib. Defining CPPHTTPLIB_OPENSSL_SUPPORT (see CMakeLists) both
// enables TLS and selects the `duckdb_httplib_openssl` namespace, so these symbols never collide
// with core DuckDB's non-SSL `duckdb_httplib` build.
#include "httplib.hpp"

namespace duckdb {

//! Strip a trailing '/' (and surrounding whitespace) from the configured URL so paths like
//! "/services/..." always join cleanly. httplib's Client wants scheme+host+port with no path.
static string NormalizeUrl(const string &raw) {
	string s = raw;
	StringUtil::Trim(s);
	while (!s.empty() && s.back() == '/') {
		s.pop_back();
	}
	return s.empty() ? "https://localhost:8089" : s;
}

// Defined here, where `Client` is complete, so the header's unique_ptr<Client> member can point at
// a forward-declared type. The destructor uses an empty body rather than `= default` to keep
// clang-tidy's performance-trivially-destructible check quiet.
SplunkClient::SplunkClient() = default;
SplunkClient::~SplunkClient() {
}

duckdb_httplib_openssl::Client &SplunkClient::GetConnection() const {
	if (!connection) {
		connection = make_uniq<duckdb_httplib_openssl::Client>(NormalizeUrl(url));
		connection->set_connection_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_read_timeout(static_cast<time_t>(timeout_seconds), 0);
		// Keep the socket open between requests so successive scans reuse one TCP+TLS connection.
		connection->set_keep_alive(true);

		// Token auth takes precedence over basic auth. Credentials go in the Authorization header,
		// never the URL/argv. Splunk accepts two token schemes: "Bearer <jwt>" for authentication
		// tokens and "Splunk <token>" for the older authtoken/session-key scheme.
		if (!token.empty()) {
			if (StringUtil::CIEquals(token_type, "Splunk")) {
				connection->set_default_headers({{"Authorization", "Splunk " + token}});
			} else {
				connection->set_bearer_token_auth(token);
			}
		} else if (!username.empty()) {
			connection->set_basic_auth(username, password);
		}

		// Local Splunk Docker ships a self-signed cert; insecure_tls disables verification for it.
		// Default (false) keeps full certificate + hostname verification.
		if (insecure_tls) {
			connection->enable_server_certificate_verification(false);
			connection->enable_server_hostname_verification(false);
		}
	}
	return *connection;
}

//! Sleep for `seconds`, polling the query's interrupt flag so a cancelled query (Ctrl+C) aborts
//! the wait within ~100ms instead of blocking a scan thread for the full retry delay.
static void SleepCheckingInterrupt(ClientContext &context, uint64_t seconds) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	while (std::chrono::steady_clock::now() < deadline) {
		if (context.interrupted) {
			throw InterruptException();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

//! TLS certificate/hostname failures are configuration or security problems — retrying cannot
//! succeed and would only delay (or worse, mask) the real error.
static bool IsRetryableTransportError(duckdb_httplib_openssl::Error error) {
	switch (error) {
	case duckdb_httplib_openssl::Error::SSLLoadingCerts:
	case duckdb_httplib_openssl::Error::SSLServerVerification:
	case duckdb_httplib_openssl::Error::SSLServerHostnameVerification:
		return false;
	default:
		return true;
	}
}

//! Seconds to wait before retrying a 429, based on the server's advice (Retry-After), else
//! exponential backoff. Clamped to [1, 60] so a stray/huge header value can't stall the query.
static uint64_t RateLimitRetryDelaySeconds(const duckdb_httplib_openssl::Response &response, uint64_t attempt) {
	if (response.has_header("Retry-After")) {
		try {
			long long secs = std::stoll(response.get_header_value("Retry-After"));
			if (secs < 0) {
				secs = 0;
			}
			if (secs > 59) {
				return 60;
			}
			return static_cast<uint64_t>(secs) + 1; // +1s margin to clear the reset boundary
		} catch (const std::exception &) {
			// Unparseable header (e.g. an HTTP-date Retry-After); fall back to backoff below.
		}
	}
	return MinValue<uint64_t>(uint64_t(1) << attempt, 60); // 1, 2, 4, 8, ... seconds
}

string SplunkClient::AuthenticatedRequest(ClientContext &context, const string &path, const string *form_body,
                                          bool index_discovery) const {
	duckdb_httplib_openssl::Headers headers = {
	    {"Accept", "application/json"},
	};

	for (uint64_t attempt = 0;; attempt++) {
		if (context.interrupted) {
			throw InterruptException();
		}
		auto response = form_body ? GetConnection().Post(path, headers, *form_body, "application/x-www-form-urlencoded")
		                          : GetConnection().Get(path, headers);

		if (!response) {
			auto error = response.error();
			// Drop the pooled connection: after a transport error the socket may be half-dead, and
			// reconnecting from scratch is the reliable way to retry.
			connection.reset();
			if (attempt >= retries || !IsRetryableTransportError(error)) {
				throw IOException("Splunk API request to %s failed: %s", NormalizeUrl(url),
				                  duckdb_httplib_openssl::to_string(error));
			}
			SleepCheckingInterrupt(context, MinValue<uint64_t>(uint64_t(1) << attempt, 60));
			continue;
		}

		// Rate limited: wait out the server-advised delay instead of failing the whole query.
		if (response->status == 429 && attempt < retries) {
			SleepCheckingInterrupt(context, RateLimitRetryDelaySeconds(*response, attempt));
			continue;
		}
		// Server-side errors are usually transient; ride them out rather than lose the query.
		if (response->status >= 500 && attempt < retries) {
			SleepCheckingInterrupt(context, MinValue<uint64_t>(uint64_t(1) << attempt, 60));
			continue;
		}
		if (response->status < 200 || response->status >= 300) {
			if (index_discovery && (response->status == 401 || response->status == 403)) {
				throw IOException("Splunk index discovery returned HTTP %d. Automatic discovery requires permission "
				                  "to list indexes; attach with INDEXES ['main', ...] to bypass discovery",
				                  response->status);
			}
			// Body may contain a Splunk error message but never the credentials (those live only in
			// the Authorization header, which is not echoed back).
			throw IOException("Splunk API returned HTTP %d: %s", response->status, response->body);
		}
		return response->body;
	}
}

string SplunkClient::ExportSearch(ClientContext &context, const string &form_body) const {
	return AuthenticatedRequest(context, "/services/search/v2/jobs/export", &form_body, false);
}

string SplunkClient::ListIndexes(ClientContext &context) const {
	return AuthenticatedRequest(context, "/services/data/indexes?output_mode=json&count=0", nullptr, true);
}

} // namespace duckdb

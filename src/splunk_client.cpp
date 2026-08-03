#include "splunk_client.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"

#ifdef __EMSCRIPTEN__
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/types/blob.hpp"
#else
#include <chrono>
#include <thread>

// Native builds use DuckDB's bundled, separately-namespaced OpenSSL httplib.
#include "httplib.hpp"
#endif

namespace duckdb {

static string NormalizeUrl(const string &raw) {
	string result = raw;
	StringUtil::Trim(result);
	while (!result.empty() && result.back() == '/') {
		result.pop_back();
	}
	return result.empty() ? "https://localhost:8089" : result;
}

SplunkClient::SplunkClient() = default;
SplunkClient::~SplunkClient() {
}

void SplunkClient::CopyConfigTo(SplunkClient &target) const {
	target.url = url;
	target.username = username;
	target.password = password;
	target.token = token;
	target.token_type = token_type;
	target.insecure_tls = insecure_tls;
	target.timeout_seconds = timeout_seconds;
	target.retries = retries;
}

#ifdef __EMSCRIPTEN__
static string BrowserHTTPErrorDetail(const HTTPResponse &response) {
	string detail = response.body.empty() ? response.GetError() : response.body;
	StringUtil::Trim(detail);
	for (auto &character : detail) {
		if (character == '\r' || character == '\n' || character == '\t') {
			character = ' ';
		}
	}
	constexpr idx_t MAX_ERROR_DETAIL_LENGTH = 500;
	if (detail.size() > MAX_ERROR_DETAIL_LENGTH) {
		detail.resize(MAX_ERROR_DETAIL_LENGTH);
		detail += "...";
	}
	return detail;
}

static void AddBrowserAuthHeaders(const SplunkClient &client, HTTPHeaders &headers) {
	if (!client.token.empty()) {
		auto scheme = StringUtil::CIEquals(client.token_type, "Splunk") ? "Splunk " : "Bearer ";
		headers.Insert("Authorization", string(scheme) + client.token);
	} else if (!client.username.empty()) {
		string credentials = client.username + ":" + client.password;
		headers.Insert("Authorization", "Basic " + Blob::ToBase64(string_t(credentials)));
	}
}
#else
duckdb_httplib_openssl::Client &SplunkClient::GetConnection() const {
	std::lock_guard<std::mutex> guard(connection_mutex);
	if (!connection) {
		connection = make_uniq<duckdb_httplib_openssl::Client>(NormalizeUrl(url));
		connection->set_connection_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_read_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_keep_alive(true);

		if (!token.empty()) {
			if (StringUtil::CIEquals(token_type, "Splunk")) {
				connection->set_default_headers({{"Authorization", "Splunk " + token}});
			} else {
				connection->set_bearer_token_auth(token);
			}
		} else if (!username.empty()) {
			connection->set_basic_auth(username, password);
		}

		if (insecure_tls) {
			connection->enable_server_certificate_verification(false);
			connection->enable_server_hostname_verification(false);
		}
	}
	return *connection;
}

static void SleepCheckingInterrupt(ClientContext &context, uint64_t seconds) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	while (std::chrono::steady_clock::now() < deadline) {
		if (context.interrupted) {
			throw InterruptException();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

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

static uint64_t RateLimitRetryDelaySeconds(const duckdb_httplib_openssl::Response &response, uint64_t attempt) {
	if (response.has_header("Retry-After")) {
		try {
			long long seconds = std::stoll(response.get_header_value("Retry-After"));
			if (seconds < 0) {
				seconds = 0;
			}
			if (seconds > 59) {
				return 60;
			}
			return static_cast<uint64_t>(seconds) + 1;
		} catch (const std::exception &) {
		}
	}
	return MinValue<uint64_t>(uint64_t(1) << attempt, 60);
}

#endif

string SplunkClient::AuthenticatedRequest(ClientContext &context, const string &path, const string *form_body,
                                          bool index_discovery) const {
#ifdef __EMSCRIPTEN__
	if (context.interrupted) {
		throw InterruptException();
	}

	auto base_url = NormalizeUrl(url);
	auto request_url = base_url + path;
	auto &http_util = HTTPUtil::Get(*context.db);
	auto params = http_util.InitializeParameters(context, request_url);
	params->timeout = timeout_seconds;
	params->retries = retries;
	params->keep_alive = true;
	params->follow_location = false;

	HTTPHeaders headers;
	headers.Insert("Accept", "application/json");
	AddBrowserAuthHeaders(*this, headers);

	unique_ptr<HTTPResponse> response;
	if (form_body) {
		headers.Insert("Content-Type", "application/x-www-form-urlencoded");
		PostRequestInfo request(request_url, headers, *params, reinterpret_cast<const_data_ptr_t>(form_body->data()),
		                        form_body->size());
		request.try_request = true;
		response = http_util.Request(request);
	} else {
		GetRequestInfo request(request_url, headers, *params, nullptr, nullptr);
		request.try_request = true;
		response = http_util.Request(request);
	}

	if (!response) {
		throw IOException("Splunk browser request failed through %s: no response (check the proxy URL and CORS "
		                  "allowlist)",
		                  base_url);
	}
	if (!response->Success()) {
		auto status = static_cast<uint16_t>(response->status);
		if (index_discovery && (status == 401 || status == 403)) {
			throw IOException("Splunk index discovery returned HTTP %d. Automatic discovery requires permission "
			                  "to list indexes; attach with INDEXES ['main', ...] to bypass discovery",
			                  status);
		}
		if (response->status != HTTPStatusCode::INVALID) {
			throw IOException("Splunk API returned HTTP %d through %s: %s", status, base_url,
			                  BrowserHTTPErrorDetail(*response));
		}
		throw IOException("Splunk browser request failed through %s: %s (check the proxy URL, CORS allowlist, "
		                  "and network connection)",
		                  base_url, response->GetError());
	}
	return response->body;
#else
	duckdb_httplib_openssl::Headers headers = {{"Accept", "application/json"}};
	for (uint64_t attempt = 0;; attempt++) {
		if (context.interrupted) {
			throw InterruptException();
		}
		auto response = form_body ? GetConnection().Post(path, headers, *form_body, "application/x-www-form-urlencoded")
		                          : GetConnection().Get(path, headers);
		if (!response) {
			auto error = response.error();
			{
				std::lock_guard<std::mutex> guard(connection_mutex);
				connection.reset();
			}
			if (attempt >= retries || !IsRetryableTransportError(error)) {
				throw IOException("Splunk API request to %s failed: %s", NormalizeUrl(url),
				                  duckdb_httplib_openssl::to_string(error));
			}
			SleepCheckingInterrupt(context, MinValue<uint64_t>(uint64_t(1) << attempt, 60));
			continue;
		}
		if (response->status == 429 && attempt < retries) {
			SleepCheckingInterrupt(context, RateLimitRetryDelaySeconds(*response, attempt));
			continue;
		}
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
			throw IOException("Splunk API returned HTTP %d: %s", response->status, response->body);
		}
		return response->body;
	}
#endif
}

void SplunkClient::ExportSearch(ClientContext &context, const string &form_body,
                                const std::function<bool(const char *, idx_t)> &on_chunk) const {
#ifdef __EMSCRIPTEN__
	auto response = AuthenticatedRequest(context, "/services/search/v2/jobs/export", &form_body, false);
	if (!response.empty() && !on_chunk(response.data(), response.size())) {
		throw InterruptException();
	}
#else
	for (uint64_t attempt = 0;; attempt++) {
		if (context.interrupted) {
			throw InterruptException();
		}

		bool success_status = false;
		bool stopped_by_consumer = false;
		idx_t success_bytes = 0;
		string error_body;
		duckdb_httplib_openssl::Request request;
		request.method = "POST";
		request.path = "/services/search/v2/jobs/export";
		request.body = form_body;
		request.set_header("Accept", "application/json");
		request.set_header("Content-Type", "application/x-www-form-urlencoded");
		request.response_handler = [&](const duckdb_httplib_openssl::Response &response) {
			success_status = response.status >= 200 && response.status < 300;
			return true;
		};
		request.content_receiver = [&](const char *data, size_t length, size_t, size_t) {
			if (success_status) {
				if (!on_chunk(data, length)) {
					stopped_by_consumer = true;
					return false;
				}
				success_bytes += length;
			} else if (error_body.size() < 4096) {
				auto remaining = 4096 - error_body.size();
				error_body.append(data, MinValue<size_t>(length, remaining));
			}
			return true;
		};

		auto response = GetConnection().send(request);
		if (stopped_by_consumer) {
			return;
		}
		if (!response) {
			auto error = response.error();
			{
				std::lock_guard<std::mutex> guard(connection_mutex);
				connection.reset();
			}
			// Once bytes have reached the parser, replaying the request would duplicate rows.
			if (success_bytes > 0 || attempt >= retries || !IsRetryableTransportError(error)) {
				throw IOException("Splunk export request to %s failed after receiving %llu bytes: %s",
				                  NormalizeUrl(url), static_cast<unsigned long long>(success_bytes),
				                  duckdb_httplib_openssl::to_string(error));
			}
			SleepCheckingInterrupt(context, MinValue<uint64_t>(uint64_t(1) << attempt, 60));
			continue;
		}
		if (response->status == 429 && attempt < retries) {
			SleepCheckingInterrupt(context, RateLimitRetryDelaySeconds(*response, attempt));
			continue;
		}
		if (response->status >= 500 && attempt < retries) {
			SleepCheckingInterrupt(context, MinValue<uint64_t>(uint64_t(1) << attempt, 60));
			continue;
		}
		if (response->status < 200 || response->status >= 300) {
			throw IOException("Splunk API returned HTTP %d: %s", response->status, error_body);
		}
		return;
	}
#endif
}

void SplunkClient::Cancel() const {
#ifdef __EMSCRIPTEN__
	// Browser HTTPUtil/fetch cancellation follows the owning query context.
#else
	std::lock_guard<std::mutex> guard(connection_mutex);
	if (connection) {
		connection->stop();
	}
#endif
}

string SplunkClient::ListIndexes(ClientContext &context) const {
	return AuthenticatedRequest(context, "/services/data/indexes?output_mode=json&count=0", nullptr, true);
}

} // namespace duckdb

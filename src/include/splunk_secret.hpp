#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Credentials needed to talk to the Splunk REST search API.
//! Either `token` (Splunk authentication token) OR `username`+`password` (basic auth) must be set;
//! token takes precedence when both are present.
struct SplunkCredentials {
	string name;
	//! Management/search API base, e.g. "https://localhost:8089". No trailing path.
	string url = "https://localhost:8089";
	string username;
	string password;
	string token;
	//! HTTP auth scheme for `token`: "Bearer" (JWT authentication tokens) or "Splunk" (the older
	//! authtoken/session-key scheme). Case-insensitive; defaults to "Bearer".
	string token_type = "Bearer";
	//! Skip TLS certificate/hostname verification. Needed for the self-signed cert local Splunk
	//! Docker ships with; must stay false in production.
	bool insecure_tls = false;

	bool HasToken() const {
		return !token.empty();
	}
	bool HasBasicAuth() const {
		return !username.empty() && !password.empty();
	}
};

//! Register the `splunk` secret type and its `config` provider so users can run:
//!   CREATE SECRET (TYPE splunk, URL '...', USERNAME '...', PASSWORD '...', INSECURE_TLS true);
//!   CREATE SECRET (TYPE splunk, URL '...', TOKEN '...');
void RegisterSplunkSecretType(ExtensionLoader &loader);

//! Resolve Splunk credentials from the secret manager. If `secret_name` is empty the first secret
//! of type `splunk` in scope is used. Throws a helpful error if none is found or if neither a
//! token nor a username+password pair is present.
SplunkCredentials GetSplunkCredentials(ClientContext &context, const string &secret_name);

} // namespace duckdb

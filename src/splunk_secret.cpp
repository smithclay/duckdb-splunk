#include "splunk_secret.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

//! Build a KeyValueSecret from `CREATE SECRET (TYPE splunk, ...)` options.
static unique_ptr<BaseSecret> CreateSplunkSecretFromConfig(ClientContext &context, CreateSecretInput &input) {
	auto secret = make_uniq<KeyValueSecret>(input.scope, "splunk", "config", input.name);

	// Only copy the keys we understand; ignore anything else.
	for (const auto &option : input.options) {
		auto lower_name = StringUtil::Lower(option.first);
		if (lower_name == "url" || lower_name == "username" || lower_name == "password" || lower_name == "token" ||
		    lower_name == "token_type" || lower_name == "insecure_tls") {
			secret->secret_map[lower_name] = option.second;
		}
	}

	// Never print the password/token in duckdb_secrets() / SHOW SECRETS.
	secret->redact_keys = {"password", "token"};
	return std::move(secret);
}

void RegisterSplunkSecretType(ExtensionLoader &loader) {
	SecretType secret_type;
	secret_type.name = "splunk";
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "config";
	loader.RegisterSecretType(secret_type);

	CreateSecretFunction splunk_secret_function = {"splunk", "config", CreateSplunkSecretFromConfig};
	splunk_secret_function.named_parameters["url"] = LogicalType::VARCHAR;
	splunk_secret_function.named_parameters["username"] = LogicalType::VARCHAR;
	splunk_secret_function.named_parameters["password"] = LogicalType::VARCHAR;
	splunk_secret_function.named_parameters["token"] = LogicalType::VARCHAR;
	splunk_secret_function.named_parameters["token_type"] = LogicalType::VARCHAR;
	splunk_secret_function.named_parameters["insecure_tls"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(splunk_secret_function);
}

//! Coerce a secret value (stored as VARCHAR or BOOLEAN) to a bool. Accepts true/1/yes/on.
static bool ValueToBool(const Value &value) {
	if (value.type().id() == LogicalTypeId::BOOLEAN) {
		return BooleanValue::Get(value);
	}
	auto s = StringUtil::Lower(value.ToString());
	return s == "true" || s == "1" || s == "yes" || s == "on";
}

SplunkCredentials GetSplunkCredentials(ClientContext &context, const string &secret_name) {
	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);

	unique_ptr<SecretEntry> entry;
	if (!secret_name.empty()) {
		entry = secret_manager.GetSecretByName(transaction, secret_name);
		if (!entry) {
			throw InvalidInputException("No secret with name '%s' found", secret_name);
		}
	} else {
		// No explicit name: use the first secret of type `splunk`.
		for (auto &candidate : secret_manager.AllSecrets(transaction)) {
			if (candidate.secret && candidate.secret->GetType() == "splunk") {
				entry = make_uniq<SecretEntry>(candidate);
				break;
			}
		}
		if (!entry) {
			throw InvalidInputException("No 'splunk' secret found. Create one first, e.g.:\n"
			                            "  CREATE SECRET (TYPE splunk, URL 'https://localhost:8089', USERNAME "
			                            "'admin', PASSWORD '<password>', INSECURE_TLS true);");
		}
	}

	const auto &base_secret = *entry->secret;
	if (base_secret.GetType() != "splunk") {
		throw InvalidInputException("Secret '%s' is not a 'splunk' secret (found type '%s')", secret_name,
		                            base_secret.GetType());
	}
	const auto *kv_secret = dynamic_cast<const KeyValueSecret *>(&base_secret);
	if (!kv_secret) {
		throw InvalidInputException("Secret '%s' is not a key-value 'splunk' secret", base_secret.GetName());
	}

	SplunkCredentials creds;
	creds.name = base_secret.GetName();
	Value value;
	if (kv_secret->TryGetValue("url", value) && !value.IsNull() && !value.ToString().empty()) {
		creds.url = value.ToString();
	}
	if (kv_secret->TryGetValue("username", value) && !value.IsNull()) {
		creds.username = value.ToString();
	}
	if (kv_secret->TryGetValue("password", value) && !value.IsNull()) {
		creds.password = value.ToString();
	}
	if (kv_secret->TryGetValue("token", value) && !value.IsNull()) {
		creds.token = value.ToString();
	}
	if (kv_secret->TryGetValue("token_type", value) && !value.IsNull() && !value.ToString().empty()) {
		creds.token_type = value.ToString();
	}
	if (kv_secret->TryGetValue("insecure_tls", value) && !value.IsNull()) {
		creds.insecure_tls = ValueToBool(value);
	}

	if (!creds.HasToken() && !creds.HasBasicAuth()) {
		throw InvalidInputException("splunk secret must provide either TOKEN, or USERNAME and PASSWORD");
	}
	// Only "Bearer" (JWT auth tokens) and "Splunk" (authtoken/session key) are valid schemes.
	if (!StringUtil::CIEquals(creds.token_type, "Bearer") && !StringUtil::CIEquals(creds.token_type, "Splunk")) {
		throw InvalidInputException("splunk secret TOKEN_TYPE must be 'Bearer' or 'Splunk' (got '%s')",
		                            creds.token_type);
	}
	return creds;
}

} // namespace duckdb

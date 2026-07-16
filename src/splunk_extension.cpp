#define DUCKDB_EXTENSION_MAIN

#include "splunk_extension.hpp"

#include "splunk_catalog.hpp"
#include "splunk_secret.hpp"
#include "logs_table.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	// Credentials: CREATE SECRET (TYPE splunk, URL '...', USERNAME '...', PASSWORD '...', ...).
	RegisterSplunkSecretType(loader);
	// Catalog: ATTACH 'splunk:' AS sp (TYPE splunk, SECRET '...', INDEXES [...]).
	RegisterSplunkCatalog(loader);
	// Reader: SELECT * FROM read_splunk_logs(query => '...', earliest => '-15m', latest => 'now').
	RegisterSplunkLogsFunction(loader);
}

void SplunkExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string SplunkExtension::Name() {
	return "splunk";
}

std::string SplunkExtension::Version() const {
#ifdef EXT_VERSION_SPLUNK
	return EXT_VERSION_SPLUNK;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(splunk, loader) {
	duckdb::LoadInternal(loader);
}
}

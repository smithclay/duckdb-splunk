#pragma once

namespace duckdb {

class ExtensionLoader;

//! Register the `splunk` storage extension used by ATTACH ... (TYPE splunk).
void RegisterSplunkCatalog(ExtensionLoader &loader);

} // namespace duckdb

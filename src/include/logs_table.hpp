#pragma once

namespace duckdb {

class ExtensionLoader;

//! Register the `read_splunk_logs(...)` table function.
void RegisterSplunkLogsFunction(ExtensionLoader &loader);

} // namespace duckdb

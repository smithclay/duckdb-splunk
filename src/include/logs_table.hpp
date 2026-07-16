#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;
class ClientContext;
class FunctionData;
class TableFunction;
class TableCatalogEntry;

//! Register the `read_splunk_logs(...)` table function.
void RegisterSplunkLogsFunction(ExtensionLoader &loader);

//! Return the stable 18-column OTLP-shaped output schema used by both public interfaces.
void GetSplunkLogsSchema(vector<LogicalType> &types, vector<string> &names);

//! Create the scan function and already-bound data for one catalog table.
TableFunction GetSplunkLogsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                     const string &index_name, unique_ptr<FunctionData> &bind_data);

} // namespace duckdb

#include "splunk_catalog.hpp"

#include "logs_table.hpp"
#include "splunk_client.hpp"
#include "splunk_secret.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/column_definition.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/storage/database_size.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/storage/table_storage_info.hpp"
#include "duckdb/transaction/transaction.hpp"
#include "duckdb/transaction/transaction_manager.hpp"

#include "yyjson.hpp"

#include <memory>
#include <unordered_set>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {
namespace {

[[noreturn]] static void ThrowReadOnly() {
	throw BinderException("Splunk catalogs are read-only");
}

class SplunkTableEntry : public TableCatalogEntry {
public:
	SplunkTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const string &index_name, const string &secret_name)
	    : SplunkTableEntry(catalog, schema, index_name, secret_name, CreateInfo(schema, index_name)) {
	}

	unique_ptr<BaseStatistics> GetStatistics(ClientContext &, column_t) override {
		return nullptr;
	}

	TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
		return GetSplunkLogsTableScan(context, *this, secret_name, index_name, bind_data);
	}

	TableStorageInfo GetStorageInfo(ClientContext &) override {
		return TableStorageInfo();
	}

private:
	SplunkTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const string &index_name, const string &secret_name,
	                 CreateTableInfo info)
	    : TableCatalogEntry(catalog, schema, info), index_name(index_name), secret_name(secret_name) {
	}

	static CreateTableInfo CreateInfo(SchemaCatalogEntry &schema, const string &index_name) {
		CreateTableInfo info(schema, index_name);
		vector<LogicalType> types;
		vector<string> names;
		GetSplunkLogsSchema(types, names);
		for (idx_t i = 0; i < names.size(); i++) {
			info.columns.AddColumn(ColumnDefinition(names[i], types[i]));
		}
		return info;
	}

	string index_name;
	string secret_name;
};

class SplunkSchemaEntry : public SchemaCatalogEntry {
public:
	SplunkSchemaEntry(Catalog &catalog, const vector<string> &indexes, const string &secret_name)
	    : SplunkSchemaEntry(catalog, indexes, secret_name, CreateInfo()) {
	}

private:
	SplunkSchemaEntry(Catalog &catalog, const vector<string> &indexes, const string &secret_name, CreateSchemaInfo info)
	    : SchemaCatalogEntry(catalog, info) {
		for (const auto &index : indexes) {
			tables.push_back(make_uniq<SplunkTableEntry>(catalog, *this, index, secret_name));
		}
	}

public:
	void Scan(ClientContext &, CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
		Scan(type, callback);
	}

	void Scan(CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
		if (type != CatalogType::TABLE_ENTRY) {
			return;
		}
		for (auto &table : tables) {
			callback(*table);
		}
	}

	optional_ptr<CatalogEntry> LookupEntry(CatalogTransaction, const EntryLookupInfo &lookup_info) override {
		if (lookup_info.GetCatalogType() != CatalogType::TABLE_ENTRY) {
			return nullptr;
		}
		const auto &name = lookup_info.GetEntryName();
		// Prefer exact matches so case-distinct Splunk index names remain deterministic, then
		// honor DuckDB's usual case-insensitive identifier lookup.
		for (auto &table : tables) {
			if (table->name == name) {
				return table.get();
			}
		}
		for (auto &table : tables) {
			if (StringUtil::CIEquals(table->name, name)) {
				return table.get();
			}
		}
		return nullptr;
	}

	optional_ptr<CatalogEntry> CreateIndex(CatalogTransaction, CreateIndexInfo &, TableCatalogEntry &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateFunction(CatalogTransaction, CreateFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateTable(CatalogTransaction, BoundCreateTableInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateView(CatalogTransaction, CreateViewInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateSequence(CatalogTransaction, CreateSequenceInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateTableFunction(CatalogTransaction, CreateTableFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCopyFunction(CatalogTransaction, CreateCopyFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreatePragmaFunction(CatalogTransaction, CreatePragmaFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCollation(CatalogTransaction, CreateCollationInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCoordinateSystem(CatalogTransaction, CreateCoordinateSystemInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateType(CatalogTransaction, CreateTypeInfo &) override {
		ThrowReadOnly();
	}
	void DropEntry(ClientContext &, DropInfo &) override {
		ThrowReadOnly();
	}
	void Alter(CatalogTransaction, AlterInfo &) override {
		ThrowReadOnly();
	}

private:
	static CreateSchemaInfo CreateInfo() {
		CreateSchemaInfo info;
		info.schema = "logs";
		return info;
	}

	vector<unique_ptr<SplunkTableEntry>> tables;
};

class SplunkCatalog : public Catalog {
public:
	SplunkCatalog(AttachedDatabase &db, vector<string> indexes, string secret_name)
	    : Catalog(db), logs_schema(make_uniq<SplunkSchemaEntry>(*this, indexes, secret_name)) {
	}

	void Initialize(bool) override {
	}

	string GetCatalogType() override {
		return "splunk";
	}

	optional_ptr<CatalogEntry> CreateSchema(CatalogTransaction, CreateSchemaInfo &) override {
		ThrowReadOnly();
	}

	void ScanSchemas(ClientContext &, std::function<void(SchemaCatalogEntry &)> callback) override {
		callback(*logs_schema);
	}

	optional_ptr<SchemaCatalogEntry> LookupSchema(CatalogTransaction, const EntryLookupInfo &schema_lookup,
	                                              OnEntryNotFound if_not_found) override {
		if (StringUtil::CIEquals(schema_lookup.GetEntryName(), "logs")) {
			return logs_schema.get();
		}
		if (if_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw CatalogException(schema_lookup.GetErrorContext(), "Schema with name %s does not exist!",
			                       schema_lookup.GetEntryName());
		}
		return nullptr;
	}

	PhysicalOperator &PlanCreateTableAs(ClientContext &, PhysicalPlanGenerator &, LogicalCreateTable &,
	                                    PhysicalOperator &) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanInsert(ClientContext &, PhysicalPlanGenerator &, LogicalInsert &,
	                             optional_ptr<PhysicalOperator>) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanDelete(ClientContext &, PhysicalPlanGenerator &, LogicalDelete &,
	                             PhysicalOperator &) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanUpdate(ClientContext &, PhysicalPlanGenerator &, LogicalUpdate &,
	                             PhysicalOperator &) override {
		ThrowReadOnly();
	}

	DatabaseSize GetDatabaseSize(ClientContext &) override {
		return DatabaseSize();
	}
	bool InMemory() override {
		return false;
	}
	string GetDBPath() override {
		return "splunk:";
	}

private:
	void DropSchema(ClientContext &, DropInfo &) override {
		ThrowReadOnly();
	}

	unique_ptr<SplunkSchemaEntry> logs_schema;
};

class SplunkTransaction : public Transaction {
public:
	SplunkTransaction(TransactionManager &manager, ClientContext &context) : Transaction(manager, context) {
	}

	void SetReadWrite() override {
		ThrowReadOnly();
	}

	void SetModifications(DatabaseModificationType) override {
		ThrowReadOnly();
	}
};

class SplunkTransactionManager : public TransactionManager {
public:
	explicit SplunkTransactionManager(AttachedDatabase &db) : TransactionManager(db) {
	}

	Transaction &StartTransaction(ClientContext &context) override {
		auto transaction = make_uniq<SplunkTransaction>(*this, context);
		auto result = transaction.get();
		lock_guard<mutex> guard(transaction_lock);
		transactions.emplace(result, std::move(transaction));
		return *result;
	}

	ErrorData CommitTransaction(ClientContext &, Transaction &transaction) override {
		lock_guard<mutex> guard(transaction_lock);
		transactions.erase(&transaction);
		return ErrorData();
	}

	void RollbackTransaction(Transaction &transaction) override {
		lock_guard<mutex> guard(transaction_lock);
		transactions.erase(&transaction);
	}

	void Checkpoint(ClientContext &, bool) override {
	}

private:
	mutex transaction_lock;
	unordered_map<Transaction *, unique_ptr<Transaction>> transactions;
};

static vector<string> ParseExplicitIndexes(const Value &value) {
	if (value.IsNull() || value.type().id() != LogicalTypeId::LIST ||
	    ListType::GetChildType(value.type()).id() != LogicalTypeId::VARCHAR) {
		throw InvalidInputException("Splunk ATTACH option INDEXES must be a VARCHAR[]");
	}
	vector<string> result;
	std::unordered_set<string> seen;
	for (const auto &child : ListValue::GetChildren(value)) {
		if (child.IsNull() || child.type().id() != LogicalTypeId::VARCHAR) {
			throw InvalidInputException("Splunk ATTACH option INDEXES must contain only non-null VARCHAR names");
		}
		auto name = child.GetValue<string>();
		if (name.empty()) {
			throw InvalidInputException("Splunk ATTACH option INDEXES must not contain empty index names");
		}
		if (seen.insert(name).second) {
			result.push_back(std::move(name));
		}
	}
	return result;
}

struct YyjsonDocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};

static vector<string> ParseDiscoveredIndexes(const string &response) {
	std::unique_ptr<yyjson_doc, YyjsonDocDeleter> doc(yyjson_read(response.c_str(), response.size(), 0));
	if (!doc) {
		throw IOException("Splunk index discovery returned invalid JSON");
	}
	auto root = yyjson_doc_get_root(doc.get());
	auto entries = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "entry") : nullptr;
	if (!entries || !yyjson_is_arr(entries)) {
		throw IOException("Splunk index discovery response did not contain an entry array");
	}

	vector<string> result;
	std::unordered_set<string> seen;
	size_t idx, max;
	yyjson_val *entry;
	yyjson_arr_foreach(entries, idx, max, entry) {
		if (!yyjson_is_obj(entry)) {
			continue;
		}
		auto name_value = yyjson_obj_get(entry, "name");
		if (!name_value || !yyjson_is_str(name_value)) {
			continue;
		}
		string name = yyjson_get_str(name_value);
		if (!name.empty() && seen.insert(name).second) {
			result.push_back(std::move(name));
		}
	}
	return result;
}

static unique_ptr<Catalog> AttachSplunk(optional_ptr<StorageExtensionInfo>, ClientContext &context,
                                        AttachedDatabase &db, const string &, AttachInfo &info,
                                        AttachOptions &options) {
	if (info.path != "splunk:") {
		throw InvalidInputException("Splunk catalogs must be attached from the path 'splunk:'");
	}

	string secret_name;
	vector<string> indexes;
	bool indexes_supplied = false;
	for (const auto &option : options.options) {
		auto key = StringUtil::Lower(option.first);
		if (key == "secret") {
			if (option.second.IsNull() || option.second.type().id() != LogicalTypeId::VARCHAR) {
				throw InvalidInputException("Splunk ATTACH option SECRET must be a non-null VARCHAR name");
			}
			secret_name = option.second.GetValue<string>();
			if (secret_name.empty()) {
				throw InvalidInputException("Splunk ATTACH option SECRET must not be empty");
			}
		} else if (key == "indexes") {
			indexes = ParseExplicitIndexes(option.second);
			indexes_supplied = true;
		} else {
			throw InvalidInputException(
			    "Unsupported Splunk ATTACH option '%s'; supported options are SECRET and INDEXES", option.first);
		}
	}

	// Validate and pin the selected secret at attach time. Explicit INDEXES keeps attachment
	// network-free; otherwise discover all indexes visible to this credential once.
	auto credentials = GetSplunkCredentials(context, secret_name);
	if (secret_name.empty()) {
		secret_name = credentials.name;
	}
	if (!indexes_supplied) {
		SplunkClient client;
		client.url = credentials.url;
		client.username = credentials.username;
		client.password = credentials.password;
		client.token = credentials.token;
		client.token_type = credentials.token_type;
		client.insecure_tls = credentials.insecure_tls;
		indexes = ParseDiscoveredIndexes(client.ListIndexes(context));
	}

	db.SetReadOnlyDatabase();
	return make_uniq<SplunkCatalog>(db, std::move(indexes), std::move(secret_name));
}

static unique_ptr<TransactionManager> CreateSplunkTransactionManager(optional_ptr<StorageExtensionInfo>,
                                                                     AttachedDatabase &db, Catalog &) {
	return make_uniq<SplunkTransactionManager>(db);
}

} // namespace

void RegisterSplunkCatalog(ExtensionLoader &loader) {
	auto storage = make_shared_ptr<StorageExtension>();
	storage->attach = AttachSplunk;
	storage->create_transaction_manager = CreateSplunkTransactionManager;
	StorageExtension::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()), "splunk", std::move(storage));
}

} // namespace duckdb

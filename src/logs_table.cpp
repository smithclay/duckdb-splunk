#include "logs_table.hpp"

#include "splunk_client.hpp"
#include "splunk_secret.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include "yyjson.hpp"

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <memory>

#ifndef __EMSCRIPTEN__
#include <chrono>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <thread>
#endif

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

//===--------------------------------------------------------------------===//
// yyjson RAII helpers — free docs/buffers on every path (incl. exceptions)
//===--------------------------------------------------------------------===//
namespace {
struct YyjsonDocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
struct YyjsonMutDocDeleter {
	void operator()(yyjson_mut_doc *doc) const {
		yyjson_mut_doc_free(doc);
	}
};
struct YyjsonFreeDeleter {
	void operator()(char *ptr) const {
		free(ptr);
	}
};
using YyjsonDocPtr = std::unique_ptr<yyjson_doc, YyjsonDocDeleter>;
using YyjsonMutDocPtr = std::unique_ptr<yyjson_mut_doc, YyjsonMutDocDeleter>;
using YyjsonStrPtr = std::unique_ptr<char, YyjsonFreeDeleter>;
} // namespace

//===--------------------------------------------------------------------===//
// Output schema — matches duckdb-otlp `read_otlp_logs`
//===--------------------------------------------------------------------===//
static constexpr idx_t COL_TIME = 0;
static constexpr idx_t COL_OBSERVED_TIME = 1;
static constexpr idx_t COL_TRACE_ID = 2;
static constexpr idx_t COL_SPAN_ID = 3;
static constexpr idx_t COL_SERVICE_NAME = 4;
static constexpr idx_t COL_SEVERITY_NUMBER = 7;
static constexpr idx_t COL_SEVERITY_TEXT = 8;
static constexpr idx_t COL_BODY = 10;
static constexpr idx_t COL_RESOURCE_ATTRS = 11;
static constexpr idx_t COL_LOG_ATTRS = 15;
static constexpr idx_t COLUMN_COUNT = 18;

void GetSplunkLogsSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"time_unix_nano",
	         "observed_time_unix_nano",
	         "trace_id",
	         "span_id",
	         "service_name",
	         "service_namespace",
	         "service_instance_id",
	         "severity_number",
	         "severity_text",
	         "event_name",
	         "body",
	         "resource_attributes",
	         "scope_name",
	         "scope_version",
	         "scope_attributes",
	         "log_attributes",
	         "dropped_attributes_count",
	         "flags"};
	types = {LogicalType::TIMESTAMP_NS, LogicalType::TIMESTAMP_NS, LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::INTEGER,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::INTEGER,      LogicalType::INTEGER};
	D_ASSERT(names.size() == COLUMN_COUNT && types.size() == COLUMN_COUNT);
}

//===--------------------------------------------------------------------===//
// Splunk -> OTLP mapping helpers
//===--------------------------------------------------------------------===//

//! Map a severity/level string to an OTLP SeverityNumber (1-24). 0 = unspecified/unknown.
static int32_t SeverityToNumber(const string &severity) {
	auto s = StringUtil::Lower(severity);
	if (s == "trace") {
		return 1;
	}
	if (s == "debug") {
		return 5;
	}
	if (s == "info" || s == "notice" || s == "ok") {
		return 9;
	}
	if (s == "warn" || s == "warning") {
		return 13;
	}
	if (s == "error" || s == "err") {
		return 17;
	}
	if (s == "critical" || s == "crit" || s == "alert" || s == "emergency" || s == "fatal") {
		return 21;
	}
	return 0;
}

static const char *GetStr(yyjson_val *obj, const char *key) {
	if (!obj) {
		return nullptr;
	}
	yyjson_val *v = yyjson_obj_get(obj, key);
	return (v && yyjson_is_str(v)) ? yyjson_get_str(v) : nullptr;
}

//! Look up a string value under any of `keys`, checking each source object in order. Sources are
//! tried in priority order: top-level extracted fields, a nested `fields` object (some Splunk JSON
//! shapes nest extracted fields), then the parsed `_raw` JSON payload (HEC/`_json` events carry
//! their structured fields only inside `_raw`). Returns the first match, or nullptr.
static const char *LookupStr(std::initializer_list<yyjson_val *> sources, std::initializer_list<const char *> keys) {
	for (yyjson_val *source : sources) {
		for (const char *key : keys) {
			if (const char *v = GetStr(source, key)) {
				return v;
			}
		}
	}
	return nullptr;
}

//! Parse an ISO-8601 timestamp (e.g. "2026-07-07T10:30:45.123+00:00") into nanoseconds since epoch.
static bool ParseIso8601ToNanos(const char *str, int64_t &out_nanos) {
	if (!str) {
		return false;
	}
	idx_t len = strlen(str);

	timestamp_t ts;
	bool has_offset = false;
	string_t tz;
	int32_t sub_micro_nanos = 0;
	auto result = Timestamp::TryConvertTimestampTZ(str, len, ts, /*use_offset=*/true, has_offset, tz, &sub_micro_nanos);
	if (result != TimestampCastResult::SUCCESS) {
		// Fall back to the strict (offset-less) nanosecond parser.
		timestamp_ns_t ts_ns;
		if (Timestamp::TryConvertTimestamp(str, len, ts_ns) != TimestampCastResult::SUCCESS) {
			return false;
		}
		out_nanos = ts_ns.value;
		return true;
	}

	int64_t epoch_nanos;
	if (!Timestamp::TryGetEpochNanoSeconds(ts, epoch_nanos)) {
		return false;
	}
	out_nanos = epoch_nanos + sub_micro_nanos;
	return true;
}

//! Convert a numeric epoch value to nanoseconds, auto-detecting the unit by magnitude (Splunk/HEC
//! `time` is epoch seconds, but sources vary). Mirrors the OTel Collector's convertTimestamp: a
//! value already in the ns/µs/ms range is scaled by the matching factor rather than blindly treated
//! as seconds — otherwise epoch-milliseconds would come out 1000x wrong.
static int64_t EpochToNanos(double value) {
	if (value >= 1e16) {
		return static_cast<int64_t>(std::llround(value)); // already nanoseconds
	}
	if (value >= 1e13) {
		return static_cast<int64_t>(std::llround(value * 1e3)); // microseconds
	}
	if (value >= 1e10) {
		return static_cast<int64_t>(std::llround(value * 1e6)); // milliseconds
	}
	return static_cast<int64_t>(std::llround(value * 1e9)); // seconds
}

//! Parse Splunk's `_time`, which may arrive as an ISO-8601 string, a numeric epoch string
//! (e.g. "1720000000.123"), or a JSON number. Returns false if it cannot be interpreted.
static bool ParseSplunkTimeToNanos(yyjson_val *time_val, int64_t &out_nanos) {
	if (!time_val) {
		return false;
	}
	if (yyjson_is_str(time_val)) {
		const char *str = yyjson_get_str(time_val);
		if (ParseIso8601ToNanos(str, out_nanos)) {
			return true;
		}
		// Numeric epoch encoded as a string.
		char *end = nullptr;
		double value = std::strtod(str, &end);
		if (end && end != str && *end == '\0') {
			out_nanos = EpochToNanos(value);
			return true;
		}
		return false;
	}
	if (yyjson_is_num(time_val)) {
		out_nanos = EpochToNanos(yyjson_get_num(time_val));
		return true;
	}
	return false;
}

//! Splunk metadata fields promoted to `resource_attributes`, mapped to OpenTelemetry Collector
//! resource-attribute names for interop with collector-produced OTLP: `host` -> `host.name`
//! (semconv), the rest -> `com.splunk.*` (matching splunkhecreceiver's hec_metadata_to_otel_attrs
//! defaults; `splunk_server` has no collector equivalent, so it keeps the com.splunk.* convention).
//! Single source of truth: `splunk_key` is also excluded from `log_attributes` (see
//! IsInternalField), so a field is never duplicated across both bags.
struct ResourceKeyMapping {
	const char *splunk_key; //! field name as it appears in a Splunk search result
	const char *otlp_key;   //! attribute name emitted in resource_attributes
};
static const ResourceKeyMapping kResourceKeys[] = {
    {"host", "host.name"},         {"source", "com.splunk.source"},        {"sourcetype", "com.splunk.sourcetype"},
    {"index", "com.splunk.index"}, {"splunk_server", "com.splunk.server"},
};

static bool IsResourceKey(const char *key) {
	for (const auto &mapping : kResourceKeys) {
		if (std::strcmp(key, mapping.splunk_key) == 0) {
			return true;
		}
	}
	return false;
}

//! True for Splunk internal/metadata fields that are promoted to dedicated columns or are noise, so
//! they are excluded from the generic `log_attributes` bag: underscore-prefixed fields (_raw, _time,
//! _bkt, _cd, _indextime, ...), the resource-attribute keys, and a little indexing noise.
static bool IsInternalField(const char *key) {
	if (!key) {
		return true;
	}
	if (key[0] == '_') {
		return true;
	}
	if (IsResourceKey(key)) {
		return true;
	}
	static const char *const kNoise[] = {"linecount", "punct", "eventtype"};
	for (const char *noise : kNoise) {
		if (std::strcmp(key, noise) == 0) {
			return true;
		}
	}
	return false;
}

//! Build the OTLP `resource_attributes` JSON from Splunk host/source/sourcetype/index metadata,
//! keyed by the collector-compatible OTLP attribute names (see kResourceKeys).
static string BuildResourceAttributes(yyjson_val *event) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	yyjson_mut_val *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	bool any = false;
	for (const auto &mapping : kResourceKeys) {
		const char *value = GetStr(event, mapping.splunk_key);
		if (value) {
			yyjson_mut_obj_add_strcpy(doc.get(), root, mapping.otlp_key, value);
			any = true;
		}
	}
	if (!any) {
		return string();
	}
	YyjsonStrPtr json(yyjson_mut_write(doc.get(), 0, nullptr));
	return json ? string(json.get()) : string();
}

//! Copy every non-internal field of `source` into the mutable object `root`, skipping keys already
//! present. Returns true if it added at least one field.
static bool CopyNonInternalFields(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *source) {
	if (!source || !yyjson_is_obj(source)) {
		return false;
	}
	bool any = false;
	size_t idx, max;
	yyjson_val *key, *val;
	yyjson_obj_foreach(source, idx, max, key, val) {
		const char *key_str = yyjson_get_str(key);
		if (IsInternalField(key_str)) {
			continue;
		}
		// Skip keys already added by a higher-priority source (extracted fields win over `_raw`).
		if (yyjson_mut_obj_get(root, key_str)) {
			continue;
		}
		yyjson_mut_val *key_copy = yyjson_mut_strcpy(doc, key_str);
		yyjson_mut_val *val_copy = yyjson_val_mut_copy(doc, val);
		yyjson_mut_obj_add(root, key_copy, val_copy);
		any = true;
	}
	return any;
}

//! Build `log_attributes` from every event field that is not a Splunk internal/metadata field,
//! merging top-level extracted fields with the structured fields carried inside the parsed `_raw`
//! JSON payload. Keeps user fields (service, level, marker, trace_id, span_id, message, ...) as a
//! compact JSON object; returns "" when there is nothing left to record.
static string BuildLogAttributes(yyjson_val *event, yyjson_val *raw_obj) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	yyjson_mut_val *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	bool any = CopyNonInternalFields(doc.get(), root, event);
	any = CopyNonInternalFields(doc.get(), root, raw_obj) || any;
	if (!any) {
		return string();
	}
	YyjsonStrPtr json(yyjson_mut_write(doc.get(), 0, nullptr));
	return json ? string(json.get()) : string();
}

//! If `event._raw` is a JSON object (Splunk HEC/`_json` events store their structured payload
//! there), parse it into `raw_doc` and return the root object; otherwise return nullptr. The
//! caller owns `raw_doc` and must keep it alive while the returned pointer is used.
static yyjson_val *ParseRawObject(yyjson_val *event, YyjsonDocPtr &raw_doc) {
	const char *raw = GetStr(event, "_raw");
	if (!raw) {
		return nullptr;
	}
	// Cheap pre-check: skip leading whitespace and require a '{' before paying for a full parse.
	const char *p = raw;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
		p++;
	}
	if (*p != '{') {
		return nullptr;
	}
	raw_doc.reset(yyjson_read(raw, strlen(raw), 0));
	if (!raw_doc) {
		return nullptr;
	}
	yyjson_val *root = yyjson_doc_get_root(raw_doc.get());
	return (root && yyjson_is_obj(root)) ? root : nullptr;
}

//! Map one Splunk event object to the projected columns of a row. `column_ids[c]` is the source
//! column for output slot c (projection pushdown); only projected columns are computed, so
//! deselected fields — above all the log_attributes JSON serialization and the `_raw` parse — are
//! skipped entirely. The `_raw` payload, severity string, and timestamp are each shared by several
//! columns, so each is computed lazily and memoized: a projection that omits them pays nothing, and
//! one that selects two columns backed by the same source does the work once.
static void MapEvent(yyjson_val *event, const vector<column_t> &column_ids, vector<Value> &row) {
	row.assign(column_ids.size(), Value()); // all projected columns NULL by default

	yyjson_val *fields = yyjson_obj_get(event, "fields");
	if (fields && !yyjson_is_obj(fields)) {
		fields = nullptr;
	}

	YyjsonDocPtr raw_doc;
	bool raw_parsed = false;
	yyjson_val *raw_cache = nullptr;
	auto raw = [&]() -> yyjson_val * {
		if (!raw_parsed) {
			raw_cache = ParseRawObject(event, raw_doc);
			raw_parsed = true;
		}
		return raw_cache;
	};

	bool severity_done = false;
	const char *severity_cache = nullptr;
	auto severity = [&]() -> const char * {
		if (!severity_done) {
			severity_cache = LookupStr({event, fields, raw()}, {"level", "severity", "status"});
			severity_done = true;
		}
		return severity_cache;
	};

	bool time_done = false;
	Value time_cache; // NULL until parsed; stays NULL if `_time` is absent/unparseable
	auto timestamp = [&]() -> const Value & {
		if (!time_done) {
			int64_t nanos;
			if (ParseSplunkTimeToNanos(yyjson_obj_get(event, "_time"), nanos)) {
				time_cache = Value::TIMESTAMPNS(timestamp_ns_t(nanos));
			}
			time_done = true;
		}
		return time_cache;
	};

	for (idx_t c = 0; c < column_ids.size(); c++) {
		switch (column_ids[c]) {
		case COL_TIME:
		case COL_OBSERVED_TIME:
			row[c] = timestamp();
			break;
		case COL_TRACE_ID: {
			const char *trace_id = LookupStr({event, fields, raw()}, {"trace_id"});
			if (trace_id) {
				row[c] = Value(string(trace_id));
			}
			break;
		}
		case COL_SPAN_ID: {
			const char *span_id = LookupStr({event, fields, raw()}, {"span_id"});
			if (span_id) {
				row[c] = Value(string(span_id));
			}
			break;
		}
		case COL_SERVICE_NAME: {
			const char *service = LookupStr({event, fields, raw()}, {"service", "service_name"});
			if (service) {
				row[c] = Value(string(service));
			}
			break;
		}
		case COL_SEVERITY_NUMBER:
			if (const char *s = severity()) {
				row[c] = Value::INTEGER(SeverityToNumber(s));
			}
			break;
		case COL_SEVERITY_TEXT:
			if (const char *s = severity()) {
				row[c] = Value(string(s));
			}
			break;
		case COL_BODY: {
			// Prefer the raw event text (the canonical Splunk body); fall back to a `message` field.
			const char *body = LookupStr({event, fields, raw()}, {"_raw", "message"});
			if (body) {
				row[c] = Value(string(body));
			}
			break;
		}
		case COL_RESOURCE_ATTRS: {
			string resource_attributes = BuildResourceAttributes(event);
			if (!resource_attributes.empty()) {
				row[c] = Value(resource_attributes);
			}
			break;
		}
		case COL_LOG_ATTRS: {
			string log_attributes = BuildLogAttributes(event, raw());
			if (!log_attributes.empty()) {
				row[c] = Value(log_attributes);
			}
			break;
		}
		default:
			// Columns Splunk has no data for (scope_*, event_name, ...) and virtual columns
			// (e.g. the rowid sentinel a bare count(*) projects) stay NULL.
			break;
		}
	}
}

//===--------------------------------------------------------------------===//
// Request building
//===--------------------------------------------------------------------===//

//! Prepend `search ` unless the query already begins with a Splunk command: an explicit `search`,
//! or a generating command introduced by a leading pipe (`| tstats ...`).
static string NormalizeSearchQuery(const string &query) {
	string trimmed = query;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return "search *";
	}
	if (trimmed[0] == '|') {
		return trimmed;
	}
	string lower = StringUtil::Lower(trimmed);
	if (StringUtil::StartsWith(lower, "search ")) {
		return trimmed;
	}
	return "search " + trimmed;
}

//! Build the form-encoded body for POST /services/search/v2/jobs/export.
static string BuildExportBody(const string &query, const string &earliest, const string &latest, int64_t max_rows) {
	string body = "search=" + StringUtil::URLEncode(NormalizeSearchQuery(query));
	body += "&earliest_time=" + StringUtil::URLEncode(earliest);
	body += "&latest_time=" + StringUtil::URLEncode(latest);
	body += "&output_mode=json";
	// `count` caps results server-side; 0 = unlimited (the default), so only send it when capping.
	if (max_rows > 0) {
		body += "&count=" + std::to_string(max_rows);
	}
	return body;
}

//! Build a safe index restriction for a catalog table. Splunk string literals use backslash
//! escaping for quotes and backslashes.
static string BuildIndexQuery(const string &index_name) {
	string escaped;
	escaped.reserve(index_name.size());
	for (auto ch : index_name) {
		if (ch == '\\' || ch == '"') {
			escaped.push_back('\\');
		}
		escaped.push_back(ch);
	}
	return "index=\"" + escaped + "\"";
}

//===--------------------------------------------------------------------===//
// Response parsing (Splunk export returns newline-delimited JSON)
//===--------------------------------------------------------------------===//

//! Invoke `on_event` for each result event in one parsed export line. Handles the export shape
//! ({"preview":false,"result":{...}}), a buffered {"results":[...]} array, and a flat event object.
//! Skips control/metadata lines (messages, previews).
template <class Fn>
static void ExtractEventsFromRoot(yyjson_val *root, Fn &&on_event) {
	if (!root || !yyjson_is_obj(root)) {
		return;
	}

	// Skip preview rows: a historical export emits final results (preview=false), but guard against
	// duplicate rows if a real-time/preview stream is ever encountered.
	yyjson_val *preview = yyjson_obj_get(root, "preview");
	if (preview && yyjson_is_bool(preview) && yyjson_get_bool(preview)) {
		return;
	}

	yyjson_val *result = yyjson_obj_get(root, "result");
	if (result && yyjson_is_obj(result)) {
		on_event(result);
		return;
	}

	yyjson_val *results = yyjson_obj_get(root, "results");
	if (results && yyjson_is_arr(results)) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(results, idx, max, item) {
			if (yyjson_is_obj(item)) {
				on_event(item);
			}
		}
		return;
	}

	// Flat event: only treat as a real event if it carries event-ish fields (avoids mapping a
	// stray {"messages":[...]} control line as an empty row).
	if (yyjson_obj_get(root, "_time") || yyjson_obj_get(root, "_raw") || yyjson_obj_get(root, "message")) {
		on_event(root);
	}
}

//! Splunk reports search errors in the export stream as a control line
//! {"messages":[{"type":"FATAL","text":"..."}]}, frequently with HTTP 200 and no results — so a bad
//! query would otherwise look indistinguishable from "no matches". Throw on the first ERROR/FATAL
//! message to make the failure visible; INFO/DEBUG/WARN messages are informational and ignored.
static void ThrowIfSearchError(yyjson_val *root) {
	if (!root || !yyjson_is_obj(root)) {
		return;
	}
	yyjson_val *messages = yyjson_obj_get(root, "messages");
	if (!messages || !yyjson_is_arr(messages)) {
		return;
	}
	size_t idx, max;
	yyjson_val *msg;
	yyjson_arr_foreach(messages, idx, max, msg) {
		const char *type = GetStr(msg, "type");
		if (type && (StringUtil::CIEquals(type, "FATAL") || StringUtil::CIEquals(type, "ERROR"))) {
			const char *text = GetStr(msg, "text");
			throw IOException("Splunk search error (%s): %s", type, text ? text : "(no detail)");
		}
	}
}

//! Parse one newline-delimited export record. Malformed lines are ignored, matching the previous
//! defensive parser behavior, while valid Splunk ERROR/FATAL control records still fail the scan.
template <class Fn>
static void ParseExportLine(const char *line, idx_t length, Fn &&on_event) {
	while (length > 0 && line[length - 1] == '\r') {
		length--;
	}
	if (length == 0) {
		return;
	}
	YyjsonDocPtr doc(yyjson_read(line, length, 0));
	if (!doc) {
		return;
	}
	auto root = yyjson_doc_get_root(doc.get());
	ThrowIfSearchError(root);
	ExtractEventsFromRoot(root, std::forward<Fn>(on_event));
}

//===--------------------------------------------------------------------===//
// Table function state
//===--------------------------------------------------------------------===//

struct SplunkLogsBindData : public TableFunctionData {
	string query = "*";
	string earliest = "-15m";
	string latest = "now";
	int64_t max_rows = 0; // 0 = unlimited
	TableCatalogEntry *table = nullptr;
	SplunkClient client;
};

struct SplunkLogsGlobalState : public GlobalTableFunctionState {
	//! Source column for each output slot (projection pushdown); may contain virtual-column
	//! sentinels (e.g. rowid for a bare count(*)), which MapEvent leaves NULL.
	vector<column_t> column_ids;
	//! Projected rows ready for the execution thread. Native builds cap this at two DuckDB vectors;
	//! the producer blocks when it is full, bounding decoded-row memory independently of result size.
	std::deque<vector<Value>> buffer;
	SplunkClient client;

#ifdef __EMSCRIPTEN__
	//! Browser fetch currently exposes a completed response body. Keep a cursor into it and decode
	//! only the rows requested by each scan call, avoiding a second all-rows materialization.
	string response;
	idx_t response_offset = 0;
	idx_t produced = 0;
	bool fetched = false;
#else
	std::mutex mutex;
	std::condition_variable rows_available;
	std::condition_variable space_available;
	std::thread producer;
	std::exception_ptr error;
	bool started = false;
	bool finished = false;
	bool cancelled = false;

	~SplunkLogsGlobalState() override {
		{
			std::lock_guard<std::mutex> guard(mutex);
			cancelled = true;
		}
		space_available.notify_all();
		client.Cancel();
		if (producer.joinable()) {
			producer.join();
		}
	}
#endif

	idx_t MaxThreads() const override {
		return 1;
	}
};

#ifndef __EMSCRIPTEN__
static constexpr idx_t SPLUNK_BUFFER_CAPACITY = STANDARD_VECTOR_SIZE * 2;

//! Start the socket reader on first scan. It parses complete NDJSON lines from arbitrary network
//! chunks and blocks after two vectors of decoded rows, providing backpressure all the way to the
//! response socket. A single partial JSON line is the only unbounded parser allocation.
static void StartExport(ClientContext &context, const SplunkLogsBindData &bind, SplunkLogsGlobalState &state) {
	bind.client.CopyConfigTo(state.client);
	auto body = BuildExportBody(bind.query, bind.earliest, bind.latest, bind.max_rows);
	auto cap = bind.max_rows > 0 ? static_cast<idx_t>(bind.max_rows) : 0;
	state.producer = std::thread([&context, &state, body, cap]() {
		try {
			string pending;
			idx_t produced = 0;
			bool limit_reached = false;

			auto parse_line = [&](const char *line, idx_t length) {
				ParseExportLine(line, length, [&](yyjson_val *event) {
					if (limit_reached) {
						return;
					}
					if (cap > 0 && produced >= cap) {
						limit_reached = true;
						return;
					}
					vector<Value> row;
					MapEvent(event, state.column_ids, row);

					std::unique_lock<std::mutex> lock(state.mutex);
					state.space_available.wait(lock, [&]() {
						return state.cancelled || context.interrupted || state.buffer.size() < SPLUNK_BUFFER_CAPACITY;
					});
					if (state.cancelled || context.interrupted) {
						limit_reached = true;
						return;
					}
					state.buffer.push_back(std::move(row));
					produced++;
					lock.unlock();
					state.rows_available.notify_one();
				});
			};

			state.client.ExportSearch(context, body, [&](const char *data, idx_t length) {
				pending.append(data, length);
				idx_t start = 0;
				while (!limit_reached) {
					auto newline = pending.find('\n', start);
					if (newline == string::npos) {
						break;
					}
					parse_line(pending.data() + start, newline - start);
					start = newline + 1;
				}
				if (start > 0) {
					pending.erase(0, start);
				}
				return !limit_reached;
			});
			if (!limit_reached && !pending.empty()) {
				parse_line(pending.data(), pending.size());
			}
		} catch (...) {
			std::lock_guard<std::mutex> guard(state.mutex);
			if (!state.cancelled) {
				state.error = std::current_exception();
			}
		}

		{
			std::lock_guard<std::mutex> guard(state.mutex);
			state.finished = true;
		}
		state.rows_available.notify_all();
	});
	state.started = true;
}
#else
static void FetchBrowserResponse(ClientContext &context, const SplunkLogsBindData &bind, SplunkLogsGlobalState &state) {
	bind.client.CopyConfigTo(state.client);
	auto body = BuildExportBody(bind.query, bind.earliest, bind.latest, bind.max_rows);
	state.client.ExportSearch(context, body, [&](const char *data, idx_t length) {
		state.response.append(data, length);
		return true;
	});
	state.fetched = true;
}
#endif

static unique_ptr<FunctionData> SplunkLogsBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<SplunkLogsBindData>();
	string secret_name;

	for (auto &param : input.named_parameters) {
		auto key = StringUtil::Lower(param.first);
		if (param.second.IsNull()) {
			continue;
		}
		if (key == "query") {
			result->query = param.second.ToString();
		} else if (key == "earliest") {
			result->earliest = param.second.ToString();
		} else if (key == "latest") {
			result->latest = param.second.ToString();
		} else if (key == "max_rows") {
			result->max_rows = param.second.GetValue<int64_t>();
		} else if (key == "retries") {
			auto retries = param.second.GetValue<int64_t>();
			if (retries < 0) {
				throw InvalidInputException("read_splunk_logs: retries must be >= 0 (0 disables retrying)");
			}
			result->client.retries = static_cast<uint64_t>(retries);
		} else if (key == "timeout") {
			auto timeout = param.second.GetValue<int64_t>();
			if (timeout < 1) {
				throw InvalidInputException("read_splunk_logs: timeout must be >= 1 (seconds)");
			}
			result->client.timeout_seconds = static_cast<uint64_t>(timeout);
		} else if (key == "secret") {
			secret_name = param.second.ToString();
		}
	}

	if (result->max_rows < 0) {
		throw InvalidInputException("read_splunk_logs: max_rows must be >= 0 (0 means unlimited)");
	}

	auto credentials = GetSplunkCredentials(context, secret_name);
	result->client.url = credentials.url;
	result->client.username = credentials.username;
	result->client.password = credentials.password;
	result->client.token = credentials.token;
	result->client.token_type = credentials.token_type;
	result->client.insecure_tls = credentials.insecure_tls;

	GetSplunkLogsSchema(return_types, names);
	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> SplunkLogsInitGlobal(ClientContext &context,
                                                                 TableFunctionInitInput &input) {
	auto state = make_uniq<SplunkLogsGlobalState>();
	state->column_ids = input.column_ids;
	return std::move(state);
}

static void SplunkLogsScan(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &bind = data_p.bind_data->Cast<SplunkLogsBindData>();
	auto &state = data_p.global_state->Cast<SplunkLogsGlobalState>();

	idx_t count = 0;
#ifdef __EMSCRIPTEN__
	if (!state.fetched) {
		FetchBrowserResponse(context, bind, state);
	}

	// First drain overflow from a buffered `results` array, then parse as many NDJSON records as fit
	// in this output vector. The raw browser response is retained once, but decoded rows are not
	// materialized wholesale.
	while (count < STANDARD_VECTOR_SIZE && !state.buffer.empty()) {
		auto &row = state.buffer.front();
		for (idx_t col = 0; col < row.size(); col++) {
			output.SetValue(col, count, row[col]);
		}
		state.buffer.pop_front();
		count++;
	}
	while (count < STANDARD_VECTOR_SIZE && state.response_offset < state.response.size()) {
		if (bind.max_rows > 0 && state.produced >= static_cast<idx_t>(bind.max_rows)) {
			state.response_offset = state.response.size();
			break;
		}
		auto newline = state.response.find('\n', state.response_offset);
		if (newline == string::npos) {
			newline = state.response.size();
		}
		ParseExportLine(state.response.data() + state.response_offset, newline - state.response_offset,
		                [&](yyjson_val *event) {
			                if (bind.max_rows > 0 && state.produced >= static_cast<idx_t>(bind.max_rows)) {
				                return;
			                }
			                vector<Value> row;
			                MapEvent(event, state.column_ids, row);
			                state.produced++;
			                if (count < STANDARD_VECTOR_SIZE) {
				                for (idx_t col = 0; col < row.size(); col++) {
					                output.SetValue(col, count, row[col]);
				                }
				                count++;
			                } else {
				                state.buffer.push_back(std::move(row));
			                }
		                });
		state.response_offset = newline + 1;
	}
#else
	if (!state.started) {
		StartExport(context, bind, state);
	}

	std::unique_lock<std::mutex> lock(state.mutex);
	while (state.buffer.empty() && !state.finished && !state.error) {
		if (context.interrupted) {
			state.cancelled = true;
			lock.unlock();
			state.space_available.notify_all();
			state.client.Cancel();
			throw InterruptException();
		}
		state.rows_available.wait_for(lock, std::chrono::milliseconds(100));
	}
	if (state.error) {
		auto error = state.error;
		lock.unlock();
		std::rethrow_exception(error);
	}
	while (count < STANDARD_VECTOR_SIZE && !state.buffer.empty()) {
		auto &row = state.buffer.front();
		for (idx_t col = 0; col < row.size(); col++) {
			output.SetValue(col, count, row[col]);
		}
		state.buffer.pop_front();
		count++;
	}
	lock.unlock();
	state.space_available.notify_one();
#endif

	output.SetCardinality(count);
}

void RegisterSplunkLogsFunction(ExtensionLoader &loader) {
	TableFunction function("read_splunk_logs", {}, SplunkLogsScan, SplunkLogsBind, SplunkLogsInitGlobal);
	function.named_parameters["query"] = LogicalType::VARCHAR;
	function.named_parameters["earliest"] = LogicalType::VARCHAR;
	function.named_parameters["latest"] = LogicalType::VARCHAR;
	function.named_parameters["max_rows"] = LogicalType::BIGINT;
	function.named_parameters["retries"] = LogicalType::BIGINT;
	function.named_parameters["timeout"] = LogicalType::BIGINT;
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	// Only projected columns are mapped from the response; a count(*) or GROUP BY service_name
	// never pays the per-row log_attributes JSON serialization.
	function.projection_pushdown = true;
	loader.RegisterFunction(function);
}

static BindInfo SplunkLogsGetBindInfo(const optional_ptr<FunctionData> bind_data) {
	auto &data = bind_data->Cast<SplunkLogsBindData>();
	D_ASSERT(data.table);
	return BindInfo(*data.table);
}

TableFunction GetSplunkLogsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                     const string &index_name, unique_ptr<FunctionData> &bind_data) {
	auto result = make_uniq<SplunkLogsBindData>();
	result->query = BuildIndexQuery(index_name);
	result->table = &table;
	auto credentials = GetSplunkCredentials(context, secret_name);
	result->client.url = credentials.url;
	result->client.username = credentials.username;
	result->client.password = credentials.password;
	result->client.token = credentials.token;
	result->client.token_type = credentials.token_type;
	result->client.insecure_tls = credentials.insecure_tls;
	bind_data = std::move(result);

	TableFunction function("splunk_logs_scan", {}, SplunkLogsScan, nullptr, SplunkLogsInitGlobal);
	function.projection_pushdown = true;
	function.get_bind_info = SplunkLogsGetBindInfo;
	return function;
}

} // namespace duckdb

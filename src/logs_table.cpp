#include "logs_table.hpp"

#include "splunk_client.hpp"
#include "splunk_secret.hpp"

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

static void GetLogsSchema(vector<LogicalType> &types, vector<string> &names) {
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
//!
//! Follows the OpenTelemetry log data model's "Appendix B: SeverityNumber example mappings", which
//! is the authority for the freeform level vocabularies (syslog, log4j, zap, ...) that reach a
//! Splunk index. Note `notice` is INFO2 (10), *not* INFO — and the top of the scale stays ordered:
//! critical (18) < alert (19) < emergency/fatal (21). Collapsing those onto a single value would
//! make `severity_number > 17` unable to distinguish a critical from an emergency.
//!
//! Kept identical to `StatusToSeverityNumber` in the sibling `duckdb-datadog`, so `severity_number`
//! compares meaningfully across a UNION ALL of both readers. `duckdb-gcloud-observability`
//! deliberately differs above ERROR: Cloud Logging's LogSeverity is a fixed nine-value enum that the
//! OpenTelemetry Collector maps CRITICAL -> 21, ALERT -> 22, EMERGENCY -> 24, and matching the
//! collector matters more there than matching this table.
static int32_t SeverityToNumber(const string &severity) {
	auto s = StringUtil::Lower(severity);
	if (s == "trace") {
		return 1;
	}
	if (s == "debug") {
		return 5;
	}
	if (s == "info" || s == "ok") {
		return 9;
	}
	if (s == "notice") {
		return 10;
	}
	if (s == "warn" || s == "warning") {
		return 13;
	}
	if (s == "error" || s == "err") {
		return 17;
	}
	if (s == "critical" || s == "crit") {
		return 18;
	}
	if (s == "alert") {
		return 19;
	}
	if (s == "emergency" || s == "fatal") {
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

//===--------------------------------------------------------------------===//
// Table function state
//===--------------------------------------------------------------------===//

struct SplunkLogsBindData : public TableFunctionData {
	string query = "*";
	string earliest = "-15m";
	string latest = "now";
	int64_t max_rows = 0; // 0 = unlimited
	SplunkClient client;
};

struct SplunkLogsGlobalState : public GlobalTableFunctionState {
	//! Source column for each output slot (projection pushdown); may contain virtual-column
	//! sentinels (e.g. rowid for a bare count(*)), which MapEvent leaves NULL.
	vector<column_t> column_ids;
	//! Rows (projected columns only) parsed and waiting to be emitted. FetchAll caps this at
	//! `max_rows`, so the scan can drain it without re-checking the limit.
	std::deque<vector<Value>> buffer;
	bool fetched = false;

	idx_t MaxThreads() const override {
		return 1; // One buffered export request; scanning is sequential.
	}
};

//! Issue the export search once and parse its newline-delimited JSON body into `state.buffer`,
//! honoring `max_rows`. Splunk's export endpoint returns the full [earliest, latest] window in one
//! streamed response, so a single request suffices for the first version.
static void FetchAll(ClientContext &context, const SplunkLogsBindData &bind, SplunkLogsGlobalState &state) {
	string body = BuildExportBody(bind.query, bind.earliest, bind.latest, bind.max_rows);
	string response = bind.client.ExportSearch(context, body);
	state.fetched = true;

	idx_t cap = bind.max_rows > 0 ? static_cast<idx_t>(bind.max_rows) : 0;

	// The response is one JSON object per line. Parse each line independently so a single malformed
	// line cannot abort the whole scan.
	size_t start = 0;
	const size_t len = response.size();
	bool capped = false;
	while (start < len && !capped) {
		size_t end = response.find('\n', start);
		if (end == string::npos) {
			end = len;
		}
		// Trim trailing '\r' for CRLF-delimited streams.
		size_t line_end = end;
		if (line_end > start && response[line_end - 1] == '\r') {
			line_end--;
		}
		if (line_end > start) {
			YyjsonDocPtr doc(yyjson_read(response.c_str() + start, line_end - start, 0));
			if (doc) {
				yyjson_val *root = yyjson_doc_get_root(doc.get());
				// Surface a server-side search error (bad SPL, etc.) instead of returning 0 rows.
				ThrowIfSearchError(root);
				ExtractEventsFromRoot(root, [&](yyjson_val *event) {
					if (cap > 0 && state.buffer.size() >= cap) {
						capped = true;
						return;
					}
					vector<Value> row;
					MapEvent(event, state.column_ids, row);
					state.buffer.push_back(std::move(row));
				});
			}
		}
		start = end + 1;
	}
}

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

	GetLogsSchema(return_types, names);
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

	// One buffered fetch on the first scan call; subsequent calls drain the buffer. FetchAll already
	// capped the buffer at max_rows, so the drain loop just emits what is there.
	if (!state.fetched) {
		FetchAll(context, bind, state);
	}

	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && !state.buffer.empty()) {
		auto &row = state.buffer.front();
		for (idx_t col = 0; col < row.size(); col++) {
			output.SetValue(col, count, row[col]);
		}
		state.buffer.pop_front();
		count++;
	}

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

} // namespace duckdb

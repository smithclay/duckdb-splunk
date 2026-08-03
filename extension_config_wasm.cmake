# Browser build. DuckDB-WASM supplies HTTPUtil/fetch, so OpenSSL and native
# sockets are excluded by CMakeLists.txt and vcpkg.json.
duckdb_extension_load(splunk SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR})

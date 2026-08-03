cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME splunk)

# Native HTTP uses DuckDB's bundled cpp-httplib with OpenSSL. Browser builds use
# DuckDB-WASM's HTTPUtil/fetch transport and therefore need neither native
# sockets nor OpenSSL. JSON always uses DuckDB's bundled yyjson.
if(NOT EMSCRIPTEN)
  find_package(OpenSSL REQUIRED)
endif()

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD
    "17"
    CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Locate DuckDB's bundled third-party headers (httplib + yyjson).
set(SPLUNK_DUCKDB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/duckdb")
if(NOT EXISTS "${SPLUNK_DUCKDB_DIR}/third_party/httplib/httplib.hpp")
  # When built from within the DuckDB tree the submodule may live one level up.
  set(SPLUNK_DUCKDB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../duckdb")
endif()

include_directories(src/include)

set(EXTENSION_SOURCES
    src/splunk_extension.cpp src/splunk_secret.cpp src/splunk_client.cpp
    src/logs_table.cpp src/splunk_catalog.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
  target_include_directories(
    ${target} PRIVATE "${SPLUNK_DUCKDB_DIR}/third_party/yyjson/include")
  if(NOT EMSCRIPTEN)
    target_include_directories(
      ${target} PRIVATE "${SPLUNK_DUCKDB_DIR}/third_party/httplib")
    # Select cpp-httplib's OpenSSL-enabled, separately-namespaced build.
    target_compile_definitions(${target} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(${target} OpenSSL::SSL OpenSSL::Crypto)
  endif()
endforeach()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

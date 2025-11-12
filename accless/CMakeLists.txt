# -----------------------------------------------------------------------------
# Accless access control C++ library
#
# This library supports native compilation and cross-compilation to WebAssembly.
# Each version of the library has slightly different features:
# - Native:
#       - library to interact with S3 KV
#       - library to fetch a cVM's attestation from a vTPM on Azure
# - WASM:
# -----------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.8.0)
project(accless)

set(CMAKE_PROJECT_TARGET accless)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(ACCLESS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

# Third-party projects we fetch using CMake.
if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # Third-party deps for native builds.
    include(cmake/NativeExternalProjects.cmake)
else ()
    include(cmake/WasmExternalProjects.cmake)
endif ()

# Hints to find the custom libriares that we install in the docker container:
# ./config/docker/accless-experiments.dockerfile
if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # Make custom prefixes visible to *all* find_package() calls in subdirs
    list(PREPEND CMAKE_PREFIX_PATH
        "/usr/local/attestationssl"
        "/usr/local/attestationcurl"
    )

    # OpenSSL hints
    set(OPENSSL_ROOT_DIR "/usr/local/attestationssl" CACHE PATH "")
    set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL "")
    set(OPENSSL_INCLUDE_DIR "/usr/local/attestationssl/include" CACHE PATH "")
    set(OPENSSL_CRYPTO_LIBRARY "/usr/local/attestationssl/lib64/libcrypto.a" CACHE FILEPATH "")
    set(OPENSSL_SSL_LIBRARY    "/usr/local/attestationssl/lib64/libssl.a"    CACHE FILEPATH "")

    # Curl hints
    set(CURL_INCLUDE_DIR "/usr/local/attestationcurl/include" CACHE PATH "")
    set(CURL_LIBRARY     "/usr/local/attestationcurl/lib/libcurl.a" CACHE FILEPATH "")
endif ()

add_library(${CMAKE_PROJECT_TARGET}
    ./src/accless.cpp
    ./src/dag.cpp
    ./src/utils.cpp
)

# TODO: for the time being we need to comment this if out if we want UBENCH
# in WASM because there is  no easy way to pass CMake vars to `wasm_cmake` in
# faasmtools
if (ACCLESS_UBENCH)
    message(STATUS "Building UBENCH")
    target_compile_definitions(${CMAKE_PROJECT_TARGET} PUBLIC ACCLESS_UBENCH)
endif ()

# Common libraries and headers that support WASM and native compilation
add_subdirectory(./libs/jwt/cpp-bindings)
add_subdirectory(./libs/abe4/cpp-bindings)
add_subdirectory(./libs/base64)

set(ACCLESS_COMMON_HEADERS
    ${ACCLESS_ROOT}/include
    ${ACCLESS_ROOT}/libs/jwt/cpp-bindings
    ${ACCLESS_ROOT}/libs/abe4/cpp-bindings
    ${ACCLESS_ROOT}/libs/base64
)
set(ACCLESS_COMMON_LIBRARIES accless::jwt accless::abe4 accless::base64)

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # The WASM version of the library relies on a pre-populated sysroot as part
    # of a Faasm installation
    set(ACCLESS_LIBRARIES faasm)
else ()
    # This lines do not suppress the warning
    set(MY_CUSTOM_RPATH "/usr/local/attestationcurl/lib;/usr/local/attestationssl/lib64")
    set(CMAKE_BUILD_RPATH "${MY_CUSTOM_RPATH}")
    set(CMAKE_INSTALL_RPATH "${MY_CUSTOM_RPATH}")
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    target_link_directories(${CMAKE_PROJECT_TARGET} PRIVATE BEFORE
        /usr/local/attestationcurl/lib
        /usr/local/attestationssl/lib64
    )

    target_compile_options(${CMAKE_PROJECT_TARGET} PRIVATE -Wno-deprecated-declarations)

    # The WASM version of the attestation and S3 libraries is part of Faasm
    # because it needs to execute (partially) outside of the WASM module
    # and outside of the enclave
    add_subdirectory(./libs/attestation)
    add_subdirectory(./libs/s3)

    set(ACCLESS_LIBRARIES
        accless::s3
        accless::attestation
        # We use the installed curl as part of azure-cvm-attestation
        /usr/local/attestationcurl/lib/libcurl.a
    )
    set(ACCLESS_HEADERS ${ACCLESS_ROOT}/libs)
endif()

target_include_directories(${CMAKE_PROJECT_TARGET} PUBLIC
    ${ACCLESS_COMMON_HEADERS}
    ${ACCLESS_HEADERS}
)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC
    ${ACCLESS_COMMON_LIBRARIES}
    ${ACCLESS_LIBRARIES}
)

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # Manually install the .imports file so that we can link against it
    add_custom_command(
        TARGET ${CMAKE_PROJECT_TARGET}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${ACCLESS_ROOT}/libaccless.imports ${CMAKE_CURRENT_BINARY_DIR}/libaccless.imports
        COMMENT "Created ${PROJECT_BINARY_DIR}/libaccless.imports"
    )
endif ()

add_library(accless::accless ALIAS accless)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    add_subdirectory(tests)
endif()

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

add_library(${CMAKE_PROJECT_TARGET}
    ./src/tless.cpp
    ./src/dag.cpp
    ./src/utils.cpp
)

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # The WASM version of the library relies on a pre-populated sysroot as part
    # of a Faasm installation
    set(ACCLESS_LIBRARIES
        faasm
        rabe-cpp
        rabe
        tless-jwt-cpp
        tless-jwt
    )

    set(ACCLESS_HEADERS ./include)
else ()
    set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS} -O3")

    add_subdirectory(./libs/s3)

    set(ACCLESS_LIBRARIES
        accless::s3
        # Order matters: librabe-cpp must preceede librabe
        "/usr/local/lib/rabe/librabe-cpp.a"
        "/usr/local/lib/rabe/librabe.a"
    )
    set(ACCLESS_HEADERS
        ./include
        "/usr/include/rabe"
    )
endif()

target_include_directories(accless PUBLIC "/usr/include/rabe")
target_link_libraries(tless PUBLIC ${TLESS_LIBRARIES})

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # Manually install the .imports file so that we can link against it
    add_custom_command(
        TARGET tless
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/libaccless.imports ${CMAKE_CURRENT_BINARY_DIR}/libaccless.imports
        COMMENT "Created ${PROJECT_BINARY_DIR}/libaccless.imports"
    )
endif ()

add_library(accless::accless ALIAS accless)

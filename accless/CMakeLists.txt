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
    ./src/accless.cpp
    ./src/dag.cpp
    ./src/utils.cpp
)

# TODO: for the time being we need to comment this if out if we want UBENCH
# in WASM because there is  no easy way to pass CMake vars to `wasm_cmake` in
# faasmtools
if (ACCLESS_UBENCH)
    target_compile_definitions(${CMAKE_PROJECT_TARGET} PUBLIC ACCLESS_UBENCH)
endif ()

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

    set(ACCLESS_HEADERS ${CMAKE_CURRENT_LIST_DIR}/include)
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

    add_subdirectory(./libs/attestation)
    add_subdirectory(./libs/s3)

    set(ACCLESS_LIBRARIES
        accless::s3
        accless::attestation
        # We use the installed curl as part of azure-cvm-attestation
        /usr/local/attestationcurl/lib/libcurl.a
        # Order matters: librabe-cpp must preceede librabe
        "/usr/local/lib/rabe/librabe-cpp.a"
        "/usr/local/lib/rabe/librabe.a"
        # Same for JWT
        "/usr/local/lib/tless-jwt/libtless-jwt-cpp.a"
        "/usr/local/lib/tless-jwt/libtless_jwt.a"
    )
    set(ACCLESS_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/libs
        "/usr/include/rabe"
        "/usr/include/tless-jwt"
    )
endif()

target_include_directories(${CMAKE_PROJECT_TARGET} PUBLIC ${ACCLESS_HEADERS})
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC ${ACCLESS_LIBRARIES})

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # Manually install the .imports file so that we can link against it
    add_custom_command(
        TARGET ${CMAKE_PROJECT_TARGET}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/libaccless.imports ${CMAKE_CURRENT_BINARY_DIR}/libaccless.imports
        COMMENT "Created ${PROJECT_BINARY_DIR}/libaccless.imports"
    )
endif ()

add_library(accless::accless ALIAS accless)

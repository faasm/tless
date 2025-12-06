set(CMAKE_PROJECT_TARGET jwt-cpp)

# ------------------------------------------------------------------------------
# Build Rust JWT library
# ------------------------------------------------------------------------------

set(CARGO_FLAGS --release)
set(JWT_RUST_LIBRARY "${ACCLESS_ROOT}/../target/release/libjwt.a" CACHE INTERNAL "")
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(CARGO_FLAGS --release --target=wasm32-wasip1)
    set(JWT_RUST_LIBRARY "${ACCLESS_ROOT}/../target/wasm32-wasip1/release/libjwt.a" CACHE INTERNAL "")
endif ()

add_library(jwt_rust_lib STATIC IMPORTED GLOBAL)

# This cert path can be set from: -DACCLESS_AS_CERT_DIR=/path/to/cert/dir
message(STATUS "Injecting AS certificates to JWT library from: '${ACCLESS_AS_CERT_DIR}'")

# It may be that we are building the accless library as a third-party dependency
# from another project (like when we build guest modules for Knative). In that
# case, we want to be able to inject the AS certificate path as a CMake argument
# that is then passed to the Rust build as an env. var.
set_property(TARGET jwt_rust_lib APPEND PROPERTY
    CARGO_ENV
        ACCLESS_AS_CERT_DIR=${ACCLESS_AS_CERT_DIR}
)
add_custom_command(
    OUTPUT ${JWT_RUST_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E env
            ACCLESS_AS_CERT_DIR=${ACCLESS_AS_CERT_DIR}
            cargo build -p jwt ${CARGO_FLAGS} > /dev/null 2>&1
    COMMENT "Building JWT staticlib with Cargo"
    WORKING_DIRECTORY ${ACCLESS_ROOT}/..
)

add_custom_target(jwt_rust_build DEPENDS ${JWT_RUST_LIBRARY})

set_target_properties(jwt_rust_lib PROPERTIES
    IMPORTED_LOCATION ${JWT_RUST_LIBRARY}
)

add_dependencies(jwt_rust_lib jwt_rust_build)

# ------------------------------------------------------------------------------
# Build CPP bindings
# ------------------------------------------------------------------------------

add_library(${CMAKE_PROJECT_TARGET} jwt.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC jwt_rust_lib)
add_library(accless::jwt ALIAS ${CMAKE_PROJECT_TARGET})

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(TESTS_TARGET jwt_cpp_tests)
    add_executable(${TESTS_TARGET} tests.cpp)
    target_link_libraries(${TESTS_TARGET} PRIVATE
        GTest::gtest_main
        accless::jwt
    )
    target_compile_options(${TESTS_TARGET} PRIVATE -Wno-deprecated-declarations)

    include(GoogleTest)
    gtest_discover_tests(${TESTS_TARGET} TEST_PREFIX jwt::)
endif ()


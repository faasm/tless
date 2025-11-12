set(CMAKE_PROJECT_TARGET abe4-cpp)

# ------------------------------------------------------------------------------
# Build Rust ABE4 library
# ------------------------------------------------------------------------------

set(CARGO_FLAGS --release)
set(ABE4_RUST_LIBRARY "${ACCLESS_ROOT}/../target/release/libabe4.a" CACHE INTERNAL "")
set(ABE4_ROOT_DIR "${ACCLESS_ROOT}/libs/abe4/cpp-bindings")
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(CARGO_FLAGS --release --target=wasm32-wasip1)
    set(ABE4_RUST_LIBRARY "${ACCLESS_ROOT}/../target/wasm32-wasip1/release/libabe4.a" CACHE INTERNAL "")
endif ()

add_library(abe4_rust_lib STATIC IMPORTED GLOBAL)

file(GLOB_RECURSE ABE4_RUST_SOURCES CONFIGURE_DEPENDS
    "${ABE4_ROOT_DIR}/src/*.rs"
    "${ABE4_ROOT_DIR}/Cargo.toml"
    "${ABE4_ROOT_DIR}/Cargo.lock"
)

add_custom_command(
    OUTPUT ${ABE4_RUST_LIBRARY}
    COMMAND cargo build -p abe4 ${CARGO_FLAGS} > /dev/null 2>&1
    COMMENT "Building ABE4 staticlib with Cargo"
    WORKING_DIRECTORY ${ACCLESS_ROOT}/..
    DEPENDS ${ABE4_RUST_SOURCES}
)

add_custom_target(abe4_rust_build DEPENDS ${ABE4_RUST_LIBRARY})

set_target_properties(abe4_rust_lib PROPERTIES
    IMPORTED_LOCATION ${ABE4_RUST_LIBRARY}
)

add_dependencies(abe4_rust_lib abe4_rust_build)

# ------------------------------------------------------------------------------
# Build CPP bindings
# ------------------------------------------------------------------------------

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
endif ()

add_library(${CMAKE_PROJECT_TARGET} abe4.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC
    abe4_rust_lib
    nlohmann_json::nlohmann_json
    accless::base64
)
target_include_directories(${CMAKE_PROJECT_TARGET} PUBLIC
    ${ACCLESS_ROOT}/libs/base64
)
add_library(accless::abe4 ALIAS ${CMAKE_PROJECT_TARGET})

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(TESTS_TARGET abe_cpp_tests)
    add_executable(${TESTS_TARGET} tests.cpp)
    target_link_libraries(${TESTS_TARGET} PRIVATE
        GTest::gtest_main
        accless::abe4
    )
    target_compile_options(${TESTS_TARGET} PRIVATE -Wno-deprecated-declarations)

    include(GoogleTest)
    gtest_discover_tests(${TESTS_TARGET} TEST_PREFIX abe4::)

    set(API_TESTS_TARGET abe_cpp_api_tests)
    add_executable(${API_TESTS_TARGET} api_tests.cpp)
    target_link_libraries(${API_TESTS_TARGET} PRIVATE
        GTest::gtest_main
        accless::abe4
    )
    target_compile_options(${API_TESTS_TARGET} PRIVATE -Wno-deprecated-declarations)

    include(GoogleTest)
    gtest_discover_tests(${API_TESTS_TARGET} TEST_PREFIX abe4::)
endif ()

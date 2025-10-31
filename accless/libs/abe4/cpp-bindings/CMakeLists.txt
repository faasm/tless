set(CMAKE_PROJECT_TARGET abe4-cpp)

# ------------------------------------------------------------------------------
# Build Rust ABE4 library
# ------------------------------------------------------------------------------

set(CARGO_FLAGS --release)
set(ABE4_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../target/release/libaccless_abe4.a" CACHE INTERNAL "")
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(CARGO_FLAGS --release --target=wasm32-wasip1)
    set(ABE4_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../target/wasm32-wasip1/release/libaccless_abe4.a" CACHE INTERNAL "")
endif ()

add_library(abe4_rust_lib STATIC IMPORTED GLOBAL)

add_custom_command(
    OUTPUT ${ABE4_RUST_LIBRARY}
    COMMAND CARGO_TARGET_DIR=${CMAKE_SOURCE_DIR}/../target cargo build
        --manifest-path ${CMAKE_SOURCE_DIR}/../Cargo.toml -p accless-abe4
        ${CARGO_FLAGS} > /dev/null 2>&1
    COMMENT "Building ABE4 staticlib with Cargo"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
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
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3 # Use a specific, stable version tag
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif ()

add_library(${CMAKE_PROJECT_TARGET} abe4.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC
    abe4_rust_lib
    nlohmann_json::nlohmann_json
)
add_library(accless::abe4 ALIAS ${CMAKE_PROJECT_TARGET})

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(TESTS_TARGET abe_cpp_tests)
    add_executable(${TESTS_TARGET} tests.cpp)
    target_link_libraries(${TESTS_TARGET} PRIVATE GTest::gtest_main)
    target_compile_options(${TESTS_TARGET} PRIVATE -Wno-deprecated-declarations)

    include(GoogleTest)
    gtest_discover_tests(${TESTS_TARGET} TEST_PREFIX abe4::)
endif ()

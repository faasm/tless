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
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}/../target cargo build
        --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/../Cargo.toml
        ${CARGO_FLAGS}
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

add_library(${CMAKE_PROJECT_TARGET} abe4.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC abe4_rust_lib)
add_library(accless::abe4 ALIAS ${CMAKE_PROJECT_TARGET})

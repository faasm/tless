set(CMAKE_PROJECT_TARGET jwt-cpp)

# ------------------------------------------------------------------------------
# Build Rust JWT library
# ------------------------------------------------------------------------------

set(CARGO_FLAGS --release)
set(JWT_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../target/release/libaccless_jwt.a" CACHE INTERNAL "")
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(CARGO_FLAGS --release --target=wasm32-wasip1)
    set(JWT_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../target/wasm32-wasip1/release/libaccless_jwt.a" CACHE INTERNAL "")
endif ()

add_library(jwt_rust_lib STATIC IMPORTED GLOBAL)

add_custom_command(
    OUTPUT ${JWT_RUST_LIBRARY}
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}/../target cargo build
        --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/../Cargo.toml
        ${CARGO_FLAGS}
    COMMENT "Building JWT staticlib with Cargo"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
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

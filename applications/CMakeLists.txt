cmake_minimum_required(VERSION 3.8.0)
project(accless-applications)

set(CMAKE_CXX_STANDARD 20)

# Build auxiliary libraries
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    message(STATUS "Accless: detected wasm build (sysroot=$ENV{FAASM_WASM_SYSROOT})")
    set(CMAKE_EXECUTABLE_SUFFIX ".wasm")
else ()
    message(STATUS "Accless: detected native build")
endif ()

# Include Accless C++ library and specify a build directory
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(ACCLESS_BUILD_DIRECTORY ${CMAKE_BINARY_DIR}/accless-wasm)
else ()
    set(ACCLESS_BUILD_DIRECTORY ${CMAKE_BINARY_DIR}/accless-native)
endif ()
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../accless ${ACCLESS_BUILD_DIRECTORY})

# Prepare variables for workflow compilation
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(ACCLESS_LIBRARIES faasm accless::accless)
    set(ACCLESS_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/../accless/include
        ${CMAKE_CURRENT_LIST_DIR}/../accless/libs/jwt/cpp-bindings
        ${CMAKE_CURRENT_LIST_DIR}/../accless/libs/abe4/cpp-bindings
        ${CMAKE_CURRENT_LIST_DIR}/../accless/libs/base64
    )
else ()
    set(ACCLESS_LIBRARIES accless::accless)
    set(ACCLESS_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/../accless/include
        ${CMAKE_CURRENT_LIST_DIR}/../accless/libs/jwt/cpp-bindings
        ${CMAKE_CURRENT_LIST_DIR}/../accless/libs/abe4/cpp-bindings
        ${CMAKE_CURRENT_LIST_DIR}/../accless/libs/base64
    )
endif()

# =============================================================================
# Application subdirectories
# =============================================================================

# Test applications.
if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    add_subdirectory(./test)
endif ()

# To-Do: add workflows

# To-Do: add functions

cmake_minimum_required(VERSION 3.8.0)
project(accless-ubench-cold-start)

set(CMAKE_PROJECT_TARGET accless-ubench-cold-start)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(ACCLESS_BUILD_DIRECTORY ${CMAKE_BINARY_DIR}/accless-wasm)
else ()
    set(ACCLESS_BUILD_DIRECTORY ${CMAKE_BINARY_DIR}/accless-native)
endif ()

# Include Accless C++ library and specify a build directory
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../accless ${ACCLESS_BUILD_DIRECTORY})

add_executable(${CMAKE_PROJECT_TARGET} ./src/main.cpp)

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(LIBRARIES faasm accless::accless)
    set(HEADERS ${CMAKE_CURRENT_LIST_DIR}/../../accless/include)
else ()
    set(LIBRARIES accless::accless)
    set(HEADERS ${CMAKE_CURRENT_LIST_DIR}/../../accless/include)
endif()

target_include_directories(${CMAKE_PROJECT_TARGET} PUBLIC ${HEADERS})
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC ${LIBRARIES})

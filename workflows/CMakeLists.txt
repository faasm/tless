cmake_minimum_required(VERSION 3.8.0)
project(accless-workflows)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
    set(LIBRARIES faasm accless::accless)
    set(HEADERS ${CMAKE_CURRENT_LIST_DIR}/../../accless/include)
else ()
    set(LIBRARIES accless::accless)
    set(HEADERS ${CMAKE_CURRENT_LIST_DIR}/../../accless/include)
endif()


function(faasm_wflow_func wflow_name func_name file_name)
    set(target_name "${wflow_name}_${func_name}")
    add_executable(${target_name} ${file_name})
    target_link_libraries(${target_name} ${LIBRARIES})
    target_include_directories(${target_name} PUBLIC ${HEADERS})
endfunction(faasm_wflow_func)

add_subdirectory(finra)
add_subdirectory(ml-inference)
add_subdirectory(ml-training)
add_subdirectory(word-count)

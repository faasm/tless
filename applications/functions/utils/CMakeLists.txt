set(CMAKE_PROJECT_TARGET accless_functions_utils)
add_library(${CMAKE_PROJECT_TARGET} INTERFACE)

# Tell consumers where to find headers
target_include_directories(${CMAKE_PROJECT_TARGET} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
add_library(accless::functions::utils ALIAS ${CMAKE_PROJECT_TARGET})

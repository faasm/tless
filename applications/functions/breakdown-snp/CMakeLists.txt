set(CMAKE_PROJECT_TARGET breakdown-snp)

add_executable(${CMAKE_PROJECT_TARGET} main.cpp)

target_include_directories(${CMAKE_PROJECT_TARGET} PRIVATE ${ACCLESS_HEADERS})
target_link_libraries(${CMAKE_PROJECT_TARGET} PRIVATE
    accless::accless
    accless::functions::utils
)

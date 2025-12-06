add_executable(multi-as ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

target_include_directories(multi-as PRIVATE ${ACCLESS_HEADERS})
target_link_libraries(multi-as PRIVATE accless::accless)

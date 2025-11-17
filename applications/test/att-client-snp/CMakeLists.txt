add_executable(att-client-snp ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

target_include_directories(att-client-snp PRIVATE ${ACCLESS_HEADERS})
target_link_libraries(att-client-snp PRIVATE accless::accless)

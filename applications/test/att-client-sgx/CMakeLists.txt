add_executable(att-client-sgx ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

target_include_directories(att-client-sgx PRIVATE ${ACCLESS_HEADERS})
target_link_libraries(att-client-sgx PRIVATE ${ACCLESS_LIBRARIES})

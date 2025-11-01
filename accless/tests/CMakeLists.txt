cmake_minimum_required(VERSION 3.10)
project(AcclessTests)

add_executable(tests main.cpp)
target_link_libraries(tests PRIVATE GTest::gtest_main)
target_compile_options(tests PRIVATE -Wno-deprecated-declarations)

include(GoogleTest)
gtest_discover_tests(tests TEST_PREFIX main::)

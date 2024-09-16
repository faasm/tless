include (ExternalProject)

# -------
# Install external deps
# -------

set(AWS_CORE_LIBRARY ${CMAKE_INSTALL_PREFIX}/lib/libaws-cpp-sdk-core.so)
set(AWS_S3_LIBRARY ${CMAKE_INSTALL_PREFIX}/lib/libaws-cpp-sdk-s3.so)
ExternalProject_Add(aws_ext
    GIT_REPOSITORY   "https://github.com/aws/aws-sdk-cpp.git"
    GIT_TAG          "a47c163630a4d4e62cd3c42e9c391c954be80664"
    BUILD_ALWAYS     0
    TEST_COMMAND     ""
    UPDATE_COMMAND   ""
    BUILD_BYPRODUCTS ${AWS_S3_LIBRARY} ${AWS_CORE_LIBRARY}
    CMAKE_CACHE_ARGS "-DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}"
    LIST_SEPARATOR    "|"
    CMAKE_ARGS       -DBUILD_SHARED_LIBS=ON
                     -DBUILD_ONLY=s3|sts
                     -DAUTORUN_UNIT_TESTS=OFF
                     -DENABLE_TESTING=OFF
                     -DCMAKE_BUILD_TYPE=Release
    LOG_CONFIGURE ON
    LOG_INSTALL ON
    LOG_BUILD ON
    LOG_OUTPUT_ON_FAILURE ON
)

add_library(aws_ext_core SHARED IMPORTED)
add_library(aws_ext_s3 SHARED IMPORTED)
set_target_properties(aws_ext_core
    PROPERTIES IMPORTED_LOCATION
    ${AWS_CORE_LIBRARY})
set_target_properties(aws_ext_s3
    PROPERTIES IMPORTED_LOCATION
    ${AWS_S3_LIBRARY})
add_dependencies(aws_ext_core aws_ext)
add_dependencies(aws_ext_s3 aws_ext)
# Merge the two libraries in one aliased interface
add_library(aws_ext_s3_lib INTERFACE)
target_link_libraries(aws_ext_s3_lib INTERFACE aws_ext_s3 aws_ext_core)
add_library(AWS::s3 ALIAS aws_ext_s3_lib)

# -------
# Library set-up
# -------

add_library(s3_wrapper_lib S3Wrapper.cpp)
target_link_libraries(s3_wrapper_lib PUBLIC AWS::s3)
add_library(TLess::s3 ALIAS s3_wrapper_lib)

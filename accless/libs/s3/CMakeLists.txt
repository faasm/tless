set(CMAKE_PROJECT_TARGET accless_s3)

include(FetchContent)

FetchContent_Declare(miniocpp_ext
    GIT_REPOSITORY "https://github.com/faasm/minio-cpp"
    GIT_TAG "76e5ffd49a7d4637cb4c2194717217b74bc0a33e"
)
FetchContent_MakeAvailable(miniocpp_ext)

if (TARGET curlpp_static)
    target_compile_options(curlpp_static PRIVATE
        -Wno-deprecated-declarations
        -Wno-sign-conversion
        -Wno-conversion
    )
    target_include_directories(curlpp_static PUBLIC "${CURL_INCLUDE_DIR}")
    if (TARGET CURL::libcurl)
        target_link_libraries(curlpp_static PUBLIC CURL::libcurl)
    endif()
endif()
if (TARGET curlpp)
    target_include_directories(curlpp PUBLIC "${CURL_INCLUDE_DIR}")
    if (TARGET CURL::libcurl)
        target_link_libraries(curlpp PUBLIC CURL::libcurl)
    endif()
endif()

# -------
# Library set-up
# -------

add_library(${CMAKE_PROJECT_TARGET} S3Wrapper.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC fmt miniocpp::miniocpp)
target_compile_options(${CMAKE_PROJECT_TARGET} PRIVATE -Wno-deprecated-declarations)
add_library(accless::s3 ALIAS ${CMAKE_PROJECT_TARGET})

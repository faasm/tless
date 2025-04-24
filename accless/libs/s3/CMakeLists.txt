set(CMAKE_PROJECT_TARGET accless_s3)

include(FetchContent)

FetchContent_Declare(miniocpp_ext
    GIT_REPOSITORY "https://github.com/faasm/minio-cpp"
    GIT_TAG "76e5ffd49a7d4637cb4c2194717217b74bc0a33e"
)
FetchContent_MakeAvailable(miniocpp_ext)

# -------
# Library set-up
# -------

add_library(${CMAKE_PROJECT_TARGET} S3Wrapper.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC fmt miniocpp::miniocpp)
add_library(accless::s3 ALIAS ${CMAKE_PROJECT_TARGET})

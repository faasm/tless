include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3 # Use a specific, stable version tag
)
FetchContent_MakeAvailable(nlohmann_json)

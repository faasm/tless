set(CMAKE_PROJECT_TARGET attestation)

include(FetchContent)

FetchContent_Declare(
    AzGuestAttestation
    GIT_REPOSITORY https://github.com/faasm/azure-cvm-guest-attestation.git
    GIT_TAG main
)
FetchContent_MakeAvailable(AzGuestAttestation)

set(AZ_GUEST_ATTESTATION_INCLUDE_DIRS
    ${azguestattestation_SOURCE_DIR}/AttestationClient
    ${azguestattestation_SOURCE_DIR}/AttestationClient/include
    ${azguestattestation_SOURCE_DIR}/LinuxTpm/include
    ${azguestattestation_SOURCE_DIR}/external/jsoncpp-0.10.7/include
)

add_library(${CMAKE_PROJECT_TARGET}
    attestation.cpp
    ec_keypair.cpp
    http_client.cpp
    mock.cpp
    mock_sgx.cpp
    mock_snp.cpp
    utils.cpp
    snp.cpp
    vcek_cache.cpp
)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC
    azguestattestation
    ${OPENSSL_CRYPTO_LIBRARY}
    ${CURL_LIBRARY}
    nlohmann_json::nlohmann_json
    accless::base64
)
target_include_directories(${CMAKE_PROJECT_TARGET} PUBLIC
    ${AZ_GUEST_ATTESTATION_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR}
    ${ACCLESS_ROOT}/libs/base64
)
# FIXME(#52): move OpenSSL usage to 3.X API.
target_compile_definitions(attestation PRIVATE OPENSSL_API_COMPAT=0x10100000L)

add_library(accless::attestation ALIAS ${CMAKE_PROJECT_TARGET})

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

add_library(${CMAKE_PROJECT_TARGET} attestation.cpp)
target_compile_options(${CMAKE_PROJECT_TARGET} PUBLIC
    # This warning comes from upstream code in the attestation library
    -Wno-delete-abstract-non-virtual-dtor
)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC azguestattestation curl)
target_include_directories(${CMAKE_PROJECT_TARGET} PUBLIC ${AZ_GUEST_ATTESTATION_INCLUDE_DIRS})

add_library(accless::attestation ALIAS ${CMAKE_PROJECT_TARGET})

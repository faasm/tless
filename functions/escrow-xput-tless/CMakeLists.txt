cmake_minimum_required(VERSION 3.8.0)
project(accless-ubench)

set(CMAKE_PROJECT_TARGET accless-ubench)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS} -O3")

# Ideally, we should have two options to measure the full authenctication +
# authorization lifecycle or not
# target_compile_definitions(tless PUBLIC ACCLESS_FULL_UBENCH)

# ------------------------------------------------------------------------------
# This project has two main dependencies:
# 1. The rabe Rust library for CP-ABE (and its CPP bindings):
#     - https://github.com/faasm/rabe
# 2. The azure guest attestaion library to retrieve cVM attestation reports
#    from a vTPM in an Azure cVM, and interact with an instance of the
#    azure attestation service:
#     - https://github.com/Azure/confidential-computing-cvm-guest-attestation
#
# We install them manually, before running this script, as part of an Ansible
# provisioning script.
# ------------------------------------------------------------------------------

set(TLESS_WORKFLOW_HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include
    /usr/include/azguestattestation1
    /usr/include/rabe/
)
set(TLESS_WORKFLOW_LIBS
    azguestattestation
    # Order matters: librabe-cpp must preceede librabe
    "/usr/local/lib/rabe/librabe-cpp.a"
    "/usr/local/lib/rabe/librabe.a"
)

add_executable(${CMAKE_PROJECT_TARGET}
    src/main.cpp
    src/logger.cpp
    src/utils.cpp
)
target_include_directories(${CMAKE_PROJECT_TARGET} PUBLIC ${TLESS_WORKFLOW_HEADERS})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${TLESS_WORKFLOW_LIBS})

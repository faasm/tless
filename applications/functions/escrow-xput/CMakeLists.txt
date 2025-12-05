set(CMAKE_PROJECT_TARGET escrow-xput)

add_executable(${CMAKE_PROJECT_TARGET}
    main.cpp
    maa.cpp
)

target_include_directories(${CMAKE_PROJECT_TARGET} PRIVATE ${ACCLESS_HEADERS})
target_link_libraries(${CMAKE_PROJECT_TARGET} PRIVATE accless::accless)

cmake_minimum_required(VERSION 3.20)
project(exeray_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(exeray_core STATIC
    src/stub.cpp
    src/engine.cpp
    src/event/string_pool.cpp
    src/event/graph.cpp
    src/etw/session.cpp
    src/etw/consumer.cpp
    src/etw/parser_process.cpp
    src/etw/parser_file.cpp
    src/etw/parser_registry.cpp
    src/etw/parser_network.cpp
    src/etw/parser_image.cpp
    src/etw/parser_thread.cpp
    src/etw/parser_memory.cpp
    src/etw/parser_dispatch.cpp
    src/process/controller.cpp
)


target_include_directories(exeray_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(exeray_core PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<CONFIG:Release>>:-O3>
)

# Windows ETW requires advapi32 and tdh
if(WIN32)
    target_link_libraries(exeray_core PRIVATE advapi32 tdh)
endif()

install(TARGETS exeray_core
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/exeray
    DESTINATION include
)

# Testing
if(BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(string_pool_test tests/string_pool_test.cpp)
    target_link_libraries(string_pool_test PRIVATE exeray_core GTest::gtest_main)
    target_compile_options(string_pool_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )

    include(GoogleTest)
    gtest_discover_tests(string_pool_test)

    add_executable(graph_test tests/graph_test.cpp)
    target_link_libraries(graph_test PRIVATE exeray_core GTest::gtest_main)
    target_compile_options(graph_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    gtest_discover_tests(graph_test)
endif()

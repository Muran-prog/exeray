cmake_minimum_required(VERSION 3.20)
project(exeray_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Option to use system-installed spdlog
option(EXERAY_USE_SYSTEM_SPDLOG "Use system-installed spdlog instead of FetchContent" OFF)

# spdlog for structured logging
if(EXERAY_USE_SYSTEM_SPDLOG)
    find_package(spdlog REQUIRED)
else()
    include(FetchContent)
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.13.0
    )
    FetchContent_MakeAvailable(spdlog)
endif()

add_library(exeray_core STATIC
    src/stub.cpp
    src/engine.cpp
    src/etw/providers/mapping.cpp
    src/engine/constructor.cpp
    src/engine/monitoring.cpp
    src/engine/control.cpp
    src/engine/legacy_api.cpp
    src/engine/etw_thread.cpp
    src/engine/correlation.cpp
    src/engine/provider_config.cpp
    src/event/string_pool.cpp
    src/event/graph.cpp
    src/event/correlator.cpp
    src/etw/providers/guids.cpp
    src/etw/session/helpers.cpp
    src/etw/session/factory.cpp
    src/etw/session/session.cpp
    src/etw/session/provider_ctrl.cpp
    src/etw/consumer.cpp
    src/etw/parser_process.cpp
    src/etw/parser_file.cpp
    src/etw/parser_registry.cpp
    src/etw/parser_network.cpp
    src/etw/parser_image.cpp
    src/etw/parser_thread.cpp
    src/etw/parser_memory.cpp
    src/etw/parser_powershell.cpp
    src/etw/parser_amsi.cpp
    src/etw/parsers/dns/dga_detector.cpp
    src/etw/parsers/dns/helpers.cpp
    src/etw/parsers/dns/query_parser.cpp
    src/etw/parsers/dns/dispatcher.cpp
    src/etw/parsers/security/brute_force_tracker.cpp
    src/etw/parsers/security/helpers.cpp
    src/etw/parsers/security/logon.cpp
    src/etw/parsers/security/process_audit.cpp
    src/etw/parsers/security/service.cpp
    src/etw/parsers/security/token.cpp
    src/etw/parsers/security/dispatcher.cpp
    src/etw/parsers/wmi/detection.cpp
    src/etw/parsers/wmi/helpers.cpp
    src/etw/parsers/wmi/parser.cpp
    src/etw/parsers/wmi/dispatcher.cpp
    src/etw/parsers/clr/detection.cpp
    src/etw/parsers/clr/helpers.cpp
    src/etw/parsers/clr/assembly_parser.cpp
    src/etw/parsers/clr/jit_parser.cpp
    src/etw/parsers/clr/dispatcher.cpp
    src/etw/parser_dispatch.cpp
    src/etw/tdh/property_helpers.cpp
    src/etw/tdh/property_extractor.cpp
    src/etw/tdh/value_getters.cpp
    src/etw/tdh/schema_cache.cpp
    src/etw/tdh/parser.cpp
    src/etw/tdh/converters/process.cpp
    src/etw/tdh/converters/file.cpp
    src/etw/tdh/converters/registry.cpp
    src/etw/tdh/converters/network.cpp
    src/etw/tdh/converters/image.cpp
    src/etw/tdh/converters/thread.cpp
    src/etw/tdh/converters/memory.cpp
    src/etw/tdh/converters/script.cpp
    src/etw/tdh/converters/amsi.cpp
    src/etw/tdh/converters/dns.cpp
    src/etw/tdh/converters/security.cpp
    src/etw/tdh/converters/wmi.cpp
    src/etw/tdh/converters/clr.cpp
    src/process/controller.cpp

    src/logging.cpp
)


target_include_directories(exeray_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(exeray_core PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<CONFIG:Release>>:-O3>
)

# Link spdlog for structured logging
target_link_libraries(exeray_core PUBLIC spdlog::spdlog)

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

    add_executable(arena_test
        tests/unit/arena/arena_basic_test.cpp
        tests/unit/arena/arena_alignment_test.cpp
        tests/unit/arena/arena_capacity_test.cpp
        tests/unit/arena/arena_overflow_test.cpp
        tests/unit/arena/arena_concurrent_test.cpp
        tests/unit/arena/arena_reset_test.cpp
        tests/unit/arena/arena_edge_cases_test.cpp
        tests/unit/arena/arena_memory_test.cpp
    )
    target_link_libraries(arena_test PRIVATE exeray_core GTest::gtest_main)
    target_compile_options(arena_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    gtest_discover_tests(arena_test)

    add_executable(string_pool_unit_test tests/unit/string_pool_test.cpp)
    target_link_libraries(string_pool_unit_test PRIVATE exeray_core GTest::gtest_main)
    target_compile_options(string_pool_unit_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    gtest_discover_tests(string_pool_unit_test)

    add_executable(event_graph_test
        tests/unit/event_graph/event_graph_basic_test.cpp
        tests/unit/event_graph/event_graph_capacity_test.cpp
        tests/unit/event_graph/event_graph_parent_child_test.cpp
        tests/unit/event_graph/event_graph_correlation_test.cpp
        tests/unit/event_graph/event_graph_category_test.cpp
        tests/unit/event_graph/event_graph_iteration_test.cpp
        tests/unit/event_graph/event_graph_concurrent_test.cpp
        tests/unit/event_graph/event_graph_index_test.cpp
        tests/unit/event_graph/event_graph_string_test.cpp
        tests/unit/event_graph/event_graph_edge_cases_test.cpp
    )
    target_link_libraries(event_graph_test PRIVATE exeray_core GTest::gtest_main)
    target_compile_options(event_graph_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    gtest_discover_tests(event_graph_test)

    add_executable(correlator_test
        tests/unit/correlator/correlator_parent_lookup_test.cpp
        tests/unit/correlator/correlator_correlation_id_test.cpp
        tests/unit/correlator/correlator_registration_test.cpp
        tests/unit/correlator/correlator_concurrent_test.cpp
        tests/unit/correlator/correlator_edge_cases_test.cpp
    )
    target_link_libraries(correlator_test PRIVATE exeray_core GTest::gtest_main)
    target_compile_options(correlator_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    gtest_discover_tests(correlator_test)
endif()


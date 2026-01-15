# Собрать все тестовые файлы из unit/ рекурсивно
file(GLOB_RECURSE UNIT_TEST_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/**/*_test.cpp"
)

add_executable(exeray_unit_tests ${UNIT_TEST_SOURCES})

target_include_directories(exeray_unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/unit  # для поиска *_common.hpp
)

target_link_libraries(exeray_unit_tests PRIVATE
    exeray_core
    GTest::gtest
    GTest::gtest_main
)

target_compile_options(exeray_unit_tests PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

include(GoogleTest)
gtest_discover_tests(exeray_unit_tests)

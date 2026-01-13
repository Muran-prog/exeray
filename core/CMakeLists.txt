cmake_minimum_required(VERSION 3.20)
project(exeray_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(exeray_core STATIC
    src/stub.cpp
)

target_include_directories(exeray_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(exeray_core PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Release>:-O3 -march=native>
)

install(TARGETS exeray_core
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/exeray
    DESTINATION include
)

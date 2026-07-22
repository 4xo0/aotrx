cmake_minimum_required(VERSION 3.20)
project(aotrx LANGUAGES C)

set(AOTRX_HDE_DIR "" CACHE PATH "Directory containing MinHook's hde64.c, hde64.h, table64.h, and pstdint.h")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(aotrx
    src/dump.c
    src/main.c
    src/out.c
    src/pe.c
    src/sig.c)

target_include_directories(aotrx PRIVATE src)

if(AOTRX_HDE_DIR)
    target_sources(aotrx PRIVATE "${AOTRX_HDE_DIR}/hde64.c")
    target_include_directories(aotrx PRIVATE "${AOTRX_HDE_DIR}")
    target_compile_definitions(aotrx PRIVATE AOTRX_USE_HDE=1)
endif()

if(MSVC)
    target_compile_options(aotrx PRIVATE /W4 /wd4701)
else()
    target_compile_options(aotrx PRIVATE -Wall -Wextra -Wpedantic)
endif()

cmake_minimum_required(VERSION 3.17)
project(smithy C)

set(CMAKE_C_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(CMakeDependentOption)

option(SM_BUILD_AARCH64 "Build smithy for aarch64" ON)
cmake_dependent_option(SM_BUILD_ANVIL "Build the anvil OS" ON "SM_BUILD_AARCH64" OFF)

set(CMAKE_C_FLAGS_DEBUG "-O0 -g -fstack-protector-strong -Wpedantic -Wall ${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_C_FLAGS_RELEASE "-Wpedantic -Wall -fstack-protector-strong ${CMAKE_C_FLAGS_RELEASE}")

include(AddBearSSL)
include(AddJansson)
include(AddClangAnalyzer)

option(ASAN "Use ASAN for builds. Not recommended for Release builds." ON)
set(USE_ASAN OFF)
if (("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang") AND ((CMAKE_BUILD_TYPE MATCHES DEBUG) OR (CMAKE_BUILD_TYPE MATCHES Debug)))
    if (ASAN)
        message(STATUS "Setting AddressSanitizer for Debug build")
        set(USE_ASAN ON)
    endif ()
endif ()

option(SM_BUILD_STDLIB "Build the stdlib module" ON)
cmake_dependent_option(SM_BUILD_CACHE "Build the cache module" ON "SM_BUILD_STDLIB" OFF)
cmake_dependent_option(SM_BUILD_CRYPTO "Build the crypto module" ON "SM_BUILD_STDLIB" OFF)
cmake_dependent_option(SM_BUILD_JSON "Build the JSON moodule" ON "SM_BUILD_STDLIB" OFF)
cmake_dependent_option(SM_BUILD_PARSER "Build the parser moodule" ON "SM_BUILD_STDLIB" OFF)
cmake_dependent_option(SM_BUILD_THREADS "Build the threads module" ON "SM_BUILD_STDLIB" OFF)
cmake_dependent_option(SM_BUILD_AUTHN "Build the authn (JWT) module" ON "SM_BUILD_STDLIB;SM_BUILD_CRYPTO;SM_BUILD_JSON" OFF)

add_subdirectory(lib)
add_subdirectory(test)

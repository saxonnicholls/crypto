# snicholls-crypto - elliptic curves, signatures and wallet key derivation for
# the snicholls libraries: secp256k1 (ECDSA with RFC 6979, public-key recovery,
# BIP-340 Schnorr), Ed25519 and X25519, BIP-39, BIP-32, SLIP-10 and the BIP-44
# family of paths.
#
# Header-only. This produces the interface target snicholls::crypto, builds the
# unit tests, demos and documentation when configured as the top-level project,
# and installs a find_package(snicholls_crypto) config.
#
# It takes part in two diamonds (CLAUDE.md "Versioning and the diamond"):
#
#   - core's: crypto pins core as a submodule at third_party/core and adds it
#     here. If the build already holds snicholls::core (a top-level project
#     added it first), core's own CMakeLists.txt skips this copy, and
#     snicholls_core_require() below states the minimum crypto needs;
#   - its own, with the same three rules: the first snicholls::crypto added
#     wins, consumers call snicholls_crypto_require(<minimum>), and the
#     top-level project calls snicholls_crypto_assert_single_version().
#
# tests/cmake/diamond_test.cmake exercises crypto's three rules.

cmake_minimum_required(VERSION 3.20)

project(snicholls_crypto
    VERSION 0.1.0
    DESCRIPTION "snicholls-crypto - elliptic curves, signatures and wallet key derivation"
    LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SnichollsCryptoRequire.cmake)

# Rule 3: every copy that is reached is recorded, winner or not
snicholls_crypto_record_version(${PROJECT_VERSION} "${CMAKE_CURRENT_SOURCE_DIR}")

# Rule 1: the first copy wins
if(TARGET snicholls::crypto)
    get_property(_crypto_winner GLOBAL PROPERTY SNICHOLLS_CRYPTO_VERSION)
    get_property(_crypto_winner_dir GLOBAL PROPERTY SNICHOLLS_CRYPTO_SOURCE_DIR)
    if(_crypto_winner VERSION_EQUAL PROJECT_VERSION)
        message(STATUS "snicholls::crypto ${PROJECT_VERSION}: already defined from ${_crypto_winner_dir}; "
                       "this copy (${CMAKE_CURRENT_SOURCE_DIR}) is skipped")
    else()
        message(WARNING "snicholls::crypto ${PROJECT_VERSION} at ${CMAKE_CURRENT_SOURCE_DIR} is skipped: "
                        "${_crypto_winner} at ${_crypto_winner_dir} was added first and wins. "
                        "Pin every dependency that carries crypto to one release.")
    endif()
    return()
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(SNICHOLLS_CRYPTO_TOP_LEVEL ON)
else()
    set(SNICHOLLS_CRYPTO_TOP_LEVEL OFF)
endif()

# As the top-level project, everything here - core, GoogleTest and Google Benchmark included - is compiled as C++20,
# the standard the library requires, so no vendored project picks its own minimum and mixes standards in one link.
if(SNICHOLLS_CRYPTO_TOP_LEVEL AND NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
endif()

# Core: our pin, unless the build already has one (core's rule 1 then skips this copy, or warns if it differs)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/core/CMakeLists.txt)
    add_subdirectory(third_party/core ${CMAKE_CURRENT_BINARY_DIR}/third_party/core EXCLUDE_FROM_ALL)
elseif(NOT TARGET snicholls::core)
    message(FATAL_ERROR "third_party/core is empty and no snicholls::core is in the build - "
                        "run: git submodule update --init third_party/core")
endif()
snicholls_core_require(0.17.0)   # the first core with the hashes (hash/)

# The library
add_library(snicholls_crypto INTERFACE)
add_library(snicholls::crypto ALIAS snicholls_crypto)
set_target_properties(snicholls_crypto PROPERTIES EXPORT_NAME crypto)
target_compile_features(snicholls_crypto INTERFACE cxx_std_20)
target_include_directories(snicholls_crypto INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(snicholls_crypto INTERFACE snicholls::core)

set_property(GLOBAL PROPERTY SNICHOLLS_CRYPTO_VERSION ${PROJECT_VERSION})
set_property(GLOBAL PROPERTY SNICHOLLS_CRYPTO_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# Tests, demos, benchmarks and docs: on by default only as the top-level project

option(SNICHOLLS_CRYPTO_BUILD_TESTS "Build the snicholls-crypto unit tests and demos" ${SNICHOLLS_CRYPTO_TOP_LEVEL})
option(SNICHOLLS_CRYPTO_BUILD_BENCHMARKS "Build the snicholls-crypto benchmarks (Google Benchmark)" OFF)
option(SNICHOLLS_CRYPTO_BUILD_DOCS "Build the Doxygen documentation; warnings are errors" OFF)
option(SNICHOLLS_CRYPTO_BUILD_FUZZ "Build the differential fuzz harness (fuzz/; Clang, libFuzzer, and the C oracles of docker/oracles)" OFF)
option(SNICHOLLS_CRYPTO_WERROR "Treat warnings as errors in everything this project compiles (CI turns this on)" OFF)
set(SNICHOLLS_CRYPTO_SANITIZE "" CACHE STRING "Sanitizers for the tests and demos, e.g. address,undefined")

# Warning flags go on the things this project compiles, never on the INTERFACE target.
function(snicholls_crypto_compile_options target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        if(SNICHOLLS_CRYPTO_WERROR)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(SNICHOLLS_CRYPTO_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
        if(SNICHOLLS_CRYPTO_SANITIZE)
            target_compile_options(${target} PRIVATE -fsanitize=${SNICHOLLS_CRYPTO_SANITIZE} -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=${SNICHOLLS_CRYPTO_SANITIZE})
        endif()
    endif()
endfunction()

# Whole inversions, point multiplications and signatures are evaluated at compile time in the tests and demos
# (static_assert, constexpr variables). The compilers' default step limits are too low for them, and how many steps
# one evaluation costs depends on the compiler and its standard library: Clang 21 with libstdc++ 15, which checks
# its assertions in constant expressions, exceeds Clang's default 1,048,576 on one field inversion. Every target here
# that evaluates them gets the same limits. The header check does not: it compiles each header as a consumer would,
# with the defaults.
function(snicholls_crypto_constexpr_limits target)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            target_compile_options(${target} PRIVATE /clang:-fconstexpr-steps=100000000)
        else()
            target_compile_options(${target} PRIVATE -fconstexpr-steps=100000000)
        endif()
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target} PRIVATE -fconstexpr-ops-limit=4294967296 -fconstexpr-loop-limit=100000000)
    elseif(MSVC)
        target_compile_options(${target} PRIVATE /constexpr:steps100000000)
    endif()
endfunction()

# Tests, demos and benchmarks: the warnings, and the constexpr limits
function(snicholls_crypto_test_options target)
    snicholls_crypto_compile_options(${target})
    snicholls_crypto_constexpr_limits(${target})
    if(MSVC)
        target_compile_options(${target} PRIVATE /wd4459)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
endfunction()

if(SNICHOLLS_CRYPTO_BUILD_TESTS)
    enable_testing()

    # Every header compiles on its own, and twice in one translation unit so a broken include guard is caught too
    file(GLOB_RECURSE _crypto_headers RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/include
        CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/snicholls/*.hpp)
    set(_header_check_sources)
    foreach(_header IN LISTS _crypto_headers)
        string(MAKE_C_IDENTIFIER "${_header}" _id)
        set(HEADER "${_header}")
        configure_file(cmake/header_check.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/header_check/${_id}.cpp @ONLY)
        list(APPEND _header_check_sources ${CMAKE_CURRENT_BINARY_DIR}/header_check/${_id}.cpp)
    endforeach()
    add_library(snicholls_crypto_header_check OBJECT ${_header_check_sources})
    target_link_libraries(snicholls_crypto_header_check PRIVATE snicholls::crypto)
    snicholls_crypto_compile_options(snicholls_crypto_header_check)

    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/googletest/CMakeLists.txt)
        message(FATAL_ERROR "third_party/googletest is empty - run: git submodule update --init --recursive")
    endif()
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(third_party/googletest EXCLUDE_FROM_ALL)
    # Plain -I, never SYSTEM: a Homebrew googletest in /usr/local/include would otherwise shadow the submodule
    set_property(TARGET gtest gtest_main gmock gmock_main PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "")

    add_subdirectory(tests)
    add_subdirectory(demos)
endif()

if(SNICHOLLS_CRYPTO_BUILD_BENCHMARKS)
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/benchmark/CMakeLists.txt)
        message(FATAL_ERROR "third_party/benchmark is empty - run: git submodule update --init --recursive")
    endif()
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory(third_party/benchmark EXCLUDE_FROM_ALL)
    add_subdirectory(benchmarks)
endif()

# The fuzz harness links libsecp256k1, libsodium and OpenSSL, test-only: its targets link them, snicholls::crypto
# never does
if(SNICHOLLS_CRYPTO_BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()

if(SNICHOLLS_CRYPTO_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)   # docs/doxygen_filter.py
    set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/docs)
    configure_file(docs/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Doxygen: every public entity documented, warnings are errors"
        VERBATIM)
    if(SNICHOLLS_CRYPTO_BUILD_TESTS)
        add_test(NAME docs.build
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(docs.build PROPERTIES LABELS docs)
    endif()
endif()

# ---------------------------------------------------------------------------
# Install and export

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp")

install(TARGETS snicholls_crypto EXPORT snicholls_cryptoTargets)

install(EXPORT snicholls_cryptoTargets
    NAMESPACE snicholls::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snicholls_crypto)

configure_package_config_file(
    cmake/snicholls_cryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/snicholls_cryptoConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snicholls_crypto)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/snicholls_cryptoConfigVersion.cmake
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/snicholls_cryptoConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/snicholls_cryptoConfigVersion.cmake
    cmake/SnichollsCryptoRequire.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snicholls_crypto)

# The last line of a top-level project: one core version in the build, and one crypto version
if(SNICHOLLS_CRYPTO_TOP_LEVEL)
    snicholls_core_assert_single_version()
    snicholls_crypto_assert_single_version()
endif()

# The differential fuzz harness: libFuzzer targets comparing this library with libsecp256k1, libsodium, OpenSSL
# and, through the JSON-lines oracles of scripts/oracles/, the Python and Rust implementations. Test-only, built
# with -DSNICHOLLS_CRYPTO_BUILD_FUZZ=ON in the oracle image (docker/oracles), where the C oracles are installed.
# fuzz/run.sh builds and runs it; fuzz/README.md describes the workflow.
#
# Every target is also a CTest (label fuzz) that replays its committed regressions (fuzz/regressions/<target>/)
# once each, so a divergence once found stays found.

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "SNICHOLLS_CRYPTO_BUILD_FUZZ needs Clang (libFuzzer)")
endif()
find_package(PkgConfig REQUIRED)
pkg_check_modules(SNICHOLLS_FUZZ_SECP256K1 REQUIRED IMPORTED_TARGET libsecp256k1)
pkg_check_modules(SNICHOLLS_FUZZ_SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(OpenSSL 3.0 REQUIRED)

set(SNICHOLLS_CRYPTO_FUZZ_SANITIZE "fuzzer,address,undefined" CACHE STRING "The fuzz targets' -fsanitize= list")

set(_fuzz_targets secp256k1_ecdsa secp256k1_parse secp256k1_schnorr ed25519 x25519 rsa p256 p384 aead text)
foreach(_t IN LISTS _fuzz_targets)
    add_executable(snicholls_crypto_fuzz_${_t} ${_t}_fuzz.cpp)
    target_link_libraries(snicholls_crypto_fuzz_${_t} PRIVATE snicholls::crypto
        PkgConfig::SNICHOLLS_FUZZ_SECP256K1 PkgConfig::SNICHOLLS_FUZZ_SODIUM OpenSSL::Crypto)
    target_include_directories(snicholls_crypto_fuzz_${_t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(snicholls_crypto_fuzz_${_t} PRIVATE SNICHOLLS_CRYPTO_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
        OPENSSL_SUPPRESS_DEPRECATED)
    target_compile_options(snicholls_crypto_fuzz_${_t} PRIVATE -Wall -Wextra -Wpedantic
        -fsanitize=${SNICHOLLS_CRYPTO_FUZZ_SANITIZE} -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
    if(SNICHOLLS_CRYPTO_WERROR)
        target_compile_options(snicholls_crypto_fuzz_${_t} PRIVATE -Werror)
    endif()
    target_link_options(snicholls_crypto_fuzz_${_t} PRIVATE -fsanitize=${SNICHOLLS_CRYPTO_FUZZ_SANITIZE})

    # The committed regressions, replayed once each (a target with none replays an empty directory)
    set(_dir ${CMAKE_CURRENT_SOURCE_DIR}/regressions/${_t})
    if(NOT EXISTS ${_dir})
        set(_dir ${CMAKE_CURRENT_BINARY_DIR}/no-regressions)
        file(MAKE_DIRECTORY ${_dir})
    endif()
    add_test(NAME fuzz.${_t}.regressions
        COMMAND snicholls_crypto_fuzz_${_t} -runs=0 ${_dir})
    set_tests_properties(fuzz.${_t}.regressions PROPERTIES LABELS fuzz TIMEOUT 600)

    # The control: a planted divergence must be reported (fuzz_support.hpp, control())
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/control/${_t} "DIVERGE")
    add_test(NAME fuzz.${_t}.control COMMAND snicholls_crypto_fuzz_${_t} ${CMAKE_CURRENT_BINARY_DIR}/control/${_t})
    set_tests_properties(fuzz.${_t}.control PROPERTIES LABELS fuzz WILL_FAIL TRUE
        ENVIRONMENT SNICHOLLS_CRYPTO_FUZZ_CONTROL=1 TIMEOUT 120)
endforeach()

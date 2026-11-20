# Unit tests. The layout mirrors include/snicholls/crypto/: <sub>/<name>.hpp has
# <sub>/<name>_test.cpp here, and scripts/check_mirror.py fails if one is
# missing or not listed below.
add_executable(snicholls_crypto_tests
    constant_time_test.cpp
    error_test.cpp
    secret_test.cpp
    version_test.cpp
    address/base58_test.cpp
    address/base58check_test.cpp
    address/bech32_test.cpp
    bip39/mnemonic_test.cpp
    bip39/wordlist_test.cpp
    curve25519/ed25519_test.cpp
    curve25519/edwards_test.cpp
    curve25519/field_test.cpp
    curve25519/scalar_test.cpp
    curve25519/x25519_test.cpp
    detail/hashes_test.cpp
    detail/limbs_test.cpp
    hd/bip32_test.cpp
    hd/path_test.cpp
    hd/slip10_test.cpp
    secp256k1/ecdsa_test.cpp
    secp256k1/field_test.cpp
    secp256k1/keys_test.cpp
    secp256k1/point_test.cpp
    secp256k1/rfc6979_test.cpp
    secp256k1/scalar_test.cpp
    secp256k1/schnorr_test.cpp)
target_link_libraries(snicholls_crypto_tests PRIVATE snicholls::crypto GTest::gtest_main GTest::gmock)
# The official test vectors (tests/fixtures/), read at run time; provenance in tests/fixtures/README.md
target_compile_definitions(snicholls_crypto_tests PRIVATE SNICHOLLS_CRYPTO_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
target_include_directories(snicholls_crypto_tests PRIVATE ${PROJECT_SOURCE_DIR}/tests/support)
snicholls_crypto_test_options(snicholls_crypto_tests)
# Compile-time tests evaluate whole point multiplications; the compilers' default step limits are too low for them
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(snicholls_crypto_tests PRIVATE -fconstexpr-steps=100000000)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(snicholls_crypto_tests PRIVATE -fconstexpr-ops-limit=4294967296 -fconstexpr-loop-limit=100000000)
endif()

include(GoogleTest)
gtest_discover_tests(snicholls_crypto_tests PROPERTIES LABELS unit DISCOVERY_MODE PRE_TEST)

# The diamond rules are CMake, so they are tested with CMake
add_test(NAME cmake.diamond
    COMMAND ${CMAKE_COMMAND}
        -DCRYPTO_SOURCE_DIR=${PROJECT_SOURCE_DIR}
        -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/diamond
        -DCXX=${CMAKE_CXX_COMPILER}
        -DGENERATOR=${CMAKE_GENERATOR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/diamond_test.cmake)
set_tests_properties(cmake.diamond PROPERTIES LABELS boundary TIMEOUT 900)

# The BIP-39 word list must be exactly the official file (its SHA-256 recomputed from the header's words), and the
# Trezor fixture must name its pinned source
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME generated.bip39_wordlist_is_official
    COMMAND Python3::Interpreter ${PROJECT_SOURCE_DIR}/scripts/generate_bip39_wordlist.py --check)
set_tests_properties(generated.bip39_wordlist_is_official PROPERTIES LABELS boundary)

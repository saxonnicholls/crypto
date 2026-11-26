# Unit tests. The layout mirrors include/snicholls/crypto/: <sub>/<name>.hpp has
# <sub>/<name>_test.cpp here, and scripts/check_mirror.py fails if one is
# missing or not listed below.
add_executable(snicholls_crypto_tests
    constant_time_test.cpp
    error_test.cpp
    secret_test.cpp
    version_test.cpp
    address/base58_test.cpp
    aead/aes128_gcm_test.cpp
    aead/aes128_gcm_oracles_test.cpp
    aead/aes256_gcm_test.cpp
    aead/aes256_gcm_oracles_test.cpp
    aead/aes_key_wrap_test.cpp
    aead/chacha20_poly1305_test.cpp
    aead/chacha20_poly1305_oracles_test.cpp
    address/base58check_test.cpp
    address/base58check_oracles_test.cpp
    address/bech32_test.cpp
    address/bech32_oracles_test.cpp
    bip39/mnemonic_test.cpp
    bip39/mnemonic_oracles_test.cpp
    bip39/wordlist_test.cpp
    curve25519/ed25519_test.cpp
    curve25519/ed25519_oracles_test.cpp
    curve25519/edwards_test.cpp
    curve25519/field_test.cpp
    curve25519/scalar_test.cpp
    curve25519/x25519_test.cpp
    curve25519/x25519_oracles_test.cpp
    detail/hashes_test.cpp
    detail/aes_test.cpp
    detail/chacha20_test.cpp
    detail/ecdsa_der_test.cpp
    detail/limbs_test.cpp
    detail/mont256_test.cpp
    detail/poly1305_test.cpp
    detail/montgomery_test.cpp
    hd/bip32_test.cpp
    hd/bip32_oracles_test.cpp
    hd/path_test.cpp
    jose/ecdh_es_test.cpp
    jose/ecdh_es_oracles_test.cpp
    hd/slip10_test.cpp
    hd/slip10_oracles_test.cpp
    p256/ecdh_test.cpp
    p256/ecdsa_test.cpp
    p256/ecdsa_oracles_test.cpp
    p256/field_test.cpp
    p256/point_test.cpp
    p256/scalar_test.cpp
    rsa/rsa_test.cpp
    rsa/rsa_oracles_test.cpp
    secp256k1/ecdsa_test.cpp
    secp256k1/ecdsa_oracles_test.cpp
    secp256k1/field_test.cpp
    secp256k1/keys_test.cpp
    secp256k1/keys_oracles_test.cpp
    secp256k1/point_test.cpp
    secp256k1/rfc6979_test.cpp
    secp256k1/scalar_test.cpp
    secp256k1/schnorr_test.cpp
    secp256k1/schnorr_oracles_test.cpp
)
target_link_libraries(snicholls_crypto_tests PRIVATE snicholls::crypto GTest::gtest_main GTest::gmock)
# The official test vectors (tests/fixtures/), read at run time; provenance in tests/fixtures/README.md
target_compile_definitions(snicholls_crypto_tests PRIVATE SNICHOLLS_CRYPTO_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
target_include_directories(snicholls_crypto_tests PRIVATE ${PROJECT_SOURCE_DIR}/tests/support)
# The warnings and the constexpr limits the compile-time tests need (CMakeLists.txt, snicholls_crypto_constexpr_limits)
snicholls_crypto_test_options(snicholls_crypto_tests)

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

# The cross-implementation fixtures (tests/fixtures/oracles/, replayed by the *_oracles_test.cpp tests above) must be
# what the pinned oracles answer today: regenerated and compared, in the oracle image (docker/oracles), where
# ORACLES_HOME holds the oracles' toolchains. Elsewhere the fixtures are replayed but not regenerated.
if(DEFINED ENV{ORACLES_HOME} AND EXISTS "$ENV{ORACLES_HOME}/venv")
    set(_crypto_oracles_default ON)
else()
    set(_crypto_oracles_default OFF)
endif()
option(SNICHOLLS_CRYPTO_TEST_ORACLES "Regenerate the oracle fixtures as a test (needs the docker/oracles image)"
       ${_crypto_oracles_default})
if(SNICHOLLS_CRYPTO_TEST_ORACLES)
    add_test(NAME generated.oracle_fixtures_up_to_date
        COMMAND Python3::Interpreter -I ${PROJECT_SOURCE_DIR}/scripts/generate_oracle_fixtures.py --check)
    set_tests_properties(generated.oracle_fixtures_up_to_date PROPERTIES LABELS oracle TIMEOUT 1800)
endif()

# The constant-time check (tests/ct/secret_marking.cpp): every secret path run under Valgrind's memcheck with the
# secrets marked undefined, so a branch or an index on a secret fails. Only where Valgrind and its header exist
# (the Ubuntu image), and not under the sanitizers. The control case leaks on purpose and must be reported.
find_program(SNICHOLLS_CRYPTO_VALGRIND valgrind)
include(CheckIncludeFileCXX)
check_include_file_cxx(valgrind/memcheck.h SNICHOLLS_CRYPTO_HAVE_MEMCHECK_H)
if(SNICHOLLS_CRYPTO_VALGRIND AND SNICHOLLS_CRYPTO_HAVE_MEMCHECK_H AND NOT SNICHOLLS_CRYPTO_SANITIZE)
    add_executable(snicholls_crypto_ct_secret_marking ct/secret_marking.cpp)
    target_link_libraries(snicholls_crypto_ct_secret_marking PRIVATE snicholls::crypto)
    snicholls_crypto_test_options(snicholls_crypto_ct_secret_marking)
    add_test(NAME ct.secret_marking
        COMMAND ${SNICHOLLS_CRYPTO_VALGRIND} --error-exitcode=1 --quiet $<TARGET_FILE:snicholls_crypto_ct_secret_marking>)
    add_test(NAME ct.secret_marking.control
        COMMAND ${SNICHOLLS_CRYPTO_VALGRIND} --error-exitcode=1 --quiet $<TARGET_FILE:snicholls_crypto_ct_secret_marking> --control)
    set_tests_properties(ct.secret_marking ct.secret_marking.control PROPERTIES LABELS ct TIMEOUT 1200)
    set_tests_properties(ct.secret_marking.control PROPERTIES WILL_FAIL TRUE)
else()
    message(STATUS "snicholls-crypto: Valgrind or valgrind/memcheck.h not found: the ct.secret_marking check is not built")
endif()

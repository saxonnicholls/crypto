# Benchmarks (Google Benchmark). The layout mirrors include/snicholls/crypto/:
# <sub>/<name>.hpp has <sub>/<name>_benchmark.cpp here. Only Release numbers
# mean anything; a short smoke run of each is a CTest (label benchmark).
#
# Each benchmark has its own main(), which checks the operation against an
# official test vector before handing over to Google Benchmark, and refuses to
# run if they disagree (CLAUDE.md "Benchmarks").
function(snicholls_crypto_add_benchmark name source)
    add_executable(snicholls_crypto_${name} ${source})
    target_link_libraries(snicholls_crypto_${name} PRIVATE snicholls::crypto benchmark::benchmark)
    target_include_directories(snicholls_crypto_${name} PRIVATE ${PROJECT_SOURCE_DIR}/tests/support)
    target_compile_definitions(snicholls_crypto_${name} PRIVATE NDEBUG)
    snicholls_crypto_test_options(snicholls_crypto_${name})
    add_test(NAME benchmark.${name} COMMAND snicholls_crypto_${name} --benchmark_min_time=0.01s)
    set_tests_properties(benchmark.${name} PROPERTIES LABELS benchmark TIMEOUT 300)
endfunction()

snicholls_crypto_add_benchmark(base58_benchmark address/base58_benchmark.cpp)
snicholls_crypto_add_benchmark(bech32_benchmark address/bech32_benchmark.cpp)
snicholls_crypto_add_benchmark(mnemonic_benchmark bip39/mnemonic_benchmark.cpp)
snicholls_crypto_add_benchmark(ed25519_benchmark curve25519/ed25519_benchmark.cpp)
snicholls_crypto_add_benchmark(x25519_benchmark curve25519/x25519_benchmark.cpp)
snicholls_crypto_add_benchmark(aes256_gcm_benchmark aead/aes256_gcm_benchmark.cpp)
snicholls_crypto_add_benchmark(chacha20_poly1305_benchmark aead/chacha20_poly1305_benchmark.cpp)
snicholls_crypto_add_benchmark(p256_ecdh_benchmark p256/ecdh_benchmark.cpp)
snicholls_crypto_add_benchmark(p256_ecdsa_benchmark p256/ecdsa_benchmark.cpp)
snicholls_crypto_add_benchmark(jose_ecdh_es_benchmark jose/ecdh_es_benchmark.cpp)
snicholls_crypto_add_benchmark(rsa_benchmark rsa/rsa_benchmark.cpp)
snicholls_crypto_add_benchmark(bip32_benchmark hd/bip32_benchmark.cpp)
snicholls_crypto_add_benchmark(ecdsa_benchmark secp256k1/ecdsa_benchmark.cpp)
snicholls_crypto_add_benchmark(schnorr_benchmark secp256k1/schnorr_benchmark.cpp)

# The informational dudect-style timing test (benchmarks/ct/timing.cpp): fixed against random secrets, Welch's t.
# The smoke run is short; run it by hand with more samples for evidence. It fails only on a wrong result.
add_executable(snicholls_crypto_ct_timing ct/timing.cpp)
target_link_libraries(snicholls_crypto_ct_timing PRIVATE snicholls::crypto)
target_compile_definitions(snicholls_crypto_ct_timing PRIVATE NDEBUG)
snicholls_crypto_test_options(snicholls_crypto_ct_timing)
add_test(NAME benchmark.ct_timing COMMAND snicholls_crypto_ct_timing 400)
set_tests_properties(benchmark.ct_timing PROPERTIES LABELS benchmark TIMEOUT 600)

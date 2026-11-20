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

snicholls_crypto_add_benchmark(mnemonic_benchmark bip39/mnemonic_benchmark.cpp)

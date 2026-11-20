# Demos. The layout mirrors include/snicholls/crypto/: <sub>/<name>.hpp has
# <sub>/<name>_demo.cpp here. Each prints what it does and exits non-zero if the
# result is not what it documents, so every demo is also a CTest (label demo).
# scripts/check_mirror.py fails if a public header has no demo or the demo is
# not listed below.
function(snicholls_crypto_add_demo name source)
    add_executable(snicholls_crypto_${name} ${source})
    target_link_libraries(snicholls_crypto_${name} PRIVATE snicholls::crypto)
    # Hex for printing keys and vectors: the test-only helper until core has a hex codec
    target_include_directories(snicholls_crypto_${name} PRIVATE ${PROJECT_SOURCE_DIR}/tests/support)
    snicholls_crypto_test_options(snicholls_crypto_${name})
    add_test(NAME demo.${name} COMMAND snicholls_crypto_${name})
    set_tests_properties(demo.${name} PROPERTIES LABELS demo)
endfunction()

snicholls_crypto_add_demo(constant_time_demo constant_time_demo.cpp)
snicholls_crypto_add_demo(error_demo error_demo.cpp)
snicholls_crypto_add_demo(secret_demo secret_demo.cpp)
snicholls_crypto_add_demo(version_demo version_demo.cpp)
snicholls_crypto_add_demo(curve25519_ed25519_demo curve25519/ed25519_demo.cpp)
snicholls_crypto_add_demo(curve25519_edwards_demo curve25519/edwards_demo.cpp)
snicholls_crypto_add_demo(curve25519_field_demo curve25519/field_demo.cpp)
snicholls_crypto_add_demo(curve25519_scalar_demo curve25519/scalar_demo.cpp)
snicholls_crypto_add_demo(curve25519_x25519_demo curve25519/x25519_demo.cpp)
snicholls_crypto_add_demo(field_demo secp256k1/field_demo.cpp)
snicholls_crypto_add_demo(point_demo secp256k1/point_demo.cpp)
snicholls_crypto_add_demo(scalar_demo secp256k1/scalar_demo.cpp)

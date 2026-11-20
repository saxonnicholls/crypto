//
//  scalar_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Arithmetic modulo the group order n: ranges, low-S and inverses.
#include <snicholls/crypto/secp256k1/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    //! [scalar]
    using snicholls::crypto::secp256k1::scalar;
    const auto n = scalar::order_bytes();
    const bool order_rejected = !scalar::from_bytes(n);                   // a key must be below n
    const auto reduced = scalar::from_bytes_reduced(n);                   // a hash is reduced: n -> 0
    const auto s = -scalar::from_u64(1);                                  // n - 1: a "high" s
    const auto low = scalar::select(s.is_high_mask(), -s, s);             // low-S normalisation, no branch
    const bool inverse_ok = scalar::from_u64(3).inverse() * scalar::from_u64(3) == scalar::from_u64(1);
    //! [scalar]
    std::printf("n = %s\n", snicholls::crypto::test::to_hex(n).c_str());
    std::printf("n rejected as a key: %s; n mod n = 0: %s; low(n-1) = 1: %s; 3 * 1/3 = 1: %s\n", order_rejected ? "yes" : "no",
                reduced.is_zero() ? "yes" : "no", low == scalar::from_u64(1) ? "yes" : "no", inverse_ok ? "yes" : "no");
    return order_rejected && reduced.is_zero() && low == scalar::from_u64(1) && inverse_ok ? 0 : 1;
}

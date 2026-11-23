//
//  scalar_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// P-256 scalars: the group order, an inverse, and a hash reduced modulo n.
#include <snicholls/crypto/p256/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [scalar]
    using snicholls::crypto::p256::scalar;
    const auto n = scalar::order_bytes();
    const bool inverse_ok = scalar::from_u64(5) * scalar::from_u64(5).inverse() == scalar::from_u64(1);
    const scalar reduced = scalar::from_bytes_reduced(hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    const bool n_refused = !scalar::from_bytes(n).has_value();   // a scalar is below n
    //! [scalar]
    std::printf("n = %s\n5 * 5^-1 = 1: %s; 2^256 - 1 mod n = %s; n refused: %s\n", to_hex(n).c_str(), inverse_ok ? "yes" : "no",
                to_hex(reduced.to_bytes()).c_str(), n_refused ? "yes" : "no");
    return inverse_ok && n_refused && to_hex(reduced.to_bytes()) == "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae" ? 0 : 1;
}

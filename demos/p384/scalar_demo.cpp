//
//  scalar_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// P-384 scalars: the group order, an inverse, and a 48-byte hash reduced modulo n.
#include <snicholls/crypto/p384/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [scalar384]
    using snicholls::crypto::p384::scalar;
    const auto n = scalar::order_bytes();
    const bool inverse_ok = scalar::from_u64(5) * scalar::from_u64(5).inverse() == scalar::from_u64(1);
    const scalar reduced = scalar::from_bytes_reduced(
        hex<48>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    const bool n_refused = !scalar::from_bytes(n).has_value();   // a scalar is below n
    //! [scalar384]
    std::printf("n = %s\n5 * 5^-1 = 1: %s; 2^384 - 1 mod n = %s; n refused: %s\n", to_hex(n).c_str(), inverse_ok ? "yes" : "no",
                to_hex(reduced.to_bytes()).c_str(), n_refused ? "yes" : "no");
    return inverse_ok && n_refused &&
                   to_hex(reduced.to_bytes()) ==
                       "000000000000000000000000000000000000000000000000389cb27e0bc8d220a7e5f24db74f58851313e695333ad68c"
               ? 0
               : 1;
}

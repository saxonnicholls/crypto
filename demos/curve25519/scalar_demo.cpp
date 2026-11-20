//
//  scalar_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Scalars modulo L: reducing a hash, S = k a + r, and the canonical check.
#include <snicholls/crypto/curve25519/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <array>
#include <cstdio>

int main()
{
    //! [scalar]
    using snicholls::crypto::curve25519::scalar;
    std::array<std::uint8_t, 64> digest{};
    digest.fill(0xff);                                                   // a 64-byte hash, as SHA-512 gives
    const scalar h = scalar::reduce(digest);                             // reduced modulo L
    const scalar s = scalar::mul_add(scalar::from_u64(6), scalar::from_u64(7), scalar::from_u64(8));   // 6 * 7 + 8
    const auto order = snicholls::crypto::test::hex<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    const bool l_is_canonical = scalar::is_canonical(order);             // S = L would be malleable: refused
    //! [scalar]
    std::printf("(2^512 - 1) mod L = %s\n6 * 7 + 8 = %d; L canonical: %s\n",
                snicholls::crypto::test::to_hex(h.to_bytes()).c_str(), s.to_bytes()[0], l_is_canonical ? "yes" : "no");
    return s == scalar::from_u64(50) && !l_is_canonical && scalar::from_canonical(h.to_bytes()) ? 0 : 1;
}

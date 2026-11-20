//
//  edwards_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// edwards25519: the base point, scalar multiplication, encoding and the cofactor.
#include <snicholls/crypto/curve25519/edwards.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    //! [edwards]
    using snicholls::crypto::curve25519::point;
    using snicholls::crypto::curve25519::scalar;
    const point a = point::mul_base(scalar::from_u64(3));                      // constant time in the scalar
    const point b = point::mul(scalar::from_u64(3), point::base());            // the same, for any point
    const point c = point::mul_add_public(scalar::from_u64(1), scalar::from_u64(2), point::base());   // public: B + 2B
    const auto encoded = a.encode();                                           // 32 bytes, RFC 8032
    const auto decoded = point::decode(encoded);                               // strict: std::nullopt if invalid
    const auto two_torsion = point::decode(snicholls::crypto::test::hex<32>(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));  // (0, -1), order 2
    const bool small = two_torsion && two_torsion->is_small_order();
    const bool prime_order = point::base().is_torsion_free();
    //! [edwards]
    std::printf("3B = %s\n3B three ways agree: %s; (0, -1) small order: %s; B torsion-free: %s\n",
                snicholls::crypto::test::to_hex(encoded).c_str(), a == b && b == c && decoded && *decoded == a ? "yes" : "no",
                small ? "yes" : "no", prime_order ? "yes" : "no");
    return a == b && b == c && decoded && *decoded == a && small && prime_order ? 0 : 1;
}

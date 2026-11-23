//
//  point_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// P-256 points: 2G by doubling and by multiplication (NIST's published value), SEC1 encodings decoded back, and an
// off-curve encoding refused.
#include <snicholls/crypto/p256/point.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    using snicholls::crypto::test::to_hex;
    //! [point]
    namespace p256 = snicholls::crypto::p256;
    const p256::point g = p256::point::base();
    const p256::point two_g = p256::point::mul_base(p256::scalar::from_u64(2));   // constant time in the scalar
    const bool same = two_g == g.dbl();
    const p256::affine_point a = two_g.to_affine().value();
    const auto back = p256::affine_point::decode(a.compressed());                // SEC1, checked on the curve
    auto bad = a.uncompressed();
    bad[64] ^= 1;
    const auto refused = p256::affine_point::decode(bad);                          // std::nullopt
    //! [point]
    std::printf("2G x %s\n2G = G + G: %s; compressed round trip: %s; off-curve refused: %s\n", to_hex(a.x.to_bytes()).c_str(),
                same ? "yes" : "no", back && *back == a ? "yes" : "no", refused ? "no" : "yes");
    return same && back && *back == a && !refused &&
                   to_hex(a.x.to_bytes()) == "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
               ? 0
               : 1;
}

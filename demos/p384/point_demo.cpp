//
//  point_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// P-384 points: 2G by doubling and by multiplication, SEC1 encodings decoded back, and an off-curve encoding refused.
#include <snicholls/crypto/p384/point.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    using snicholls::crypto::test::to_hex;
    //! [point384]
    namespace p384 = snicholls::crypto::p384;
    const p384::point g = p384::point::base();
    const p384::point two_g = p384::point::mul_base(p384::scalar::from_u64(2));   // constant time in the scalar
    const bool same = two_g == g.dbl();
    const p384::affine_point a = two_g.to_affine().value();
    const auto back = p384::affine_point::decode(a.compressed());                // SEC1 (49 bytes), checked
    auto bad = a.uncompressed();
    bad[96] ^= 1;
    const auto refused = p384::affine_point::decode(bad);                          // std::nullopt
    //! [point384]
    std::printf("2G x %s\n2G = G + G: %s; compressed round trip: %s; off-curve refused: %s\n", to_hex(a.x.to_bytes()).c_str(),
                same ? "yes" : "no", back && *back == a ? "yes" : "no", refused ? "no" : "yes");
    return same && back && *back == a && !refused &&
                   to_hex(a.x.to_bytes()) ==
                       "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61"
               ? 0
               : 1;
}

//
//  point_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Points on secp256k1: the group law and scalar multiplication.
#include <snicholls/crypto/secp256k1/point.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    //! [point]
    using namespace snicholls::crypto::secp256k1;
    constexpr point two_g = point::base().dbl();                         // the compiler doubles G
    static_assert(two_g == point::base() + point::base());               // complete formulas: same answer
    const point k_g = point::mul_base(scalar::from_u64(3));              // constant time in the scalar
    const point check = point::mul_add_public(scalar::from_u64(1), scalar::from_u64(1), two_g);   // public: G + 2G
    const auto affine = k_g.to_affine();                                 // std::nullopt only for the identity
    const auto from_x = decompress(generator().x, 0);                    // G from its x and parity
    //! [point]
    const std::string x = snicholls::crypto::test::to_hex(affine->x.to_bytes());
    std::printf("3G.x = %s\nG + 2G == 3G: %s; decompress(G.x) == G: %s\n", x.c_str(), check == k_g ? "yes" : "no",
                from_x && *from_x == generator() ? "yes" : "no");
    return x == "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" && check == k_g && from_x &&
                   *from_x == generator()
               ? 0
               : 1;
}

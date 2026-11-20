//
//  field_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Arithmetic modulo secp256k1's p, evaluated by the compiler.
#include <snicholls/crypto/secp256k1/field.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    //! [field]
    using snicholls::crypto::secp256k1::field_element;
    constexpr auto seven = field_element::from_u64(7);
    constexpr auto inv = seven.inverse();                    // computed at compile time
    static_assert(inv * seven == field_element::from_u64(1));
    const auto root = (seven * seven).sqrt();                // a square root, for public data
    const bool root_ok = root && (*root == seven || *root == -seven);
    const auto too_big = field_element::from_bytes(snicholls::crypto::test::hex<32>(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"));   // p itself: rejected
    //! [field]
    std::printf("1/7 mod p = %s\n", snicholls::crypto::test::to_hex(inv.to_bytes()).c_str());
    std::printf("sqrt(49) is +-7: %s; p rejected: %s\n", root_ok ? "yes" : "no", too_big ? "no" : "yes");
    return root_ok && !too_big ? 0 : 1;
}

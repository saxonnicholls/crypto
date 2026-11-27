//
//  field_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// The P-384 field: an inverse, a square root, and p refused as a value.
#include <snicholls/crypto/p384/field.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    using snicholls::crypto::test::hex;
    //! [field384]
    using snicholls::crypto::p384::field_element;
    const field_element seven = field_element::from_u64(7);
    const bool inverse_ok = seven * seven.inverse() == field_element::from_u64(1);
    std::uint64_t is_square = 0;
    const field_element root = field_element::from_u64(9).sqrt_ct(is_square);   // 3 or p - 3
    const auto p = field_element::from_bytes(
        hex<48>("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"));   // std::nullopt
    //! [field384]
    std::printf("7 * 7^-1 = 1: %s; sqrt(9) squared is 9: %s; p as a value: %s\n", inverse_ok ? "yes" : "no",
                is_square && root.square() == field_element::from_u64(9) ? "yes" : "no", p ? "accepted" : "refused");
    return inverse_ok && is_square && root.square() == field_element::from_u64(9) && !p ? 0 : 1;
}

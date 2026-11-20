//
//  field_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Arithmetic modulo 2^255 - 19.
#include <snicholls/crypto/curve25519/field.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>

int main()
{
    //! [field]
    using snicholls::crypto::curve25519::field_element;
    constexpr auto i = field_element::sqrt_m1();
    static_assert(i.square() == -field_element::from_u64(1));          // sqrt(-1), checked by the compiler
    const auto inv = field_element::from_u64(5).invert();               // 1/5, a fixed addition chain
    std::uint64_t is_square = 0;
    const auto root = field_element::sqrt_ratio(field_element::from_u64(9), field_element::from_u64(1), is_square);
    const auto p_bytes = snicholls::crypto::test::hex<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    const bool p_is_canonical = field_element::is_canonical(p_bytes);   // p itself is not a canonical encoding
    //! [field]
    const bool ok = inv * field_element::from_u64(5) == field_element::from_u64(1) && is_square != 0 &&
                    (root == field_element::from_u64(3) || root == -field_element::from_u64(3)) && !p_is_canonical &&
                    field_element::from_bytes(p_bytes).is_zero();
    std::printf("1/5 = %s\nsqrt(9) found: %s; p canonical: %s\n", snicholls::crypto::test::to_hex(inv.to_bytes()).c_str(),
                is_square ? "yes" : "no", p_is_canonical ? "yes" : "no");
    return ok ? 0 : 1;
}

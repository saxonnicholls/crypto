//
//  field_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/curve25519/field.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <type_traits>

using snicholls::crypto::curve25519::field_element;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

static_assert(std::is_trivially_copyable_v<field_element>);
// sqrt(-1) squares to -1, and the inverse is an inverse: evaluated by the compiler
static_assert(field_element::sqrt_m1().square() == -field_element::from_u64(1));
static_assert(field_element::from_u64(121666).invert() * field_element::from_u64(121666) == field_element::from_u64(1));
static_assert(field_element{}.invert().is_zero());

TEST(CryptoCurve25519Field, EncodingIsCanonicalAtTheModulus)
{
    // p - 1 encodes as itself; p is zero; 2^255 - 1 is 18; bit 255 is ignored on input
    const auto p_minus_1 = hex<32>("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    const auto p = hex<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    const auto top = hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    EXPECT_EQ(field_element::from_bytes(p_minus_1).to_bytes(), p_minus_1);
    EXPECT_TRUE(field_element::from_bytes(p).is_zero());
    EXPECT_EQ(field_element::from_bytes(top), field_element::from_u64(18));
    auto with_sign = p_minus_1;
    with_sign[31] |= 0x80;
    EXPECT_EQ(field_element::from_bytes(with_sign), field_element::from_bytes(p_minus_1));
    EXPECT_TRUE(field_element::is_canonical(p_minus_1));
    EXPECT_TRUE(field_element::is_canonical(with_sign));
    EXPECT_FALSE(field_element::is_canonical(p));
    EXPECT_FALSE(field_element::is_canonical(top));
}

TEST(CryptoCurve25519Field, ArithmeticIdentities)
{
    field_element x = field_element::from_u64(7);
    for (int i = 0; i < 64; ++i) {
        EXPECT_EQ(x * x.invert(), field_element::from_u64(1));
        EXPECT_EQ((x - x), field_element{});
        EXPECT_EQ(-(-x), x);
        EXPECT_EQ(x.square(), x * x);
        x = x.square() + field_element::from_u64(static_cast<std::uint64_t>(i + 1));
    }
    // (p - 1)^2 = 1
    const auto m1 = field_element::from_bytes(hex<32>("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    EXPECT_EQ(m1 * m1, field_element::from_u64(1));
    EXPECT_EQ(m1.square_times(3), field_element::from_u64(1));
}

TEST(CryptoCurve25519Field, SqrtRatioFindsRootsAndRefusesNonSquares)
{
    std::uint64_t ok = 0;
    const auto r = field_element::sqrt_ratio(field_element::from_u64(4), field_element::from_u64(1), ok);
    EXPECT_NE(ok, 0u);
    EXPECT_TRUE(r == field_element::from_u64(2) || r == -field_element::from_u64(2));
    // 2 is not a square modulo p (p = 5 mod 8)
    (void)field_element::sqrt_ratio(field_element::from_u64(2), field_element::from_u64(1), ok);
    EXPECT_EQ(ok, 0u);
    // -1 is a square: the root is sqrt(-1), found through the flipped branch
    const auto i = field_element::sqrt_ratio(-field_element::from_u64(1), field_element::from_u64(1), ok);
    EXPECT_NE(ok, 0u);
    EXPECT_EQ(i.square(), -field_element::from_u64(1));
    // 0 / v is the square 0
    EXPECT_TRUE(field_element::sqrt_ratio(field_element{}, field_element::from_u64(3), ok).is_zero());
    EXPECT_NE(ok, 0u);
}

TEST(CryptoCurve25519Field, SelectSwapAndSign)
{
    auto a = field_element::from_u64(1), b = field_element::from_u64(2);
    EXPECT_EQ(field_element::select(~0ull, a, b), a);
    EXPECT_EQ(field_element::select(0, a, b), b);
    field_element::conditional_swap(~0ull, a, b);
    EXPECT_EQ(a, field_element::from_u64(2));
    field_element::conditional_swap(0, a, b);
    EXPECT_EQ(a, field_element::from_u64(2));
    EXPECT_EQ(field_element::from_u64(1).is_negative(), 1u);
    EXPECT_EQ((-field_element::from_u64(1)).is_negative(), 0u);   // p - 1 is even
    EXPECT_EQ(to_hex(field_element::from_u64(1).to_bytes()), "0100000000000000000000000000000000000000000000000000000000000000");
}

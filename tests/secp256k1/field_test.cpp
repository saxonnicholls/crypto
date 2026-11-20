//
//  field_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/secp256k1/field.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <type_traits>

using snicholls::crypto::secp256k1::field_element;
using snicholls::crypto::test::hex;

namespace {
constexpr auto p_minus_1 = hex<32>("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
constexpr auto p_bytes = hex<32>("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
} // namespace

static_assert(std::is_trivially_copyable_v<field_element>);
static_assert(sizeof(field_element) == 32);
// p - 1 = -1: (-1)^2 = 1, -1 + 1 = 0, and the inverse of 2 doubles to 1, all evaluated by the compiler
static_assert(field_element::from_bytes(p_minus_1)->square() == field_element::from_u64(1));
static_assert((*field_element::from_bytes(p_minus_1) + field_element::from_u64(1)).is_zero());
static_assert(field_element::from_u64(2).inverse() * field_element::from_u64(2) == field_element::from_u64(1));
static_assert(!field_element::from_bytes(p_bytes).has_value());

TEST(CryptoSecp256k1Field, EncodingsAtAndAboveTheModulusAreRejected)
{
    EXPECT_FALSE(field_element::from_bytes(p_bytes));
    EXPECT_FALSE(field_element::from_bytes(hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
    ASSERT_TRUE(field_element::from_bytes(p_minus_1));
    EXPECT_EQ(field_element::from_bytes(p_minus_1)->to_bytes(), p_minus_1);
}

TEST(CryptoSecp256k1Field, InverseOfEveryValueTriedIsAnInverse)
{
    field_element x = field_element::from_u64(3);
    for (int i = 0; i < 64; ++i) {
        EXPECT_EQ(x * x.inverse(), field_element::from_u64(1));
        x = x.square() + field_element::from_u64(static_cast<std::uint64_t>(i));
    }
    EXPECT_TRUE(field_element{}.inverse().is_zero());
}

TEST(CryptoSecp256k1Field, SquareRootsOfSquaresAndNonResidues)
{
    field_element x = field_element::from_u64(5);
    for (int i = 0; i < 32; ++i) {
        const auto r = x.square().sqrt();
        ASSERT_TRUE(r);
        EXPECT_TRUE(*r == x || *r == -x);
        x = x * field_element::from_u64(0x10001) + field_element::from_u64(1);
    }
    // -1 is not a square, since p = 3 (mod 4)
    EXPECT_FALSE((-field_element::from_u64(1)).sqrt());
    std::uint64_t ok = 1;
    (void)(-field_element::from_u64(1)).sqrt_ct(ok);
    EXPECT_EQ(ok, 0u);
}

TEST(CryptoSecp256k1Field, SelectAndParity)
{
    const auto a = field_element::from_u64(1), b = field_element::from_u64(2);
    EXPECT_EQ(field_element::select(~0ull, a, b), a);
    EXPECT_EQ(field_element::select(0, a, b), b);
    EXPECT_EQ(a.is_odd(), 1u);
    EXPECT_EQ(b.is_odd(), 0u);
    EXPECT_EQ((-a).is_odd(), 0u);   // p - 1 is even
}

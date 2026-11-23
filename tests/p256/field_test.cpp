//
//  field_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/p256/field.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using snicholls::crypto::p256::field_element;
using snicholls::crypto::test::hex;

namespace {
constexpr auto p_bytes = hex<32>("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
constexpr auto p_minus_1 = hex<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");
} // namespace

// Identities at compile time
static_assert(field_element::from_u64(7).inverse() * field_element::from_u64(7) == field_element::from_u64(1));
static_assert((field_element::from_u64(3) + field_element::from_u64(4)) * field_element::from_u64(5) ==
              field_element::from_u64(35));
static_assert(field_element::from_bytes(p_minus_1).value() + field_element::from_u64(1) == field_element{});
static_assert(!field_element::from_bytes(p_bytes).has_value());
static_assert(field_element::from_u64(0).inverse() == field_element{});

TEST(CryptoP256Field, SquareRootsAndBoundaries)
{
    const auto four = field_element::from_u64(4);
    std::uint64_t square = 0;
    const auto r = four.sqrt_ct(square);
    EXPECT_NE(square, 0u);
    EXPECT_EQ(r.square(), four);
    // -1 is not a square: p = 3 mod 4
    (void)(-field_element::from_u64(1)).sqrt_ct(square);
    EXPECT_EQ(square, 0u);
    EXPECT_EQ(field_element::from_bytes(p_minus_1).value().to_bytes(), p_minus_1);
    EXPECT_EQ((-field_element::from_u64(1)).to_bytes(), p_minus_1);
    std::uint64_t below = 0;
    EXPECT_EQ(field_element::from_bytes_ct(p_bytes, below), field_element{});
    EXPECT_EQ(below, 0u);
    EXPECT_EQ(field_element::from_u64(3).is_odd(), 1u);
}

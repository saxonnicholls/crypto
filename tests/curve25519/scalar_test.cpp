//
//  scalar_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/curve25519/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <type_traits>

using snicholls::crypto::curve25519::scalar;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

namespace {
constexpr auto order = hex<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
constexpr auto order_minus_1 = hex<32>("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
} // namespace

static_assert(std::is_trivially_copyable_v<scalar>);
static_assert(!scalar::is_canonical(order));
static_assert(scalar::is_canonical(order_minus_1));
static_assert(scalar::from_bytes_reduced(order) == scalar{});

TEST(CryptoCurve25519Scalar, CanonicalMeansBelowTheOrder)
{
    EXPECT_FALSE(scalar::from_canonical(order));
    EXPECT_TRUE(scalar::from_canonical(order_minus_1));
    EXPECT_FALSE(scalar::from_canonical(hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
    EXPECT_TRUE(scalar::from_canonical(hex<32>("0000000000000000000000000000000000000000000000000000000000000000")));
}

TEST(CryptoCurve25519Scalar, ReduceMatchesExactArithmetic)
{
    std::array<std::uint8_t, 64> all_ones{};
    all_ones.fill(0xff);
    // (2^512 - 1) mod L, computed with exact integers
    EXPECT_EQ(to_hex(scalar::reduce(all_ones).to_bytes()), "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903");
    EXPECT_EQ(scalar::from_bytes_reduced(order_minus_1).to_bytes(), order_minus_1);
}

TEST(CryptoCurve25519Scalar, MulAddMatchesExactArithmetic)
{
    const auto a = scalar::from_bytes_reduced(hex<32>("efcdab8967452301efcdab8967452301efcdab8967452301efcdab8967452301"));
    const auto b = scalar::from_bytes_reduced(hex<32>("1032547698badcfe1032547698badcfe1032547698badcfe1032547698badcfe"));
    EXPECT_EQ(to_hex(b.to_bytes()), "2dc7ec030decc8d58101d2e98c16ccc50f32547698badcfe1032547698badc0e");
    EXPECT_EQ(to_hex(scalar::mul_add(a, b, scalar::from_u64(12345)).to_bytes()),
              "f1a8dfd2197e9011cd92002ecb5b38ff3321144794b6aa9d1e7d4ed58e7e720e");
    // (L - 1)(L - 1) + (L - 1) = (L - 1) L = 0
    const auto m1 = *scalar::from_canonical(order_minus_1);
    EXPECT_EQ(scalar::mul_add(m1, m1, m1), scalar{});
    EXPECT_EQ(scalar::mul_add(scalar::from_u64(6), scalar::from_u64(7), scalar::from_u64(0)), scalar::from_u64(42));
}

TEST(CryptoCurve25519Scalar, Nibbles)
{
    const auto s = scalar::from_u64(0x1234);
    EXPECT_EQ(s.nibble(0), 4u);
    EXPECT_EQ(s.nibble(1), 3u);
    EXPECT_EQ(s.nibble(3), 1u);
    EXPECT_EQ(s.nibble(63), 0u);
}

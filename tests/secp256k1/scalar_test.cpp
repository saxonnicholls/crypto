//
//  scalar_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/secp256k1/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <type_traits>

using snicholls::crypto::secp256k1::scalar;
using snicholls::crypto::test::hex;

namespace {
constexpr auto n_bytes = hex<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
constexpr auto n_minus_1 = hex<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
constexpr auto half_n = hex<32>("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
constexpr auto half_n_plus_1 = hex<32>("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
} // namespace

static_assert(std::is_trivially_copyable_v<scalar>);
static_assert(scalar::order_bytes() == n_bytes);
static_assert(!scalar::from_bytes(n_bytes).has_value());
static_assert((*scalar::from_bytes(n_minus_1) + scalar::from_u64(1)).is_zero());
static_assert(scalar::from_u64(7).inverse() * scalar::from_u64(7) == scalar::from_u64(1));

TEST(CryptoSecp256k1Scalar, RangeChecksAtTheOrder)
{
    EXPECT_FALSE(scalar::from_bytes(n_bytes));
    ASSERT_TRUE(scalar::from_bytes(n_minus_1));
    std::uint64_t below = 0;
    const auto r = scalar::from_bytes_ct(n_bytes, below);
    EXPECT_EQ(below, 0u);
    EXPECT_TRUE(r.is_zero());   // n reduces to zero
    EXPECT_TRUE(scalar::from_bytes_reduced(n_bytes).is_zero());
    const auto all_ones = hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    // 2^256 - 1 - n = 0x14551231950b75fc4402da1732fc9bebe
    EXPECT_EQ(scalar::from_bytes_reduced(all_ones).to_bytes(),
              hex<32>("000000000000000000000000000000014551231950b75fc4402da1732fc9bebe"));
}

TEST(CryptoSecp256k1Scalar, HighMeansAboveHalfTheOrder)
{
    EXPECT_FALSE(scalar::from_bytes(half_n)->is_high());
    EXPECT_TRUE(scalar::from_bytes(half_n_plus_1)->is_high());
    EXPECT_TRUE(scalar::from_bytes(n_minus_1)->is_high());
    EXPECT_FALSE(scalar::from_u64(1).is_high());
    EXPECT_EQ(-*scalar::from_bytes(half_n_plus_1), *scalar::from_bytes(half_n));
}

TEST(CryptoSecp256k1Scalar, ProductsReduceAndInvert)
{
    const auto m1 = *scalar::from_bytes(n_minus_1);
    EXPECT_EQ(m1 * m1, scalar::from_u64(1));
    scalar x = scalar::from_u64(0x1234567);
    for (int i = 0; i < 64; ++i) {
        EXPECT_EQ(x * x.inverse(), scalar::from_u64(1));
        x = x * x + m1;
    }
    EXPECT_TRUE(scalar{}.inverse().is_zero());
}

TEST(CryptoSecp256k1Scalar, NibblesAndSelect)
{
    const auto s = *scalar::from_bytes(hex<32>("f000000000000000000000000000000000000000000000000000000000000021"));
    EXPECT_EQ(s.nibble(0), 1u);
    EXPECT_EQ(s.nibble(1), 2u);
    EXPECT_EQ(s.nibble(63), 0xfu);
    EXPECT_EQ(scalar::select(~0ull, s, scalar{}), s);
    EXPECT_TRUE(scalar::select(0, s, scalar{}).is_zero());
}

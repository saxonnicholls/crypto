//
//  scalar_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/p256/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using snicholls::crypto::p256::scalar;
using snicholls::crypto::test::hex;

namespace {
constexpr auto n_bytes = hex<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
constexpr auto all_ones = hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
} // namespace

static_assert(scalar::order_bytes() == n_bytes);
static_assert(scalar::from_u64(12345).inverse() * scalar::from_u64(12345) == scalar::from_u64(1));
static_assert(!scalar::from_bytes(n_bytes).has_value());
static_assert(scalar::from_bytes_reduced(n_bytes) == scalar{});

TEST(CryptoP256Scalar, ReductionAndArithmetic)
{
    // 2^256 - 1 mod n = 2^256 - 1 - n
    const auto r = scalar::from_bytes_reduced(all_ones);
    EXPECT_EQ(r.to_bytes(), hex<32>("00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae"));
    EXPECT_EQ(-scalar::from_u64(1) + scalar::from_u64(1), scalar{});
    EXPECT_EQ((scalar::from_u64(6) - scalar::from_u64(9)) + scalar::from_u64(3), scalar{});
    EXPECT_TRUE(scalar{}.is_zero());
    EXPECT_EQ(scalar::select(~0ull, scalar::from_u64(1), scalar::from_u64(2)), scalar::from_u64(1));
}

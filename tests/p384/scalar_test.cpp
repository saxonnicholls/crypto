//
//  scalar_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/p384/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using snicholls::crypto::p384::scalar;
using snicholls::crypto::test::hex;

namespace {
constexpr auto n_bytes = hex<48>("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
constexpr auto all_ones = hex<48>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
} // namespace

static_assert(scalar::order_bytes() == n_bytes);
static_assert(scalar::from_u64(12345).inverse() * scalar::from_u64(12345) == scalar::from_u64(1));
static_assert(!scalar::from_bytes(n_bytes).has_value());
static_assert(scalar::from_bytes_reduced(n_bytes) == scalar{});

TEST(CryptoP384Scalar, ReductionAndArithmetic)
{
    // 2^384 - 1 mod n = 2^384 - 1 - n
    const auto r = scalar::from_bytes_reduced(all_ones);
    EXPECT_EQ(r.to_bytes(), hex<48>("000000000000000000000000000000000000000000000000389cb27e0bc8d220a7e5f24db74f58851313e695333ad68c"));
    EXPECT_EQ(-scalar::from_u64(1) + scalar::from_u64(1), scalar{});
    EXPECT_EQ((scalar::from_u64(6) - scalar::from_u64(9)) + scalar::from_u64(3), scalar{});
    EXPECT_TRUE(scalar{}.is_zero());
    EXPECT_EQ(scalar::select(~0ull, scalar::from_u64(1), scalar::from_u64(2)), scalar::from_u64(1));
}

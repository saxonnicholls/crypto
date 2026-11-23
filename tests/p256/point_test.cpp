//
//  point_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/p256/point.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::p256;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

// The group law at compile time: G on the curve, G + G = 2G, G + identity = G, G - G = identity
static_assert(point::base().to_affine().value().is_on_curve());
static_assert(point::base() + point::base() == point::base().dbl());
static_assert(point::base() + point::identity() == point::base());
static_assert((point::base() + -point::base()).is_identity());

TEST(CryptoP256Point, KnownMultiplesAndTheOrder)
{
    // 2G and 3G (NIST's published multiples of the P-256 generator)
    const auto two = point::mul(scalar::from_u64(2), point::base()).to_affine().value();
    EXPECT_EQ(to_hex(two.x.to_bytes()), "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");
    EXPECT_EQ(to_hex(two.y.to_bytes()), "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
    const auto three = point::mul_base(scalar::from_u64(3)).to_affine().value();
    EXPECT_EQ(to_hex(three.x.to_bytes()), "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c");
    // n G = identity: (n - 1) G + G
    const auto n1 = scalar::from_bytes_reduced(hex<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"));
    EXPECT_TRUE((point::mul_base(n1) + point::base()).is_identity());
    // the variable-time double multiplication agrees with the constant-time one
    const auto a = scalar::from_u64(123456789), b = scalar::from_u64(987654321);
    const auto q = point::mul_base(scalar::from_u64(42));
    EXPECT_EQ(point::mul_add_public(a, b, q), point::mul_base(a) + point::mul(b, q));
    // SEC1 round trips
    EXPECT_EQ(affine_point::decode(two.compressed()).value(), two);
    EXPECT_EQ(affine_point::decode(two.uncompressed()).value(), two);
}

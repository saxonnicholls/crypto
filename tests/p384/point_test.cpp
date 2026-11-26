//
//  point_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/p384/point.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::p384;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

// The group law at compile time: G on the curve, G + G = 2G, G + identity = G, G - G = identity
static_assert(point::base().to_affine().value().is_on_curve());
static_assert(point::base() + point::base() == point::base().dbl());
static_assert(point::base() + point::identity() == point::base());
static_assert((point::base() + -point::base()).is_identity());

TEST(CryptoP384Point, KnownMultiplesAndTheOrder)
{
    // 2G and 3G
    const auto two = point::mul(scalar::from_u64(2), point::base()).to_affine().value();
    EXPECT_EQ(to_hex(two.x.to_bytes()), "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61");
    EXPECT_EQ(to_hex(two.y.to_bytes()), "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80");
    const auto three = point::mul_base(scalar::from_u64(3)).to_affine().value();
    EXPECT_EQ(to_hex(three.x.to_bytes()), "077a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831");
    // n G = identity: (n - 1) G + G
    const auto n1 = scalar::from_bytes_reduced(
        hex<48>("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972"));
    EXPECT_TRUE((point::mul_base(n1) + point::base()).is_identity());
    // the variable-time double multiplication agrees with the constant-time one
    const auto a = scalar::from_u64(123456789), b = scalar::from_u64(987654321);
    const auto q = point::mul_base(scalar::from_u64(42));
    EXPECT_EQ(point::mul_add_public(a, b, q), point::mul_base(a) + point::mul(b, q));
    // SEC1 round trips, and the identity has no affine form
    EXPECT_EQ(affine_point::decode(two.compressed()).value(), two);
    EXPECT_EQ(affine_point::decode(two.uncompressed()).value(), two);
    EXPECT_EQ(two.compressed().size(), 49u);
    EXPECT_EQ(two.uncompressed().size(), 97u);
    EXPECT_FALSE(point::identity().to_affine());
    // a 65-byte (P-256 sized) encoding is not a P-384 point
    EXPECT_FALSE(affine_point::decode(std::array<std::uint8_t, 65>{0x04}));
}

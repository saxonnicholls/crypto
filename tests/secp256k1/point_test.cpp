//
//  point_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/secp256k1/point.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <string>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

namespace {
// 2G and 3G as published (SEC 2 and every secp256k1 library's tests)
constexpr affine_point g2{*field_element::from_bytes(hex<32>("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")),
                          *field_element::from_bytes(hex<32>("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"))};
constexpr affine_point g3{*field_element::from_bytes(hex<32>("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")),
                          *field_element::from_bytes(hex<32>("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"))};
} // namespace

// The group law, evaluated by the compiler
static_assert(generator().is_on_curve() && g2.is_on_curve() && g3.is_on_curve());
static_assert(point::base().dbl() == point(g2));
static_assert(point::base() + point::base() == point(g2));
static_assert(point::base() + point(g2) == point(g3));
static_assert((point::base() + -point::base()).is_identity());
static_assert(point::identity() + point::identity() == point::identity());
static_assert(point::identity().dbl().is_identity());

TEST(CryptoSecp256k1Point, ScalarMultiplesMatchPublishedPoints)
{
    EXPECT_EQ(*point::mul_base(scalar::from_u64(2)).to_affine(), g2);
    EXPECT_EQ(*point::mul_base(scalar::from_u64(3)).to_affine(), g3);
    // 7G and 20G from the secp256k1 multiples list widely republished with the curve
    EXPECT_EQ(to_hex(point::mul_base(scalar::from_u64(7)).to_affine()->x.to_bytes()),
              "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc");
    EXPECT_EQ(to_hex(point::mul_base(scalar::from_u64(20)).to_affine()->x.to_bytes()),
              "4ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97");
}

TEST(CryptoSecp256k1Point, OrderAndIdentityBehave)
{
    const scalar n_minus_1 = scalar{} - scalar::from_u64(1);
    const auto a = point::mul_base(n_minus_1).to_affine();
    ASSERT_TRUE(a);
    EXPECT_EQ(a->x, generator().x);
    EXPECT_EQ(a->y, -generator().y);
    EXPECT_TRUE(point::mul_base(scalar{}).is_identity());
    EXPECT_FALSE(point::identity().to_affine());
    std::uint64_t finite = 1;
    (void)point::identity().to_affine_ct(finite);
    EXPECT_EQ(finite, 0u);
    EXPECT_TRUE(point::mul(scalar::from_u64(5), point::identity()).is_identity());
}

TEST(CryptoSecp256k1Point, ConstantTimeAndPublicMultiplicationAgree)
{
    scalar a = scalar::from_u64(0xdeadbeef), b = scalar::from_u64(0xfeedface);
    const point q = point::mul_base(scalar::from_u64(99));
    for (int i = 0; i < 8; ++i) {
        EXPECT_EQ(point::mul_add_public(a, b, q), point::mul_base(a) + point::mul(b, q));
        a = a * a + scalar::from_u64(3);
        b = b * a;
    }
    EXPECT_EQ(point::mul_add_public(scalar{}, scalar{}, q), point::identity());
}

TEST(CryptoSecp256k1Point, DecompressPicksTheParity)
{
    const auto even = decompress(generator().x, 0), odd = decompress(generator().x, 1);
    ASSERT_TRUE(even && odd);
    EXPECT_EQ(*even, generator());   // G's y is even
    EXPECT_EQ(odd->y, -generator().y);
    // x = 5: 5^3 + 7 = 132 is not a square modulo p
    EXPECT_FALSE(decompress(field_element::from_u64(5), 0));
}

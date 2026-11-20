//
//  edwards_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/curve25519/edwards.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <type_traits>

using snicholls::crypto::curve25519::field_element;
using snicholls::crypto::curve25519::point;
using snicholls::crypto::curve25519::scalar;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

static_assert(std::is_trivially_copyable_v<point>);
// d = -121665 / 121666, and the group law, evaluated by the compiler
static_assert(point::d() * field_element::from_u64(121666) == -field_element::from_u64(121665));
static_assert(point::base() + point::base() == point::base().dbl());
static_assert(point::base() + point::identity() == point::base());
static_assert((point::base() - point::base()).is_identity());
static_assert(point::base().encode()[0] == 0x58);

TEST(CryptoCurve25519Edwards, BaseIsOnTheCurveAndEncodesAsRfc8032)
{
    EXPECT_EQ(to_hex(point::base().encode()), "5866666666666666666666666666666666666666666666666666666666666666");
    const auto b = point::decode(point::base().encode());
    ASSERT_TRUE(b);
    EXPECT_EQ(*b, point::base());
    EXPECT_TRUE(point::base().is_torsion_free());
    EXPECT_FALSE(point::base().is_small_order());
    EXPECT_EQ(to_hex(point::identity().encode()), "0100000000000000000000000000000000000000000000000000000000000000");
}

TEST(CryptoCurve25519Edwards, ConstantTimeAndPublicMultiplicationAgree)
{
    scalar a = scalar::from_u64(0x1234567), b = scalar::from_u64(0x89abcdef);
    const point q = point::mul_base(scalar::from_u64(99));
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(point::mul_add_public(a, b, q), point::mul_base(a) + point::mul(b, q));
        EXPECT_EQ(point::mul(a, point::base()), point::mul_base(a));
        EXPECT_EQ(point::mul_public(a.to_bytes(), q), point::mul(a, q));
        a = scalar::mul_add(a, a, scalar::from_u64(3));
        b = scalar::mul_add(a, b, scalar::from_u64(1));
    }
    EXPECT_TRUE(point::mul_base(scalar{}).is_identity());
    EXPECT_TRUE(point::mul(scalar::from_u64(5), point::identity()).is_identity());
}

TEST(CryptoCurve25519Edwards, TheEightSmallOrderPointsDecodeAndAreSmallOrder)
{
    const char* encodings[] = {
        "0100000000000000000000000000000000000000000000000000000000000000",   // identity
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",   // (0, -1), order 2
        "0000000000000000000000000000000000000000000000000000000000000000",   // order 4
        "0000000000000000000000000000000000000000000000000000000000000080",   // order 4
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",   // order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    };
    for (const char* e : encodings) {
        const auto bytes = hex<32>(e);
        const auto p = point::decode(bytes);
        ASSERT_TRUE(p) << e;
        EXPECT_TRUE(p->is_small_order()) << e;
        EXPECT_EQ(p->encode(), bytes) << e;
    }
    // A mixed-order point: B plus a point of order 2 is neither small-order nor torsion-free
    const auto two = point::decode(hex<32>("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    const point mixed = point::base() + *two;
    EXPECT_FALSE(mixed.is_small_order());
    EXPECT_FALSE(mixed.is_torsion_free());
}

TEST(CryptoCurve25519Edwards, StrictDecodingRejectsNonCanonicalEncodings)
{
    // y = p (the identity's y plus p), and y = p + 1
    EXPECT_FALSE(point::decode(hex<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")));
    EXPECT_FALSE(point::decode(hex<32>("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")));
    // The identity with the sign bit set: x = 0 cannot be negative
    EXPECT_FALSE(point::decode(hex<32>("0100000000000000000000000000000000000000000000000000000000000080")));
    // y = 2 is not on the curve: (y^2 - 1) / (d y^2 + 1) has no square root
    EXPECT_FALSE(point::decode(hex<32>("0200000000000000000000000000000000000000000000000000000000000000")));
}

TEST(CryptoCurve25519Edwards, SelectAndCofactor)
{
    const point b = point::base();
    EXPECT_EQ(point::select(~0ull, b, point::identity()), b);
    EXPECT_TRUE(point::select(0, b, point::identity()).is_identity());
    EXPECT_EQ(b.mul_by_cofactor(), point::mul_base(scalar::from_u64(8)));
    EXPECT_EQ(point::table(b)[5], point::mul_base(scalar::from_u64(5)));
}

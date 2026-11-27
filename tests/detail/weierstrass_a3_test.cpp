//
//  weierstrass_a3_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The shared curve code: P-256's and P-384's points are its instances, so the group law is checked on both here;
//  each curve's own tests (tests/p256/point_test.cpp, tests/p384/point_test.cpp) check its known multiples.
//
#include <snicholls/crypto/detail/weierstrass_a3.hpp>
#include <snicholls/crypto/p256/point.hpp>
#include <snicholls/crypto/p384/point.hpp>
#include <gtest/gtest.h>

#include <type_traits>

namespace {

template <class Point>
void group_law()
{
    using scalar = typename Point::scalar;
    const Point g = Point::base();
    const Point a = Point::mul(scalar::from_u64(5), g), b = Point::mul(scalar::from_u64(11), g);
    EXPECT_EQ(a + b, Point::mul(scalar::from_u64(16), g));                     // 5G + 11G = 16G
    EXPECT_EQ(a + b, b + a);                                                   // commutative
    EXPECT_EQ((a + b) + g, a + (b + g));                                       // associative
    EXPECT_EQ(a + Point::identity(), a);                                       // the identity
    EXPECT_TRUE((a + -a).is_identity());                                       // inverses
    EXPECT_EQ(Point::select(~0ull, a, b), a);
    EXPECT_EQ(Point::select(0, a, b), b);
    std::uint64_t finite = 1;
    (void)Point::identity().to_affine_ct(finite);
    EXPECT_EQ(finite, 0u);
    const auto af = a.to_affine().value();
    EXPECT_TRUE(af.is_on_curve());
    auto bad = af;
    bad.x = bad.x + decltype(bad.x)::from_u64(1);
    EXPECT_FALSE(bad.is_on_curve());
    EXPECT_FALSE(decltype(af)::decode(af.compressed()).value() == bad);
}

} // namespace

static_assert(std::is_same_v<snicholls::crypto::p256::point, snicholls::crypto::detail::point_t<snicholls::crypto::p256::detail::curve>>);
static_assert(std::is_same_v<snicholls::crypto::p384::point, snicholls::crypto::detail::point_t<snicholls::crypto::p384::detail::curve>>);

TEST(CryptoDetailWeierstrassA3, GroupLawOnP256)
{
    group_law<snicholls::crypto::p256::point>();
}

TEST(CryptoDetailWeierstrassA3, GroupLawOnP384)
{
    group_law<snicholls::crypto::p384::point>();
}

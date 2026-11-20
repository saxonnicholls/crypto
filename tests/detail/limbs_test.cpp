//
//  limbs_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/detail/limbs.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace d = snicholls::crypto::detail;

// A toy modulus of the same shape, 2^256 - 189 (the largest 256-bit prime), checked against the arithmetic it implies
inline constexpr d::pseudo_mersenne<1> toy{{~189ull + 1, ~0ull, ~0ull, ~0ull}, {189}, {189, 0, 0, 0}};

static_assert([] {
    std::uint64_t c = 0;
    const auto r = d::add_carry(~0ull, 1, c);
    return r == 0 && c == 1;
}());
static_assert([] {
    std::uint64_t b = 0;
    const auto r = d::sub_borrow(0, 1, b);
    return r == ~0ull && b == 1;
}());

TEST(CryptoDetailLimbs, AddAndSubWrapAtTheModulus)
{
    const d::limbs4 m_minus_1{toy.m[0] - 1, ~0ull, ~0ull, ~0ull};
    const d::limbs4 one{1, 0, 0, 0}, two{2, 0, 0, 0}, zero{};
    EXPECT_EQ(d::mod_add(m_minus_1, one, toy), zero);
    EXPECT_EQ(d::mod_add(m_minus_1, two, toy), one);
    EXPECT_EQ(d::mod_sub(zero, one, toy), m_minus_1);
    EXPECT_EQ(d::mod_sub(one, two, toy), m_minus_1);
}

TEST(CryptoDetailLimbs, MulOfMinusOneSquaredIsOne)
{
    const d::limbs4 m_minus_1{toy.m[0] - 1, ~0ull, ~0ull, ~0ull};
    EXPECT_EQ(d::mod_mul(m_minus_1, m_minus_1, toy), (d::limbs4{1, 0, 0, 0}));
}

TEST(CryptoDetailLimbs, Mul4IsTheFullProduct)
{
    const d::limbs4 a{~0ull, ~0ull, ~0ull, ~0ull};
    const auto p = d::mul4(a, a);   // (2^256 - 1)^2 = 2^512 - 2^257 + 1
    EXPECT_EQ(p[0], 1u);
    EXPECT_EQ(p[1], 0u);
    EXPECT_EQ(p[3], 0u);
    EXPECT_EQ(p[4], ~0ull - 1);
    EXPECT_EQ(p[7], ~0ull);
}

TEST(CryptoDetailLimbs, PowByFermatInverts)
{
    const d::limbs4 e{toy.m[0] - 2, ~0ull, ~0ull, ~0ull};
    const d::limbs4 a{123456789, 42, 7, 1};
    const auto inv = d::mod_pow_public(a, e, toy);
    EXPECT_EQ(d::mod_mul(a, inv, toy), (d::limbs4{1, 0, 0, 0}));
}

TEST(CryptoDetailLimbs, BigEndianRoundTrip)
{
    std::array<std::uint8_t, 32> b{};
    for (std::size_t i = 0; i < 32; ++i)
        b[i] = static_cast<std::uint8_t>(i);
    const auto l = d::from_be(b);
    EXPECT_EQ(l[3], 0x0001020304050607ull);
    EXPECT_EQ(d::to_be(l), b);
    EXPECT_NE(d::mask_less4({1, 0, 0, 0}, {2, 0, 0, 0}), 0u);
    EXPECT_EQ(d::mask_less4({0, 0, 0, 1}, {~0ull, 0, 0, 0}), 0u);
}

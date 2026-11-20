//
//  constant_time_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/constant_time.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <limits>

namespace ct = snicholls::crypto::ct;

static_assert(ct::mask_from_bit(1) == ~std::uint64_t{0});
static_assert(ct::mask_from_bit(0) == 0);
static_assert(ct::mask_is_zero(0) == ~std::uint64_t{0} && ct::mask_is_zero(5) == 0);
static_assert(ct::mask_is_zero(std::uint64_t{1} << 63) == 0);
static_assert(ct::mask_less(1, 2) != 0 && ct::mask_less(2, 1) == 0 && ct::mask_less(3, 3) == 0);
static_assert(ct::select<std::uint8_t>(~std::uint64_t{0}, 7, 9) == 7 && ct::select<std::uint8_t>(0, 7, 9) == 9);
static_assert(noexcept(ct::equal({}, {})));

TEST(CryptoConstantTime, MaskLessAgreesWithLessOnBoundaries)
{
    constexpr std::uint64_t max = std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t values[] = {0, 1, 2, 0x7fffffffffffffff, 0x8000000000000000, max - 1, max};
    for (const auto a : values)
        for (const auto b : values)
            EXPECT_EQ(ct::mask_less(a, b) != 0, a < b) << a << " " << b;
}

TEST(CryptoConstantTime, MaskEqualAndIsZero)
{
    EXPECT_NE(ct::mask_equal(42, 42), 0u);
    EXPECT_EQ(ct::mask_equal(42, 43), 0u);
    EXPECT_EQ(ct::mask_is_zero(~std::uint64_t{0}), 0u);
}

TEST(CryptoConstantTime, ConditionalSwapSwapsOnlyUnderTheFullMask)
{
    std::uint32_t a = 1, b = 2;
    ct::conditional_swap(0, a, b);
    EXPECT_EQ(a, 1u);
    EXPECT_EQ(b, 2u);
    ct::conditional_swap(~std::uint64_t{0}, a, b);
    EXPECT_EQ(a, 2u);
    EXPECT_EQ(b, 1u);
}

TEST(CryptoConstantTime, EqualComparesLengthsThenBytes)
{
    const std::array<std::uint8_t, 3> x{1, 2, 3}, y{1, 2, 3}, z{1, 2, 4};
    const std::array<std::uint8_t, 2> shorter{1, 2};
    EXPECT_TRUE(ct::equal(x, y));
    EXPECT_FALSE(ct::equal(x, z));
    EXPECT_FALSE(ct::equal(x, shorter));
    EXPECT_TRUE(ct::equal({}, {}));
}

TEST(CryptoConstantTime, IsZeroAndConditionalCopy)
{
    std::array<std::uint8_t, 4> a{};
    EXPECT_TRUE(ct::is_zero(a));
    const std::array<std::uint8_t, 4> src{9, 8, 7, 6};
    ct::conditional_copy(0, a, src);
    EXPECT_TRUE(ct::is_zero(a));
    ct::conditional_copy(~std::uint64_t{0}, a, src);
    EXPECT_EQ(a, src);
    EXPECT_FALSE(ct::is_zero(a));
}

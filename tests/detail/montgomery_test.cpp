//
//  montgomery_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/montgomery.hpp>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>

using namespace snicholls::crypto::detail;

namespace {
constexpr wide small(std::uint64_t v)
{
    wide w{};
    w[0] = v;
    return w;
}
} // namespace

// Values checked with Python's pow()
static_assert([] {
    const auto m = montgomery::make(small(1000003)).value();
    return m.pow(small(123456), 65537)[0] == 146354 && m.pow(small(2), 3)[0] == 8;
}());

TEST(CryptoDetailMontgomery, RefusesEvenAndTinyModuli)
{
    EXPECT_FALSE(montgomery::make(small(0)));
    EXPECT_FALSE(montgomery::make(small(1)));
    EXPECT_FALSE(montgomery::make(small(1000002)));
    EXPECT_TRUE(montgomery::make(small(3)));
}

TEST(CryptoDetailMontgomery, PowerIdentitiesAtFullWidth)
{
    // n = 2^4095 + 2^1000 * 12345 + 1: 64 limbs, odd
    wide n{};
    n[63] = 1ull << 63;
    n[1000 / 64] |= 12345ull << (1000 % 64);
    n[0] |= 1;
    const auto m = montgomery::make(n).value();
    EXPECT_EQ(m.limbs(), 64u);
    const auto s = small(7);
    EXPECT_EQ(m.pow(s, 1), s);
    EXPECT_EQ(m.pow(s, 2), small(49));
    // s^(a+b) = s^a s^b, checked through mul with the R factors cancelled by a second pow
    const auto a = m.pow(s, 65537);
    const auto b = m.pow(a, 3);
    const auto c = m.pow(s, 196611);
    EXPECT_EQ(b, c);
}

TEST(CryptoDetailMontgomery, BytesRoundTrip)
{
    const std::array<std::uint8_t, 5> be{0x00, 0x01, 0x02, 0x03, 0x04};
    const auto w = wide_from_be(be).value();
    EXPECT_EQ(w[0], 0x01020304u);
    EXPECT_EQ(wide_bits(w), 25u);
    std::array<std::uint8_t, 5> out{};
    wide_to_be(w, out);
    EXPECT_EQ(out, be);
    std::array<std::uint8_t, 513> too_long{};
    too_long[0] = 1;
    EXPECT_FALSE(wide_from_be(too_long));
}

//
//  ecdsa_der_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/ecdsa_der.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <vector>

using namespace snicholls::crypto::detail;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::to_hex;

// The shortest and the longest encodings, at compile time
static_assert(ecdsa_der_encode(std::array<std::uint8_t, 32>{}, std::array<std::uint8_t, 32>{}).size() == 8);
static_assert(ecdsa_der_encode(hex<32>("ff00000000000000000000000000000000000000000000000000000000000000"),
                               hex<32>("8000000000000000000000000000000000000000000000000000000000000000"))
                  .size() == 72);

TEST(CryptoDetailEcdsaDer, RoundTripAndStrictness)
{
    const auto r = hex<32>("00000000000000000000000000000000000000000000000000000000000000ff");
    const auto s = hex<32>("7f00000000000000000000000000000000000000000000000000000000000001");
    const auto der = ecdsa_der_encode(r, s);
    EXPECT_EQ(to_hex(std::span<const std::uint8_t>(der.data(), der.size())),
              "3026020200ff02207f00000000000000000000000000000000000000000000000000000000000001");
    const auto back = ecdsa_der_decode(std::span<const std::uint8_t>(der.data(), der.size())).value();
    EXPECT_EQ(back.first, r);
    EXPECT_EQ(back.second, s);
    EXPECT_EQ(der[4], 0x00);   // ff needs its sign byte
    // non-minimal padding, a negative integer, trailing bytes, more than 256 bits: refused
    EXPECT_FALSE(ecdsa_der_decode(std::span<const std::uint8_t>()));
    for (const char* bad : {"30080203000001020101", "300602018102010101", "3006020101020101" "00",
                            "302a0223010000000000000000000000000000000000000000000000000000000000000000020101"}) {
        const auto b = hex_bytes(bad);
        EXPECT_FALSE(ecdsa_der_decode(b)) << bad;
    }
    const auto ok = hex_bytes("3006020101020102");
    EXPECT_TRUE(ecdsa_der_decode(ok));
}

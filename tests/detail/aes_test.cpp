//
//  aes_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/aes.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::detail;
using snicholls::crypto::test::hex;

// The S-box at its known points, and inverse of every value
static_assert(aes_sbox(0x00) == 0x63 && aes_sbox(0x01) == 0x7c && aes_sbox(0x53) == 0xed && aes_sbox(0xff) == 0x16);

TEST(CryptoDetailAes, SboxIsABijectionAndGhashIsLinear)
{
    for (int v = 0; v < 256; ++v)
        EXPECT_EQ(aes_inv_sbox(aes_sbox(static_cast<std::uint8_t>(v))), v);
    // GHASH multiplication: x * 1 (the bit-reflected unit, 0x80 then zeros) = x
    const auto x = hex<16>("0388dace60b6a392f328c2b971b2fe78");
    const auto one = hex<16>("80000000000000000000000000000000");
    EXPECT_EQ(ghash_mul(x, one), x);
    EXPECT_EQ(ghash_mul(one, x), x);
    // the GCM specification's test case 2: H = E(0, 0), X1 = C ^ 0 times H
    EXPECT_EQ(ghash_mul(x, hex<16>("66e94bd4ef8a2c3b884cfa59ca342b2e")), hex<16>("5e2ec746917062882c85b0685353deb7"));
}

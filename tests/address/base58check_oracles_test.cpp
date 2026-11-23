//
//  base58check_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  base58check against python base58, bitcoinjs bs58check and bs58 (tests/fixtures/oracles/): payloads of every
//  length to 89 bytes with leading zeros, and text that must not decode.
//
#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

namespace a = snicholls::crypto::address;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::text_of;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoAddressBase58checkOracles, EncodingsAgreeBothWaysAndBadTextIsRefused)
{
    int ok = 0, refused = 0;
    for (const auto& f : oracle_rows("base58check.txt")) {
        const auto decoded = a::base58check_decode<128>(f[2]);
        if (f[0] == "refused") {
            EXPECT_FALSE(decoded) << "'" << f[2] << "'";
            ++refused;
            continue;
        }
        const auto payload = hex_bytes(f[1]);
        EXPECT_EQ(text_of(a::base58check_encode<128>(view(payload)).unwrap()), f[2]);
        ASSERT_TRUE(decoded) << f[2];
        EXPECT_EQ(to_hex(std::span<const std::uint8_t>(decoded->data(), decoded->size())), f[1]);
        ++ok;
    }
    EXPECT_GE(ok, 500);
    EXPECT_GE(refused, 400);
}

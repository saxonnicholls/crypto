//
//  bech32_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Segwit addresses against the BIP-173 / BIP-350 reference code, bitcoinjs-lib and the bech32 crate
//  (tests/fixtures/oracles/): every witness version and program length, and addresses that must be refused
//  (a changed symbol, mixed case, another network, the wrong checksum variant, a version or length out of range).
//
#include <snicholls/crypto/address/bech32.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

#include <string>

namespace a = snicholls::crypto::address;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::text_of;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoAddressBech32Oracles, SegwitAddressesAgreeBothWaysAndBadOnesAreRefused)
{
    int ok = 0, refused = 0;
    for (const auto& f : oracle_rows("segwit.txt")) {
        const auto decoded = a::segwit_decode(f[1], f[4]);
        if (f[0] == "refused") {
            EXPECT_FALSE(decoded) << f[1] << " " << f[4];
            ++refused;
            continue;
        }
        const auto version = static_cast<std::uint8_t>(std::stoi(f[2]));
        const auto program = hex_bytes(f[3]);
        ASSERT_TRUE(decoded) << f[4];
        EXPECT_EQ(decoded->version, version);
        EXPECT_EQ(to_hex(std::span<const std::uint8_t>(decoded->program.data(), decoded->program.size())), f[3]);
        if (f[4].find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == std::string::npos) {
            EXPECT_EQ(text_of(a::segwit_encode(f[1], version, view(program)).unwrap()), f[4]);
        }
        ++ok;
    }
    EXPECT_GE(ok, 600);
    EXPECT_GE(refused, 400);
}

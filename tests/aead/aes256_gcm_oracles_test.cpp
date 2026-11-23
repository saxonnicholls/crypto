//
//  aes256_gcm_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  AES-256-GCM against OpenSSL (through Python cryptography) and Node's crypto (tests/fixtures/oracles/): seal byte
//  for byte, and open of the sealed and of a tampered message.
//
#include <snicholls/crypto/aead/aes256_gcm.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

#include <vector>

using namespace snicholls::crypto::aead;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoAeadOracles, Aes256Gcm)
{
    int rows = 0, opened = 0;
    for (const auto& f : oracle_rows("aes256_gcm.txt")) {
        const auto k = hex_bytes(f[0]), n = hex_bytes(f[1]), ad = hex_bytes(f[2]), m = hex_bytes(f[3]), ct = hex_bytes(f[4]);
        const std::span<const std::uint8_t, 32> key(k.data(), 32);
        const std::span<const std::uint8_t, 12> nonce(n.data(), 12);
        std::vector<std::uint8_t> out(m.size());
        EXPECT_EQ(to_hex(aes256_gcm_seal(key, nonce, view(ad), view(m), out).unwrap()), f[5]) << "row " << rows;
        EXPECT_EQ(out, ct) << "row " << rows;
        const auto colon = f[6].find(':');
        const auto tct = hex_bytes(f[6].substr(0, colon) == "-" ? "" : f[6].substr(0, colon)), ttag = hex_bytes(f[6].substr(colon + 1));
        std::vector<std::uint8_t> back(tct.size());
        const bool ok = static_cast<bool>(aes256_gcm_open(key, nonce, view(ad), view(tct), std::span<const std::uint8_t, 16>(ttag.data(), 16), back));
        EXPECT_EQ(ok, f[7] == "1") << "row " << rows;
        opened += ok;
        ++rows;
    }
    EXPECT_EQ(rows, 300);
    EXPECT_EQ(opened, 100);
}

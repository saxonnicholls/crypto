//
//  ecdsa_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  P-256 against OpenSSL (through Python cryptography, in its RFC 6979 mode), noble-curves, RustCrypto's p256 and
//  Node's crypto (tests/fixtures/oracles/, scripts/generate_oracle_fixtures.py): keys, RFC 6979 signatures byte for
//  byte, verification of mutated and out-of-range signatures, SEC1 parsing.
//
#include <snicholls/crypto/p256/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::p256;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoP256Oracles, PublicKeysAgree)
{
    int valid = 0, refused = 0;
    for (const auto& f : oracle_rows("p256_keys.txt")) {
        const auto key = private_key::from_bytes(hex<32>(f[0]));
        if (f[1].empty()) {
            EXPECT_FALSE(key) << f[0];
            ++refused;
            continue;
        }
        ASSERT_TRUE(key) << f[0];
        const auto pub = key->public_key();
        EXPECT_EQ(to_hex(pub.compressed()), f[1]);
        EXPECT_EQ(to_hex(pub.uncompressed()), f[2]);
        ++valid;
    }
    EXPECT_GE(valid, 500);
    EXPECT_EQ(refused, 4);   // 0, n, n + 1, 2^256 - 1
}

TEST(CryptoP256Oracles, SignaturesAreByteForByteTheOracles)
{
    int rows = 0;
    for (const auto& f : oracle_rows("p256_sign.txt")) {
        const auto key = private_key::from_bytes(hex<32>(f[0])).unwrap();
        const auto sig = sign(key, hex<32>(f[2]));
        EXPECT_EQ(to_hex(sig.r), f[3]) << f[0];
        EXPECT_EQ(to_hex(sig.s), f[4]) << f[0];
        ++rows;
    }
    EXPECT_EQ(rows, 500);
}

TEST(CryptoP256Oracles, VerificationAgrees)
{
    int rows = 0, valid = 0;
    for (const auto& f : oracle_rows("p256_verify.txt")) {
        const auto pub_bytes = hex_bytes(f[1]);
        const auto pub = public_key::parse(view(pub_bytes)).unwrap();
        const bool ok = static_cast<bool>(verify(pub, hex<32>(f[3]), signature::from_jose(hex<64>(f[4]))));
        EXPECT_EQ(ok, f[5] == "1") << f[0] << " " << f[4];
        valid += ok;
        ++rows;
    }
    EXPECT_GT(rows, 2500);
    EXPECT_EQ(valid, 800);   // each signature and its n - s
}

TEST(CryptoP256Oracles, Sec1ParsingAgrees)
{
    int rows = 0;
    for (const auto& f : oracle_rows("p256_sec1.txt")) {
        const auto b = hex_bytes(f[0]);
        const auto key = public_key::parse(view(b));
        if (f[1].empty()) {
            EXPECT_FALSE(key) << f[0];
        } else {
            EXPECT_TRUE(key) << f[0];
            if (key) {
                EXPECT_EQ(to_hex(key->compressed()), f[1]);
            }
        }
        ++rows;
    }
    EXPECT_GT(rows, 900);
}

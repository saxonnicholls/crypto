//
//  ecdsa_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  P-384 against OpenSSL (through Python cryptography), noble-curves and Node's crypto (tests/fixtures/oracles/,
//  scripts/generate_oracle_fixtures.py): keys, verification of RFC 6979 signatures (OpenSSL's and noble's byte for
//  byte) and their mutations, ECDH, SEC1 parsing.
//
#include <snicholls/crypto/p384/ecdh.hpp>
#include <snicholls/crypto/p384/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::p384;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoP384Oracles, PublicKeysAgree)
{
    int valid = 0, refused = 0;
    for (const auto& f : oracle_rows("p384_keys.txt")) {
        const auto key = private_key::from_bytes(hex<48>(f[0]));
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
    EXPECT_GE(valid, 300);
    EXPECT_EQ(refused, 4);   // 0, n, n + 1, 2^384 - 1
}

TEST(CryptoP384Oracles, VerificationAgrees)
{
    int rows = 0, valid = 0;
    for (const auto& f : oracle_rows("p384_verify.txt")) {
        const auto pub_bytes = hex_bytes(f[1]);
        const auto pub = public_key::parse(view(pub_bytes)).unwrap();
        const bool ok = static_cast<bool>(verify(pub, hex<48>(f[3]), signature::from_jose(hex<96>(f[4]))));
        EXPECT_EQ(ok, f[5] == "1") << f[0] << " " << f[4];
        valid += ok;
        ++rows;
    }
    EXPECT_GT(rows, 1200);
    EXPECT_EQ(valid, 400);   // each signature and its n - s
}

TEST(CryptoP384Oracles, EcdhAgrees)
{
    int rows = 0, refused = 0;
    for (const auto& f : oracle_rows("p384_ecdh.txt")) {
        const auto key = private_key::from_bytes(hex<48>(f[0])).unwrap();
        const auto pub_bytes = hex_bytes(f[1]);
        const auto peer = public_key::parse(view(pub_bytes));
        if (f[2].empty()) {
            EXPECT_TRUE(!peer || !shared_secret(key, *peer)) << f[1];
            ++refused;
        } else {
            ASSERT_TRUE(peer) << f[1];
            EXPECT_EQ(to_hex(shared_secret(key, *peer).unwrap().reveal()), f[2]) << f[1];
        }
        ++rows;
    }
    EXPECT_EQ(rows, 200);
    EXPECT_EQ(refused, 20);
}

TEST(CryptoP384Oracles, Sec1ParsingAgrees)
{
    int rows = 0;
    for (const auto& f : oracle_rows("p384_sec1.txt")) {
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
    EXPECT_GT(rows, 700);
}

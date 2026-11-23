//
//  rsa_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  RSA verification against OpenSSL (through Python cryptography), Node's crypto and RustCrypto's rsa
//  (tests/fixtures/oracles/, scripts/generate_oracle_fixtures.py): their PKCS#1 v1.5 signatures, their verdicts on
//  mutated signatures and malformed encodings, PSS with salt lengths 0, 20, 32 and 64, and SubjectPublicKeyInfo.
//
#include <snicholls/crypto/rsa/rsa.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

#include <map>
#include <string>

using namespace snicholls::crypto::rsa;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoRsaOracles, Pkcs1SignaturesFromEveryOracleVerify)
{
    int rows = 0;
    for (const auto& f : oracle_rows("rsa_pkcs1_sign.txt")) {
        const auto spki = hex_bytes(f[0]), m = hex_bytes(f[1]), sig = hex_bytes(f[2]);
        const auto key = public_key::from_spki_der(view(spki)).unwrap();
        EXPECT_TRUE(verify_pkcs1v15_sha256(key, view(m), view(sig))) << f[2].substr(0, 32);
        ++rows;
    }
    EXPECT_EQ(rows, 240);
}

TEST(CryptoRsaOracles, Pkcs1VerdictsAgreeOnMutationsAndMalformedEncodings)
{
    int rows = 0, valid = 0;
    std::map<std::string, int> refused;
    for (const auto& f : oracle_rows("rsa_pkcs1_verify.txt")) {
        const auto n = hex_bytes(f[1]), e = hex_bytes(f[2]), m = hex_bytes(f[3]), sig = hex_bytes(f[4]);
        const auto key = public_key::from_components(view(n), view(e)).unwrap();
        const bool ok = static_cast<bool>(verify_pkcs1v15_sha256(key, view(m), view(sig)));
        EXPECT_EQ(ok, f[5] == "1") << f[0] << " " << f[4].substr(0, 32);
        valid += ok;
        refused[f[0]] += !ok;
        ++rows;
    }
    EXPECT_EQ(valid, 240);
    EXPECT_GT(refused["no_NULL"], 0);
    EXPECT_GT(rows, 700);
}

TEST(CryptoRsaOracles, PssVerdictsAgreeAcrossSaltLengths)
{
    int rows = 0, valid = 0;
    for (const auto& f : oracle_rows("rsa_pss_verify.txt")) {
        const auto n = hex_bytes(f[1]), e = hex_bytes(f[2]), m = hex_bytes(f[3]), sig = hex_bytes(f[4]);
        const auto key = public_key::from_components(view(n), view(e)).unwrap();
        const bool ok = static_cast<bool>(verify_pss_sha256(key, view(m), view(sig), std::stoul(f[5])));
        EXPECT_EQ(ok, f[6] == "1") << f[0] << " salt " << f[5];
        valid += ok;
        ++rows;
    }
    EXPECT_EQ(rows, 480);
    EXPECT_EQ(valid, 120);
}

TEST(CryptoRsaOracles, SubjectPublicKeyInfoReadsAlike)
{
    int rows = 0;
    for (const auto& f : oracle_rows("rsa_spki.txt")) {
        const auto der = hex_bytes(f[0]), n = hex_bytes(f[1]), e = hex_bytes(f[2]);
        const auto a = public_key::from_spki_der(view(der)).unwrap();
        const auto b = public_key::from_components(view(n), view(e)).unwrap();
        EXPECT_EQ(a.modulus_bits(), b.modulus_bits());
        EXPECT_EQ(a.exponent(), b.exponent());
        ++rows;
    }
    EXPECT_EQ(rows, 6);
}

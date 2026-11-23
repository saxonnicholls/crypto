//
//  ed25519_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Ed25519 against OpenSSL, libsodium, ed25519-dalek and noble (tests/fixtures/oracles/): keys and signatures
//  byte for byte, and verification where the verifiers' rules part (small-order and mixed-order points,
//  non-canonical encodings, S + L), against this library's stated rule; each oracle's own verdict is in the
//  fixture, checked against its stated rule by the generator.
//
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

#include <map>
#include <string>

using namespace snicholls::crypto::ed25519;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoEd25519Oracles, KeysAndSignaturesAreByteForByteTheOracles)
{
    int rows = 0;
    for (const auto& f : oracle_rows("ed25519_sign.txt")) {
        const auto kp = key_pair::from_seed(hex<32>(f[0]));
        const auto m = hex_bytes(f[1]);
        EXPECT_EQ(to_hex(kp.public_key().bytes), f[2]) << f[0];
        EXPECT_EQ(to_hex(kp.sign(view(m)).bytes), f[3]) << f[0];
        ++rows;
    }
    EXPECT_EQ(rows, 800);
}

TEST(CryptoEd25519Oracles, VerificationFollowsTheStatedCofactorlessRule)
{
    int rows = 0;
    std::map<std::string, int> accepted;
    for (const auto& f : oracle_rows("ed25519_verify.txt")) {
        const public_key key{hex<32>(f[1])};
        const auto m = hex_bytes(f[2]);
        const signature sig{hex<64>(f[3])};
        const bool ok = static_cast<bool>(verify(key, view(m), sig));
        EXPECT_EQ(ok, f[4] == "1") << f[0] << " " << f[1] << " " << f[2] << " " << f[3];
        accepted[f[0]] += ok;
        ++rows;
    }
    EXPECT_EQ(rows, 906);
    EXPECT_EQ(accepted["honest"], 150);
    EXPECT_EQ(accepted["S_+_L"], 0);
    EXPECT_GT(accepted["small-order_A_and_R,_S_=_0"], 0);   // Wycheproof's "acceptable": the equation holds
}

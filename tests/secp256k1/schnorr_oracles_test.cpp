//
//  schnorr_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  BIP-340 against libsecp256k1 (two bindings), k256 and noble (tests/fixtures/oracles/): signatures with fixed
//  auxiliary randomness, byte for byte, over 32-byte and variable-length messages, and verification.
//
#include <snicholls/crypto/secp256k1/schnorr.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoSecp256k1SchnorrOracles, SignaturesAreByteForByteTheOracles)
{
    int rows = 0;
    for (const auto& f : oracle_rows("bip340_sign.txt")) {
        const auto key = private_key::from_bytes(hex<32>(f[0])).unwrap();
        const auto m = hex_bytes(f[1]);
        const auto sig = schnorr_sign(key, view(m), hex<32>(f[2]));
        EXPECT_EQ(to_hex(sig.bytes), f[3]) << f[0] << " " << f[1];
        EXPECT_EQ(to_hex(xonly_public_key_of(key).bytes), f[4]);
        ++rows;
    }
    EXPECT_EQ(rows, 700);
}

TEST(CryptoSecp256k1SchnorrOracles, VerificationAgrees)
{
    int rows = 0, valid = 0;
    for (const auto& f : oracle_rows("bip340_verify.txt")) {
        const xonly_public_key key{hex<32>(f[0])};
        const auto m = hex_bytes(f[1]);
        const schnorr_signature sig{hex<64>(f[2])};
        const bool ok = static_cast<bool>(schnorr_verify(key, view(m), sig));
        EXPECT_EQ(ok, f[3] == "1") << f[0] << " " << f[1] << " " << f[2];
        ++rows;
        valid += ok;
    }
    EXPECT_EQ(rows, 2650);
    EXPECT_GE(valid, 500);
}

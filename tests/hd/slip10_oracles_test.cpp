//
//  slip10_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  SLIP-10 Ed25519 against the SLIP-10 reference, ed25519-hd-key and slip10_ed25519 (tests/fixtures/oracles/).
//
#include <snicholls/crypto/hd/slip10.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::hd;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoHdSlip10Oracles, KeysChainCodesAndPublicKeysAgree)
{
    int rows = 0;
    for (const auto& f : oracle_rows("slip10_ed25519.txt")) {
        const auto seed = hex_bytes(f[0]);
        const auto path = derivation_path::parse(f[1]).unwrap();
        const auto key = slip10_ed25519_key::from_seed(view(seed)).unwrap().derive(path).unwrap();
        EXPECT_EQ(to_hex(key.private_key()), f[2]) << f[0] << " " << f[1];
        EXPECT_EQ(to_hex(key.chain_code()), f[3]);
        EXPECT_EQ(to_hex(key.public_key().bytes), f[4]);
        ++rows;
    }
    EXPECT_EQ(rows, 300);
}

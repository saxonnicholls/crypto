//
//  bip32_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  BIP-32 against the SLIP-10 reference, ethers HDNodeWallet, bitcoinjs bip32 and the bip32 crate
//  (tests/fixtures/oracles/): xprv and xpub along BIP-44, 49, 84 and 86 paths and random ones.
//
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::hd;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::text_of;
using snicholls::crypto::test::view;

TEST(CryptoHdBip32Oracles, ExtendedKeysAgreeWithEveryOracle)
{
    int rows = 0;
    for (const auto& f : oracle_rows("bip32.txt")) {
        const auto seed = hex_bytes(f[0]);
        const auto path = derivation_path::parse(f[1]).unwrap();
        const auto key = extended_private_key::from_seed(view(seed)).unwrap().derive(path).unwrap();
        EXPECT_EQ(text_of(key.to_text()), f[2]) << f[0] << " " << f[1];
        EXPECT_EQ(text_of(key.public_key().to_text()), f[3]) << f[0] << " " << f[1];
        ++rows;
    }
    EXPECT_EQ(rows, 400);
}

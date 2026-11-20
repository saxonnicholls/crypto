//
//  bip32_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>
#include <type_traits>

using namespace snicholls::crypto::hd;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
std::string text_of(const extended_key_text& t) { return std::string(t.begin(), t.end()); }

extended_private_key master(const std::string& seed_hex)
{
    const auto seed = hex_bytes(seed_hex);
    return extended_private_key::from_seed(seed).unwrap();
}
} // namespace

static_assert(!std::is_copy_constructible_v<extended_private_key>);
static_assert(std::is_nothrow_move_constructible_v<extended_private_key>);
static_assert(std::is_trivially_copyable_v<extended_key_text>);   // so secure_wipe can clear an xprv's text

TEST(CryptoHdBip32, OfficialVectorsOneToFour)
{
    int chains = 0;
    for (const auto& f : read_fixture("hd/bip32.txt")) {
        if (f[0] != "valid")
            continue;
        const auto path = derivation_path::parse(f[3]).unwrap();
        const auto key = master(f[2]).derive(path).unwrap();
        EXPECT_EQ(text_of(key.to_text()), f[5]) << "vector " << f[1] << " " << f[3];
        EXPECT_EQ(text_of(key.public_key().to_text()), f[4]) << "vector " << f[1] << " " << f[3];
        // Both texts parse back to the same key
        const auto prv = extended_private_key::parse(std::string_view(f[5])).unwrap();
        EXPECT_EQ(text_of(prv.to_text()), f[5]);
        EXPECT_EQ(extended_public_key::parse(std::string_view(f[4])).unwrap(), key.public_key());
        ++chains;
    }
    EXPECT_EQ(chains, 17);
}

TEST(CryptoHdBip32, PublicDerivationAgreesWithPrivateForNonHardenedSteps)
{
    // Vector 1: m/0'/1/2'/2/1000000000; from m/0'/1/2' the last two steps are non-hardened
    const auto m = master("000102030405060708090a0b0c0d0e0f");
    const auto base = m.derive(derivation_path::parse("m/0'/1/2'").unwrap()).unwrap();
    const auto tail = derivation_path::parse("m/2/1000000000").unwrap();
    EXPECT_EQ(base.public_key().derive(tail).unwrap(), base.derive(tail).unwrap().public_key());
    // Vector 2's m/0 is non-hardened from the master
    const auto m2 = master("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
    EXPECT_EQ(m2.public_key().derive_child(0).unwrap(), m2.derive_child(0).unwrap().public_key());
    EXPECT_EQ(m2.public_key().derive_child(hardened(0)).unwrap_err(), errc::hardened_required);
}

TEST(CryptoHdBip32, VectorFiveInvalidKeysAreRefused)
{
    int refused = 0;
    for (const auto& f : read_fixture("hd/bip32.txt")) {
        if (f[0] != "invalid")
            continue;
        EXPECT_FALSE(extended_private_key::parse(std::string_view(f[2]))) << f[3];
        EXPECT_FALSE(extended_public_key::parse(std::string_view(f[2]))) << f[3];
        ++refused;
    }
    EXPECT_EQ(refused, 16);
}

TEST(CryptoHdBip32, Slip10Secp256k1VectorsAreBip32)
{
    int rows = 0;
    for (const auto& f : read_fixture("hd/slip10.txt")) {
        if (f[0] != "secp256k1")
            continue;
        const auto key = master(f[1]).derive(derivation_path::parse(f[2]).unwrap()).unwrap();
        EXPECT_EQ(to_hex(key.parent_fingerprint()), f[3]) << f[2];
        EXPECT_EQ(to_hex(key.chain_code()), f[4]) << f[2];
        EXPECT_EQ(to_hex(key.private_key().reveal()), f[5]) << f[2];
        EXPECT_EQ(to_hex(key.public_key().key.compressed()), f[6]) << f[2];
        ++rows;
    }
    EXPECT_EQ(rows, 12);
}

TEST(CryptoHdBip32, TrezorMnemonicSeedsGiveTheirMasterKeys)
{
    std::ifstream in(std::string(SNICHOLLS_CRYPTO_FIXTURE_DIR) + "/bip39/trezor_english.txt");
    int rows = 0;
    for (std::string line; std::getline(in, line);) {
        if (line.empty() || line[0] == '#')
            continue;
        std::vector<std::string> cols;
        std::stringstream ss(line);
        for (std::string c; std::getline(ss, c, '|');)
            cols.push_back(c);
        EXPECT_EQ(text_of(master(cols[2]).to_text()), cols[3]);
        ++rows;
    }
    EXPECT_EQ(rows, 24);
}

TEST(CryptoHdBip32, SeedLengthAndHeaderRules)
{
    EXPECT_EQ(extended_private_key::from_seed(hex_bytes("000102030405060708090a0b0c0d0e")).unwrap_err(), errc::invalid_seed);
    EXPECT_EQ(extended_private_key::from_seed(std::vector<std::uint8_t>(65)).unwrap_err(), errc::invalid_seed);
    EXPECT_TRUE(extended_private_key::from_seed(std::vector<std::uint8_t>(64)));
    const auto m = master("000102030405060708090a0b0c0d0e0f");
    EXPECT_EQ(m.depth(), 0);
    EXPECT_EQ(m.parent_fingerprint(), key_fingerprint{});
    const auto child = m.derive_child(hardened(0)).unwrap();
    EXPECT_EQ(child.depth(), 1);
    EXPECT_EQ(child.parent_fingerprint(), m.fingerprint());
    EXPECT_EQ(to_hex(m.fingerprint()), "3442193e");   // vector 1's master fingerprint
    EXPECT_EQ(child.child_number(), hardened(0));
    // Another network's versions: the same key under tprv / tpub, refused under the mainnet versions
    const auto t = text_of(child.to_text(bitcoin_testnet));
    EXPECT_EQ(t.substr(0, 4), "tprv");
    EXPECT_EQ(extended_private_key::parse(std::string_view(t)).unwrap_err(), errc::invalid_extended_key);
    EXPECT_EQ(text_of(extended_private_key::parse(std::string_view(t), bitcoin_testnet).unwrap().to_text(bitcoin_testnet)), t);
    EXPECT_EQ(text_of(child.public_key().to_text(bip84_mainnet)).substr(0, 4), "zpub");
    EXPECT_EQ(text_of(child.to_text(bip49_mainnet)).substr(0, 4), "yprv");
    // The 78 bytes round-trip too
    const auto bytes = child.serialize();
    EXPECT_EQ(text_of(extended_private_key::parse(bytes.reveal()).unwrap().to_text()), text_of(child.to_text()));
    EXPECT_EQ(child.clone().fingerprint(), child.fingerprint());
}

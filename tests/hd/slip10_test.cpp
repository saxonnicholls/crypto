//
//  slip10_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/hd/slip10.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <type_traits>

using namespace snicholls::crypto::hd;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

static_assert(!std::is_copy_constructible_v<slip10_ed25519_key>);

TEST(CryptoHdSlip10, Ed25519VectorsOneAndTwo)
{
    int rows = 0;
    for (const auto& f : read_fixture("hd/slip10.txt")) {
        if (f[0] != "ed25519")
            continue;
        const auto seed = hex_bytes(f[1]);
        const auto key = slip10_ed25519_key::from_seed(seed).unwrap().derive(derivation_path::parse(f[2]).unwrap()).unwrap();
        EXPECT_EQ(to_hex(key.parent_fingerprint()), f[3]) << f[2];
        EXPECT_EQ(to_hex(key.chain_code()), f[4]) << f[2];
        EXPECT_EQ(to_hex(key.private_key()), f[5]) << f[2];
        EXPECT_EQ("00" + to_hex(key.public_key().bytes), f[6]) << f[2];
        EXPECT_EQ(key.key_pair().public_key(), key.public_key());
        ++rows;
    }
    EXPECT_EQ(rows, 12);
}

TEST(CryptoHdSlip10, NonHardenedIndicesAreRefusedNeverHardened)
{
    const auto m = slip10_ed25519_key::from_seed(hex_bytes("000102030405060708090a0b0c0d0e0f")).unwrap();
    EXPECT_EQ(m.derive_child(0).unwrap_err(), errc::hardened_required);
    EXPECT_EQ(m.derive_child(hardened_bit - 1).unwrap_err(), errc::hardened_required);
    EXPECT_EQ(m.derive(derivation_path::parse("m/44'/501'/0'/0").unwrap()).unwrap_err(), errc::hardened_required);
    EXPECT_TRUE(m.derive(derivation_path::parse("m/44'/501'/0'/0'").unwrap()));
    EXPECT_EQ(m.depth(), 0);
    EXPECT_EQ(m.child_number(), 0u);
    const auto c = m.derive_child(hardened(7)).unwrap();
    EXPECT_EQ(c.depth(), 1);
    EXPECT_EQ(c.child_number(), hardened(7));
    EXPECT_EQ(c.parent_fingerprint(), m.fingerprint());
}

TEST(CryptoHdSlip10, SeedLengthIsSixteenToSixtyFourBytes)
{
    EXPECT_EQ(slip10_ed25519_key::from_seed(std::vector<std::uint8_t>(15)).unwrap_err(), errc::invalid_seed);
    EXPECT_EQ(slip10_ed25519_key::from_seed(std::vector<std::uint8_t>(65)).unwrap_err(), errc::invalid_seed);
    EXPECT_TRUE(slip10_ed25519_key::from_seed(std::vector<std::uint8_t>(16)));
}

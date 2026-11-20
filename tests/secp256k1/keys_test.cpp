//
//  keys_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/secp256k1/keys.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <type_traits>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::to_hex;

namespace {
constexpr auto one = hex<32>("0000000000000000000000000000000000000000000000000000000000000001");
constexpr auto n_minus_1 = hex<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
} // namespace

static_assert(!std::is_copy_constructible_v<private_key>);
static_assert(std::is_nothrow_move_constructible_v<private_key>);
// The public key of 1 is G, computed by the compiler
static_assert(private_key::from_bytes(one).unwrap().public_key().point() == generator());

TEST(CryptoSecp256k1Keys, PrivateKeyRangeIsOneToOrderMinusOne)
{
    EXPECT_EQ(private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000000")).unwrap_err(),
              errc::invalid_private_key);
    EXPECT_EQ(private_key::from_bytes(hex<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")).unwrap_err(),
              errc::invalid_private_key);
    EXPECT_EQ(private_key::from_bytes(hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).unwrap_err(),
              errc::invalid_private_key);
    EXPECT_TRUE(private_key::from_bytes(one));
    EXPECT_TRUE(private_key::from_bytes(n_minus_1));
    snicholls::crypto::secret_bytes<32> zero;
    EXPECT_EQ(private_key::from_secret(std::move(zero)).unwrap_err(), errc::invalid_private_key);
}

TEST(CryptoSecp256k1Keys, PublicKeysOfKnownPrivateKeys)
{
    EXPECT_EQ(to_hex(private_key::from_bytes(one).unwrap().public_key().compressed()),
              "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    EXPECT_EQ(to_hex(private_key::from_bytes(n_minus_1).unwrap().public_key().compressed()),
              "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    EXPECT_EQ(to_hex(private_key::from_bytes(one).unwrap().public_key().uncompressed()),
              "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    const auto k = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000012345678")).unwrap();
    EXPECT_EQ(to_hex(k.public_key().compressed()), "034cf7a9777c51afd98a605cc8dc54787686e632d716ebc6f186d40760845344c3");
    EXPECT_EQ(k.clone().reveal()[31], 0x78);
}

TEST(CryptoSecp256k1Keys, ParseRoundTripsBothEncodings)
{
    const auto pub = private_key::from_bytes(n_minus_1).unwrap().public_key();
    EXPECT_EQ(public_key::parse(pub.compressed()).unwrap(), pub);
    EXPECT_EQ(public_key::parse(pub.uncompressed()).unwrap(), pub);
    const auto xy = pub.xy();
    EXPECT_EQ(to_hex(std::span<const std::uint8_t>(xy).first(32)), to_hex(pub.point().x.to_bytes()));
}

TEST(CryptoSecp256k1Keys, ParseRejectsEveryMalformedEncoding)
{
    const auto g = private_key::from_bytes(one).unwrap().public_key();
    auto c = g.compressed();
    auto u = g.uncompressed();
    EXPECT_EQ(public_key::parse(std::span<const std::uint8_t>(c).first(32)).unwrap_err(), errc::invalid_length);
    EXPECT_EQ(public_key::parse({}).unwrap_err(), errc::invalid_length);
    for (const std::uint8_t prefix : {0x00, 0x01, 0x04, 0x05, 0x06, 0x07}) {
        c[0] = prefix;
        EXPECT_EQ(public_key::parse(c).unwrap_err(), errc::invalid_public_key) << int(prefix);
    }
    for (const std::uint8_t prefix : {0x00, 0x02, 0x03, 0x06, 0x07}) {   // hybrid forms are refused
        u[0] = prefix;
        EXPECT_EQ(public_key::parse(u).unwrap_err(), errc::invalid_public_key) << int(prefix);
    }
    // x = p, x = 5 (no point), y off the curve
    EXPECT_FALSE(public_key::parse(hex_bytes("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")));
    EXPECT_FALSE(public_key::parse(hex_bytes("020000000000000000000000000000000000000000000000000000000000000005")));
    u = g.uncompressed();
    u[64] ^= 1;
    EXPECT_EQ(public_key::parse(u).unwrap_err(), errc::invalid_public_key);
}

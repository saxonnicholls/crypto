//
//  ecdh_es_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/jose/ecdh_es.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <array>
#include <string_view>
#include <vector>

using namespace snicholls::crypto;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::to_hex;

namespace {

constexpr std::array<std::uint8_t, 5> alice{'A', 'l', 'i', 'c', 'e'};
constexpr std::array<std::uint8_t, 3> bob{'B', 'o', 'b'};

// RFC 7518 appendix C's Z (printed there as decimal bytes)
constexpr std::array<std::uint8_t, 32> rfc7518_z{158, 86,  217, 29,  129, 113, 53,  211, 114, 131, 66,  131, 191, 132, 38,  156,
                                                 251, 49,  110, 163, 218, 128, 106, 72,  246, 218, 167, 121, 140, 254, 144, 196};
// ... and its derived key, "VqqN6vgjbSBcIijNcacQGg"
constexpr std::array<std::uint8_t, 16> rfc7518_key{0x56, 0xaa, 0x8d, 0xea, 0xf8, 0x23, 0x6d, 0x20,
                                                   0x5c, 0x22, 0x28, 0xcd, 0x71, 0xa7, 0x10, 0x1a};

constexpr bool rfc7518_at_compile_time()
{
    const auto k = jose::ecdh_es_kdf<16>(rfc7518_z, "A128GCM", alice, bob);
    for (std::size_t i = 0; i < 16; ++i)
        if (k.reveal()[i] != rfc7518_key[i])
            return false;
    return true;
}
static_assert(rfc7518_at_compile_time(), "RFC 7518 appendix C, in a constant expression");

p256::public_key p256_key(std::string_view h)
{
    const auto b = hex_bytes(std::string(h));
    return p256::public_key::parse(std::span<const std::uint8_t>(b.data(), b.size())).unwrap();
}

} // namespace

TEST(CryptoJoseEcdhEs, Rfc7518AppendixCFromBothSides)
{
    const auto alice_key = p256::private_key::from_bytes(hex<32>("d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a")).unwrap();
    const auto bob_key = p256::private_key::from_bytes(hex<32>("5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc")).unwrap();
    // the sender (Alice, ephemeral) with the recipient's key, and the recipient (Bob) with the epk
    const auto k1 = jose::ecdh_es_p256<16>(alice_key, bob_key.public_key(), "A128GCM", alice, bob).unwrap();
    const auto k2 = jose::ecdh_es_p256<16>(bob_key, alice_key.public_key(), "A128GCM", alice, bob).unwrap();
    EXPECT_EQ(to_hex(k1.reveal()), "56aa8deaf8236d205c2228cd71a7101a");
    EXPECT_TRUE(k1 == k2);
}

TEST(CryptoJoseEcdhEs, KdfAloneMatchesRfc7518)
{
    const auto k = jose::ecdh_es_kdf<16>(rfc7518_z, "A128GCM", alice, bob);
    EXPECT_EQ(to_hex(k.reveal()), "56aa8deaf8236d205c2228cd71a7101a");
}

// The key length and every field are in the OtherInfo: changing any of them changes the whole key
TEST(CryptoJoseEcdhEs, EveryFieldIsBound)
{
    const auto base = jose::ecdh_es_kdf<32>(rfc7518_z, "A256GCM", alice, bob);
    const auto as16 = jose::ecdh_es_kdf<16>(rfc7518_z, "A256GCM", alice, bob);
    EXPECT_NE(to_hex(base.reveal()).substr(0, 32), to_hex(as16.reveal()));
    EXPECT_FALSE(base == jose::ecdh_es_kdf<32>(rfc7518_z, "ECDH-ES+A256KW", alice, bob));
    EXPECT_FALSE(base == jose::ecdh_es_kdf<32>(rfc7518_z, "A256GCM", bob, alice));
    EXPECT_FALSE(base == jose::ecdh_es_kdf<32>(rfc7518_z, "A256GCM", alice, {}));
    EXPECT_FALSE(base == jose::ecdh_es_kdf<32>(rfc7518_z, "A256GCM"));
    auto z = rfc7518_z;
    z[31] ^= 1;
    EXPECT_FALSE(base == jose::ecdh_es_kdf<32>(z, "A256GCM", alice, bob));
}

// A 64-byte key (A256CBC-HS512) takes two SHA-256 blocks: the second is H(2 || Z || OtherInfo)
TEST(CryptoJoseEcdhEs, SixtyFourBytesTakeTwoBlocks)
{
    const auto k64 = jose::ecdh_es_kdf<64>(rfc7518_z, "A256CBC-HS512");
    const auto h = to_hex(k64.reveal());
    EXPECT_NE(h.substr(0, 64), h.substr(64));
}

// RFC 8037 appendix A.6: X25519 with RFC 7748's keys; the shared secret is RFC 7748 section 6.1's
TEST(CryptoJoseEcdhEs, Rfc8037AppendixA6)
{
    const secret_bytes<32> ephemeral(hex<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const secret_bytes<32> recipient(hex<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    const x25519::public_key bob_public{hex<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")};
    EXPECT_EQ(x25519::public_key_from_secret(recipient), bob_public);
    const auto z = hex<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    const auto expected = jose::ecdh_es_kdf<16>(z, "ECDH-ES+A128KW");
    const auto sender = jose::ecdh_es_x25519<16>(ephemeral, bob_public, "ECDH-ES+A128KW").unwrap();
    const auto receiver = jose::ecdh_es_x25519<16>(recipient, x25519::public_key_from_secret(ephemeral), "ECDH-ES+A128KW").unwrap();
    EXPECT_TRUE(sender == expected);
    EXPECT_TRUE(receiver == expected);
}

TEST(CryptoJoseEcdhEs, RefusesASmallOrderX25519Key)
{
    const secret_bytes<32> s(hex<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const x25519::public_key zero{};
    EXPECT_EQ(jose::ecdh_es_x25519<32>(s, zero, "A256GCM").unwrap_err(), errc::small_order);
    const x25519::public_key one{{1}};
    EXPECT_EQ(jose::ecdh_es_x25519<32>(s, one, "A256GCM").unwrap_err(), errc::small_order);
}

TEST(CryptoJoseEcdhEs, RefusesAP256PointOffTheCurve)
{
    const auto key = p256::private_key::from_bytes(hex<32>("5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc")).unwrap();
    auto p = p256_key("04808d060082c176eed3e776a4ac598cc8672c1779f974eecc9b03411ca5b9495d"
                      "48b5bfc527dfce53d6ac7115237d031ccff87a0570b77350a9e503ee7305a69b")
                 .point();
    p.x = p.x + p256::field_element::from_u64(1);
    EXPECT_EQ(jose::ecdh_es_p256<32>(key, p256::public_key(p), "A256GCM").unwrap_err(), errc::invalid_public_key);
}

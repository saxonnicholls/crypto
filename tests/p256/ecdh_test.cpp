//
//  ecdh_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/p256/ecdh.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <vector>

using namespace snicholls::crypto::p256;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {

// RFC 7518 appendix C: Alice's ephemeral key and Bob's static key (the JWKs' x, y and d, base64url-decoded)
constexpr auto alice_d = "d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a";
constexpr auto alice_xy = "04808d060082c176eed3e776a4ac598cc8672c1779f974eecc9b03411ca5b9495d"
                          "48b5bfc527dfce53d6ac7115237d031ccff87a0570b77350a9e503ee7305a69b";
constexpr auto bob_d = "5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc";
constexpr auto bob_xy = "04c1e349cb61ec70248ce801034c3834e1b88ebe1161cb25af38741f785fcfc4c4"
                        "7bc96708ef80952b53f8d2555fe72b841ed04588628b1d378a594939500ec9c9";

public_key parse(const char* h)
{
    const auto b = hex_bytes(h);
    return public_key::parse(std::span<const std::uint8_t>(b.data(), b.size())).unwrap();
}

private_key key(const char* h) { return private_key::from_bytes(hex<32>(h)).unwrap(); }

} // namespace

TEST(CryptoP256Ecdh, Rfc7518AppendixCBothSidesAgree)
{
    const auto alice = key(alice_d), bob = key(bob_d);
    EXPECT_EQ(alice.public_key(), parse(alice_xy));
    EXPECT_EQ(bob.public_key(), parse(bob_xy));
    const auto z1 = shared_secret(alice, parse(bob_xy)).unwrap();
    const auto z2 = shared_secret(bob, parse(alice_xy)).unwrap();
    EXPECT_TRUE(z1 == z2);
    // RFC 7518 appendix C prints Z as decimal bytes: 158, 86, 217, 29, ..., 144, 196
    EXPECT_EQ(to_hex(z1.reveal()), "9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");
}

TEST(CryptoP256Ecdh, RefusesAPointOffTheCurve)
{
    // a public_key built from an unchecked point: y + 1 is not on the curve
    auto p = parse(bob_xy).point();
    p.y = p.y + field_element::from_u64(1);
    ASSERT_FALSE(p.is_on_curve());
    EXPECT_EQ(shared_secret(key(alice_d), public_key(p)).unwrap_err(), errc::invalid_public_key);
}

// Every Wycheproof ecdh_secp256r1_ecpoint case: "valid" and "acceptable" (a compressed point, which SEC1 parsing
// accepts) agree byte for byte; every "invalid" one (a point off the curve, on another curve, or badly encoded) is
// refused by public_key::parse, before any arithmetic
TEST(CryptoP256EcdhWycheproof, EcpointCases)
{
    int agreed = 0, refused = 0;
    for (const auto& f : read_fixture("wycheproof/ecdh_p256.txt")) {
        ASSERT_EQ(f.size(), 5u);
        const auto pub = f[2] == "-" ? std::vector<std::uint8_t>{} : hex_bytes(f[2]);
        const auto peer = public_key::parse(std::span<const std::uint8_t>(pub.data(), pub.size()));
        const auto d = private_key::from_bytes(hex<32>(f[3]));
        ASSERT_TRUE(d) << "tcId " << f[0];
        if (f[1] == "invalid") {
            EXPECT_TRUE(!peer || !shared_secret(*d, *peer)) << "tcId " << f[0];
            ++refused;
            continue;
        }
        ASSERT_TRUE(peer) << "tcId " << f[0];
        const auto z = shared_secret(*d, *peer);
        ASSERT_TRUE(z) << "tcId " << f[0];
        EXPECT_EQ(to_hex(z->reveal()), f[4]) << "tcId " << f[0];
        ++agreed;
    }
    EXPECT_EQ(agreed, 331);
    EXPECT_EQ(refused, 24);
}

//
//  ecdh_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/p384/ecdh.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <vector>

using namespace snicholls::crypto::p384;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
private_key key(const char* h) { return private_key::from_bytes(hex<48>(h)).unwrap(); }
constexpr auto a_d = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";
constexpr auto b_d = "0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
} // namespace

TEST(CryptoP384Ecdh, BothSidesAgree)
{
    const auto a = key(a_d), b = key(b_d);
    const auto z1 = shared_secret(a, b.public_key()).unwrap();
    const auto z2 = shared_secret(b, a.public_key()).unwrap();
    EXPECT_TRUE(z1 == z2);
    EXPECT_EQ(z1.reveal().size(), 48u);
}

TEST(CryptoP384Ecdh, RefusesAPointOffTheCurve)
{
    auto p = key(b_d).public_key().point();
    p.y = p.y + field_element::from_u64(1);
    ASSERT_FALSE(p.is_on_curve());
    EXPECT_EQ(shared_secret(key(a_d), public_key(p)).unwrap_err(), errc::invalid_public_key);
}

// Every Wycheproof ecdh_secp384r1_ecpoint case: "valid" and "acceptable" (a compressed point, which SEC1 parsing
// accepts) agree byte for byte; every "invalid" one (off the curve, on another curve, badly encoded) is refused
TEST(CryptoP384EcdhWycheproof, EcpointCases)
{
    int agreed = 0, refused = 0;
    for (const auto& f : read_fixture("wycheproof/ecdh_p384.txt")) {
        ASSERT_EQ(f.size(), 5u);
        const auto pub = hex_bytes(f[2]);
        const auto peer = public_key::parse(std::span<const std::uint8_t>(pub.data(), pub.size()));
        const auto d = private_key::from_bytes(hex<48>(f[3]));
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
    EXPECT_GT(agreed, 700);
    EXPECT_GT(refused, 10);
    EXPECT_EQ(agreed + refused, 790);
}

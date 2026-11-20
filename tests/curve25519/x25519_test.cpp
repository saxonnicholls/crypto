//
//  x25519_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <utility>

namespace x25519 = snicholls::crypto::x25519;
using snicholls::crypto::errc;
using snicholls::crypto::secret_bytes;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

// RFC 7748 section 5.2's first vector, computed by the compiler
static_assert(x25519::scalar_mult(hex<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                                  hex<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")) ==
              hex<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

namespace {
// RFC 7748 section 5.2: k = u = 9, then repeatedly (k, u) = (X25519(k, u), k)
std::string iterate(int n)
{
    std::array<std::uint8_t, 32> k{9}, u{9};
    for (int i = 0; i < n; ++i) {
        const auto r = x25519::scalar_mult(k, u);
        u = k;
        k = r;
    }
    return to_hex(k);
}
} // namespace

TEST(CryptoX25519, Rfc7748Section52Vectors)
{
    EXPECT_EQ(to_hex(x25519::scalar_mult(hex<32>("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                                         hex<32>("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))),
              "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}

TEST(CryptoX25519, Rfc7748Section52IteratedOnceAndAThousandTimes)
{
    EXPECT_EQ(iterate(1), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    EXPECT_EQ(iterate(1000), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}

// A million ladders: minutes in a Debug build. Run with --gtest_also_run_disabled_tests.
TEST(CryptoX25519, DISABLED_Rfc7748Section52IteratedAMillionTimes)
{
    EXPECT_EQ(iterate(1000000), "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
}

TEST(CryptoX25519, Rfc7748Section61DiffieHellman)
{
    const secret_bytes<32> alice(hex<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const secret_bytes<32> bob(hex<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    const auto alice_public = x25519::public_key_from_secret(alice);
    const auto bob_public = x25519::public_key_from_secret(bob);
    EXPECT_EQ(to_hex(alice_public.bytes), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    EXPECT_EQ(to_hex(bob_public.bytes), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    auto k1 = x25519::shared_secret(alice, bob_public);
    auto k2 = x25519::shared_secret(bob, alice_public);
    ASSERT_TRUE(k1.is_ok() && k2.is_ok());
    EXPECT_EQ(to_hex(k1.unwrap().reveal()), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    EXPECT_TRUE(k1.unwrap() == k2.unwrap());
}

TEST(CryptoX25519, Wycheproof)
{
    const auto rows = read_fixture("wycheproof/x25519.txt");
    ASSERT_EQ(rows.size(), 518u);
    int small_order = 0;
    for (const auto& r : rows) {
        const secret_bytes<32> secret(hex<32>(r[2]));
        const x25519::public_key peer{hex<32>(r[3])};
        // Every case, valid or acceptable, has a defined X25519 output, which scalar_mult must reproduce
        EXPECT_EQ(to_hex(x25519::scalar_mult(secret.reveal(), peer.bytes)), r[4]) << "tcId " << r[0];
        auto shared = x25519::shared_secret(secret, peer);
        if (r[4] == std::string(64, '0')) {
            ASSERT_FALSE(shared.is_ok()) << "tcId " << r[0];
            EXPECT_EQ(shared.unwrap_err(), errc::small_order);
            ++small_order;
        } else {
            ASSERT_TRUE(shared.is_ok()) << "tcId " << r[0];
            EXPECT_EQ(to_hex(shared.unwrap().reveal()), r[4]) << "tcId " << r[0];
        }
        EXPECT_NE(r[1], "invalid") << "x25519_test.json has no invalid cases: tcId " << r[0];
    }
    std::printf("wycheproof x25519: 518 outputs reproduced, %d all-zero refused as small_order\n", small_order);
}

TEST(CryptoX25519, ClampingAndTheTopBitOfU)
{
    const auto c = x25519::clamp(hex<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    EXPECT_EQ(c[0], 0xf8);
    EXPECT_EQ(c[31], 0x7f);
    // Clamped and unclamped secrets give the same result; so do u with and without bit 255
    const auto k = hex<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto u = hex<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    const auto expected = x25519::scalar_mult(k, u);
    EXPECT_EQ(x25519::scalar_mult(x25519::clamp(k), u), expected);
    u[31] ^= 0x80;
    EXPECT_EQ(x25519::scalar_mult(k, u), expected);
}

TEST(CryptoX25519, SmallOrderPeerIsRefused)
{
    const secret_bytes<32> secret(hex<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const x25519::public_key zero{};   // u = 0, order 4 on the curve
    EXPECT_EQ(x25519::shared_secret(secret, zero).unwrap_err(), errc::small_order);
    const x25519::public_key one{hex<32>("0100000000000000000000000000000000000000000000000000000000000000")};
    EXPECT_EQ(x25519::shared_secret(secret, one).unwrap_err(), errc::small_order);
}

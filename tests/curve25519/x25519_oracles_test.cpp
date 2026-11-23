//
//  x25519_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  X25519 against OpenSSL, libsodium, x25519-dalek and noble (tests/fixtures/oracles/): random scalars and
//  u-coordinates, the small-order u values, u at or above p, and bit 255 set.
//
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::x25519;
using snicholls::crypto::secret_bytes;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;

TEST(CryptoX25519Oracles, SharedSecretsAgreeAndTheAllZeroResultIsRefused)
{
    int agreed = 0, refused = 0;
    for (const auto& f : oracle_rows("x25519.txt")) {
        const secret_bytes<32> k(hex<32>(f[0]));
        const public_key u{hex<32>(f[1])};
        const auto out = shared_secret(k, u);
        if (f[2].empty()) {
            EXPECT_FALSE(out) << f[1];
            ++refused;
        } else {
            EXPECT_TRUE(out) << f[1];
            if (!out)
                continue;
            EXPECT_EQ(to_hex(out->reveal()), f[2]) << f[0] << " " << f[1];
            ++agreed;
        }
    }
    EXPECT_GE(agreed, 600);
    EXPECT_GE(refused, 20);
}

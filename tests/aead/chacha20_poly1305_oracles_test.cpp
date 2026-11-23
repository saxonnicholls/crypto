//
//  chacha20_poly1305_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  ChaCha20-Poly1305 against OpenSSL (through Python cryptography), libsodium (PyNaCl) and Node's crypto, and
//  XChaCha20-Poly1305 against libsodium (tests/fixtures/oracles/): seal byte for byte, and open of the sealed and of a
//  tampered message.
//
#include <snicholls/crypto/aead/chacha20_poly1305.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace snicholls::crypto::aead;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

namespace {
void replay(const std::string& name, bool x)
{
    int rows = 0, opened = 0;
    for (const auto& f : oracle_rows(name)) {
        const auto k = hex_bytes(f[0]), n = hex_bytes(f[1]), ad = hex_bytes(f[2]), m = hex_bytes(f[3]), ct = hex_bytes(f[4]),
                   tg = hex_bytes(f[5]);
        const std::span<const std::uint8_t, 32> key(k.data(), 32);
        std::vector<std::uint8_t> out(m.size());
        const auto t = x ? xchacha20_poly1305_seal(key, std::span<const std::uint8_t, 24>(n.data(), 24), view(ad), view(m), out)
                         : chacha20_poly1305_seal(key, std::span<const std::uint8_t, 12>(n.data(), 12), view(ad), view(m), out);
        EXPECT_EQ(out, ct) << name << " row " << rows;
        EXPECT_EQ(to_hex(t.unwrap()), f[5]);
        const auto colon = f[6].find(':');
        const auto tct = hex_bytes(f[6].substr(0, colon) == "-" ? "" : f[6].substr(0, colon)), ttag = hex_bytes(f[6].substr(colon + 1));
        std::vector<std::uint8_t> back(tct.size());
        const bool ok = static_cast<bool>(
            x ? xchacha20_poly1305_open(key, std::span<const std::uint8_t, 24>(n.data(), 24), view(ad), view(tct),
                                        std::span<const std::uint8_t, 16>(ttag.data(), 16), back)
              : chacha20_poly1305_open(key, std::span<const std::uint8_t, 12>(n.data(), 12), view(ad), view(tct),
                                       std::span<const std::uint8_t, 16>(ttag.data(), 16), back));
        EXPECT_EQ(ok, f[7] == "1") << name << " row " << rows;
        if (ok) {
            EXPECT_EQ(back, m);
        }
        opened += ok;
        ++rows;
    }
    EXPECT_EQ(rows, 300);
    EXPECT_EQ(opened, 100);   // a third as sealed, a third with the ciphertext changed, a third with the tag
}
} // namespace

TEST(CryptoAeadOracles, ChaCha20Poly1305) { replay("chacha20_poly1305.txt", false); }

TEST(CryptoAeadOracles, XChaCha20Poly1305) { replay("xchacha20_poly1305.txt", true); }

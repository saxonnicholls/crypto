//
//  chacha20_poly1305_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/aead/chacha20_poly1305.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

using namespace snicholls::crypto::aead;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
constexpr std::string_view sunscreen =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
std::vector<std::uint8_t> text(std::string_view s) { return {s.begin(), s.end()}; }
std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) { return {v.data(), v.size()}; }
constexpr auto key_80 = hex<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
constexpr auto aad_rfc = hex<12>("50515253c0c1c2c3c4c5c6c7");
} // namespace

// RFC 8439 section 2.5.2 (Poly1305) and 2.3.2 (the block function), at compile time
static_assert([] {
    snicholls::crypto::detail::poly1305 mac(hex<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"));
    constexpr std::string_view m = "Cryptographic Forum Research Group";
    std::array<std::uint8_t, 34> b{};
    for (std::size_t i = 0; i < m.size(); ++i)
        b[i] = static_cast<std::uint8_t>(m[i]);
    mac.update(b);
    return mac.finish() == hex<16>("a8061dc1305136c6c22b8baf0c0127a9");
}());
static_assert(snicholls::crypto::detail::chacha20_block(hex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), 1,
                                                        hex<12>("000000090000004a00000000"))[0] == 0x10);

TEST(CryptoAeadChaCha20Poly1305, Rfc8439Section282)
{
    const auto pt = text(sunscreen);
    std::vector<std::uint8_t> ct(pt.size());
    const auto t = chacha20_poly1305_seal(key_80, hex<12>("070000004041424344454647"), aad_rfc, view(pt), ct).unwrap();
    EXPECT_EQ(to_hex(view(ct)), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a"
                                "71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4"
                                "def08e4b7a9de576d26586cec64b6116");
    EXPECT_EQ(to_hex(t), "1ae10b594f09e26a7e902ecbd0600691");
    std::vector<std::uint8_t> back(ct.size());
    EXPECT_TRUE(chacha20_poly1305_open(key_80, hex<12>("070000004041424344454647"), aad_rfc, view(ct), t, back));
    EXPECT_EQ(back, pt);
    // a changed byte anywhere: refused, and nothing released
    auto bad = ct;
    bad[5] ^= 1;
    std::vector<std::uint8_t> out(ct.size(), 0xaa);
    EXPECT_EQ(chacha20_poly1305_open(key_80, hex<12>("070000004041424344454647"), aad_rfc, view(bad), t, out).unwrap_err(),
              errc::authentication_failed);
    EXPECT_EQ(out, std::vector<std::uint8_t>(ct.size(), 0));
    EXPECT_FALSE(chacha20_poly1305_open(key_80, hex<12>("070000004041424344454647"), {}, view(ct), t, out));
}

TEST(CryptoAeadXChaCha20Poly1305, DraftVectorAndInPlace)
{
    auto buf = text(sunscreen);
    const auto nonce = hex<24>("404142434445464748494a4b4c4d4e4f5051525354555657");
    const auto t = xchacha20_poly1305_seal(key_80, nonce, aad_rfc, view(buf), buf).unwrap();   // in place
    EXPECT_EQ(to_hex(view(buf)).substr(0, 32), "bd6d179d3e83d43b9576579493c0e939");
    EXPECT_EQ(to_hex(t), "c0875924c1c7987947deafd8780acf49");
    EXPECT_TRUE(xchacha20_poly1305_open(key_80, nonce, aad_rfc, view(buf), t, buf));
    EXPECT_EQ(buf, text(sunscreen));
}

TEST(CryptoAeadChaCha20Poly1305, LengthsMustMatch)
{
    const auto pt = text("abc");
    std::vector<std::uint8_t> shorter(2);
    EXPECT_EQ(chacha20_poly1305_seal(key_80, hex<12>("000000000000000000000000"), {}, view(pt), shorter).unwrap_err(),
              errc::invalid_length);
    std::vector<std::uint8_t> empty;
    EXPECT_TRUE(chacha20_poly1305_seal(key_80, hex<12>("000000000000000000000000"), {}, {}, empty));
}

namespace {
// Every Wycheproof case: a nonce of the scheme's length is sealed and opened; any other length cannot be passed to
// this API at all (the nonce is a fixed-size span), and Wycheproof marks every such case invalid
void wycheproof(const std::string& name, std::size_t nonce_len, int& valid, int& invalid, int& unrepresentable)
{
    for (const auto& f : read_fixture("wycheproof/" + name)) {
        const auto iv = hex_bytes(f[2]), key = hex_bytes(f[3]), aad = hex_bytes(f[4]), msg = hex_bytes(f[5]), ct = hex_bytes(f[6]),
                   tg = hex_bytes(f[7]);
        if (iv.size() != nonce_len || tg.size() != 16) {
            EXPECT_EQ(f[1], "invalid") << name << " tcId " << f[0];
            ++unrepresentable;
            continue;
        }
        const std::span<const std::uint8_t, 32> k(key.data(), 32);
        std::vector<std::uint8_t> out(ct.size());
        bool opened = false;
        if (nonce_len == 12)
            opened = static_cast<bool>(chacha20_poly1305_open(k, std::span<const std::uint8_t, 12>(iv.data(), 12), view(aad), view(ct),
                                                              std::span<const std::uint8_t, 16>(tg.data(), 16), out));
        else
            opened = static_cast<bool>(xchacha20_poly1305_open(k, std::span<const std::uint8_t, 24>(iv.data(), 24), view(aad), view(ct),
                                                               std::span<const std::uint8_t, 16>(tg.data(), 16), out));
        EXPECT_EQ(opened, f[1] == "valid") << name << " tcId " << f[0];
        if (f[1] == "valid") {
            EXPECT_EQ(out, msg) << name << " tcId " << f[0];
            std::vector<std::uint8_t> sealed(msg.size());
            const auto t = nonce_len == 12 ? chacha20_poly1305_seal(k, std::span<const std::uint8_t, 12>(iv.data(), 12), view(aad), view(msg), sealed)
                                           : xchacha20_poly1305_seal(k, std::span<const std::uint8_t, 24>(iv.data(), 24), view(aad), view(msg), sealed);
            EXPECT_EQ(sealed, ct) << name << " tcId " << f[0];
            EXPECT_EQ(to_hex(t.unwrap()), f[7]) << name << " tcId " << f[0];
            ++valid;
        } else {
            ++invalid;
        }
    }
}
} // namespace

TEST(CryptoAeadWycheproof, ChaCha20Poly1305AndXChaCha20Poly1305)
{
    int v = 0, i = 0, u = 0;
    wycheproof("chacha20_poly1305.txt", 12, v, i, u);
    EXPECT_EQ(v + i + u, 325);
    int xv = 0, xi = 0, xu = 0;
    wycheproof("xchacha20_poly1305.txt", 24, xv, xi, xu);
    EXPECT_EQ(xv + xi + xu, 315);
    EXPECT_GT(v, 100);
    EXPECT_GT(xv, 100);
}

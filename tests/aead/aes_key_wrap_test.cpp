//
//  aes_key_wrap_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/aead/aes_key_wrap.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <vector>

using namespace snicholls::crypto::aead;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) { return {v.data(), v.size()}; }
}

TEST(CryptoAeadKeyWrap, Rfc3394Section46)
{
    const auto kek = hex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto key = hex_bytes("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
    std::vector<std::uint8_t> wrapped(key.size() + 8);
    ASSERT_TRUE(aes256_key_wrap(kek, view(key), wrapped));
    EXPECT_EQ(to_hex(view(wrapped)), "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");
    std::vector<std::uint8_t> back(key.size());
    EXPECT_TRUE(aes256_key_unwrap(kek, view(wrapped), back));
    EXPECT_EQ(back, key);
    wrapped[3] ^= 1;
    EXPECT_EQ(aes256_key_unwrap(kek, view(wrapped), back).unwrap_err(), errc::authentication_failed);
    EXPECT_EQ(back, std::vector<std::uint8_t>(key.size(), 0));
    std::vector<std::uint8_t> one_block(8), out(16);
    EXPECT_EQ(aes256_key_wrap(kek, view(one_block), out).unwrap_err(), errc::invalid_length);   // RFC 3394: n >= 2
}

// Every Wycheproof case with a 256-bit key-encryption key. The only "acceptable" case (tcId 109) wraps an 8-byte
// key; RFC 3394 needs at least two blocks, so this library refuses it, as its documentation states
TEST(CryptoAeadWycheproof, Aes256KeyWrap)
{
    int valid = 0, refused = 0;
    for (const auto& f : read_fixture("wycheproof/aes256_wrap.txt")) {
        const auto kek = hex_bytes(f[2]), msg = hex_bytes(f[3]), ct = hex_bytes(f[4]);
        const std::span<const std::uint8_t, 32> k(kek.data(), 32);
        std::vector<std::uint8_t> out(ct.size() >= 8 ? ct.size() - 8 : 0);
        const bool ok = static_cast<bool>(aes256_key_unwrap(k, view(ct), out));
        EXPECT_EQ(ok, f[1] == "valid") << "tcId " << f[0];
        if (ok) {
            EXPECT_EQ(out, msg) << "tcId " << f[0];
            std::vector<std::uint8_t> again(msg.size() + 8);
            EXPECT_TRUE(aes256_key_wrap(k, view(msg), again));
            EXPECT_EQ(again, ct) << "tcId " << f[0];
            ++valid;
        } else {
            ++refused;
        }
    }
    EXPECT_EQ(valid + refused, 68);
    EXPECT_GT(valid, 10);
}

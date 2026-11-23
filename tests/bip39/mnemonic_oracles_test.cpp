//
//  mnemonic_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  BIP-39 against python-mnemonic (Trezor's reference), ethers, @scure/bip39 and the bip39 crate
//  (tests/fixtures/oracles/): words both ways, seeds with ASCII passphrases, and text that is not canonical.
//
#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>

namespace b = snicholls::crypto::bip39;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

namespace {
std::string text(const b::mnemonic& m)
{
    std::array<char, b::max_text_length> buf{};
    return std::string(buf.data(), m.to_text(buf));
}

std::string entropy_hex(const b::mnemonic& m)
{
    const auto e = b::to_entropy(m);
    return to_hex(e.reveal().first(m.entropy_size()));
}
} // namespace

TEST(CryptoBip39Oracles, WordsAndSeedsAgreeWithEveryOracle)
{
    int rows = 0;
    for (const auto& f : oracle_rows("bip39.txt")) {
        const auto e = hex_bytes(f[0]);
        std::string words = f[1];
        std::replace(words.begin(), words.end(), '+', ' ');
        const auto pass_bytes = hex_bytes(f[2]);
        const std::string pass(pass_bytes.begin(), pass_bytes.end());
        const auto m = b::from_entropy(view(e)).unwrap();
        EXPECT_EQ(text(m), words);
        EXPECT_EQ(entropy_hex(b::parse(words).unwrap()), f[0]);
        EXPECT_EQ(to_hex(b::to_seed(m, pass).unwrap().reveal()), f[3]) << words;
        ++rows;
    }
    EXPECT_EQ(rows, 300);
}

TEST(CryptoBip39Oracles, OnlyCanonicalTextIsRead)
{
    int read = 0, refused = 0;
    for (const auto& f : oracle_rows("bip39_text.txt")) {
        const auto raw = hex_bytes(f[1]);
        const std::string t(raw.begin(), raw.end());
        const auto m = b::parse(t);
        if (f[2].empty()) {
            EXPECT_FALSE(m) << f[0] << ": '" << t << "'";
            ++refused;
        } else {
            EXPECT_TRUE(m) << f[0] << ": '" << t << "'";
            if (!m)
                continue;
            EXPECT_EQ(entropy_hex(*m), f[2]);
            ++read;
        }
    }
    EXPECT_EQ(read, 60);
    EXPECT_EQ(refused, 540);
}

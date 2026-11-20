//
//  mnemonic_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// Trezor's BIP-39 reference vectors (tests/fixtures/bip39/trezor_english.txt): entropy to words, words to
// entropy, and the seed with the passphrase "TREZOR"; then every error and the canonical-text rules.
#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace b = snicholls::crypto::bip39;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::to_hex;

namespace {

struct vector_row {
    std::string entropy, words, seed, xprv;
};

std::vector<vector_row> trezor_vectors()
{
    std::ifstream in(std::string(SNICHOLLS_CRYPTO_FIXTURE_DIR) + "/bip39/trezor_english.txt");
    std::vector<vector_row> rows;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        std::stringstream s(line);
        vector_row r;
        std::getline(s, r.entropy, '|');
        std::getline(s, r.words, '|');
        std::getline(s, r.seed, '|');
        std::getline(s, r.xprv, '|');
        rows.push_back(r);
    }
    return rows;
}

std::string text_of(const b::mnemonic& m)
{
    std::array<char, b::max_text_length> buf{};
    return std::string(buf.data(), m.to_text(buf));
}

} // namespace

static_assert(!std::is_copy_constructible_v<b::mnemonic>);
static_assert(std::is_nothrow_move_constructible_v<b::mnemonic>);
static_assert(b::max_text_length == 215);

// Entropy to words and back, evaluated by the compiler
static_assert([] {
    constexpr std::array<std::uint8_t, 16> zero{};
    auto m = b::from_entropy(zero);
    return m && m->size() == 12 && m->index(0) == 0 && m->index(11) == 3 && b::to_entropy(*m).reveal()[0] == 0;
}());
static_assert([] {
    auto m = b::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    return m && m->index(11) == 3;
}());

TEST(CryptoBip39Mnemonic, TrezorVectorsHaveTwentyFourRows)
{
    EXPECT_EQ(trezor_vectors().size(), 24u);
}

TEST(CryptoBip39Mnemonic, TrezorEntropyToWords)
{
    for (const auto& v : trezor_vectors()) {
        const auto e = hex_bytes(v.entropy);
        const auto m = b::from_entropy(e);
        ASSERT_TRUE(m) << v.entropy;
        EXPECT_EQ(text_of(*m), v.words);
        EXPECT_EQ(m->size(), e.size() * 3 / 4);
    }
}

TEST(CryptoBip39Mnemonic, TrezorWordsToEntropy)
{
    for (const auto& v : trezor_vectors()) {
        const auto m = b::parse(v.words);
        ASSERT_TRUE(m) << v.words;
        const auto e = b::to_entropy(*m);
        EXPECT_EQ(to_hex(e.reveal().first(m->entropy_size())), v.entropy);
        EXPECT_EQ(*m, *b::from_entropy(hex_bytes(v.entropy)));
    }
}

TEST(CryptoBip39Mnemonic, TrezorSeedsWithPassphraseTrezor)
{
    for (const auto& v : trezor_vectors()) {
        const auto seed = b::to_seed(*b::parse(v.words), "TREZOR");
        ASSERT_TRUE(seed);
        EXPECT_EQ(to_hex(seed->reveal()), v.seed) << v.words;
    }
}

TEST(CryptoBip39Mnemonic, EmptyPassphraseSeed)
{
    // The all-"abandon ... about" mnemonic without a passphrase, as published by every BIP-39 implementation
    const auto seed = b::to_seed(*b::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
    ASSERT_TRUE(seed);
    EXPECT_EQ(to_hex(seed->reveal()),
              "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
}

TEST(CryptoBip39Mnemonic, EntropyOfTheWrongLengthIsRefused)
{
    for (const std::size_t n : {0u, 12u, 15u, 17u, 33u, 36u}) {
        const std::vector<std::uint8_t> e(n, 1);
        const auto m = b::from_entropy(e);
        ASSERT_FALSE(m) << n;
        EXPECT_EQ(m.unwrap_err(), errc::invalid_mnemonic_length);
    }
}

TEST(CryptoBip39Mnemonic, BadChecksumIsRefused)
{
    // "about" carries the checksum of twelve zero words; "abandon" in its place does not
    const auto m = b::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
    ASSERT_FALSE(m);
    EXPECT_EQ(m.unwrap_err(), errc::invalid_checksum);
}

TEST(CryptoBip39Mnemonic, UnknownWordsAreRefused)
{
    for (const char* t : {"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abouts",
                          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abou",
                          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon aboutaboutabout"}) {
        const auto m = b::parse(t);
        ASSERT_FALSE(m) << t;
        EXPECT_EQ(m.unwrap_err(), errc::unknown_word) << t;
    }
}

TEST(CryptoBip39Mnemonic, WrongWordCountsAreRefused)
{
    for (const char* t : {"abandon", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}) {
        const auto m = b::parse(t);
        ASSERT_FALSE(m) << t;
        EXPECT_EQ(m.unwrap_err(), errc::invalid_mnemonic_length) << t;
    }
    EXPECT_EQ(b::parse("").unwrap_err(), errc::invalid_mnemonic_length);
    EXPECT_EQ(b::parse(std::string(216, 'a')).unwrap_err(), errc::invalid_mnemonic_length);
}

TEST(CryptoBip39Mnemonic, NonCanonicalTextIsRefused)
{
    const std::string good = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    ASSERT_TRUE(b::parse(good));
    for (const std::string& t : std::vector<std::string>{" " + good, good + " ", "abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                                 "Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                                 "abandon\tabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                                 good + "\n", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abo1t"}) {
        const auto m = b::parse(t);
        ASSERT_FALSE(m) << t;
        EXPECT_EQ(m.unwrap_err(), errc::non_canonical) << t;
    }
}

TEST(CryptoBip39Mnemonic, TwentyFourLongWordsFitTheBuffer)
{
    // 32 bytes of 0xff: every word is "zoo" except the last, which carries the checksum
    const std::vector<std::uint8_t> e(32, 0xff);
    const auto m = b::from_entropy(e);
    ASSERT_TRUE(m);
    EXPECT_EQ(text_of(*m), "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote");
    EXPECT_TRUE(b::parse(text_of(*m)));
}

TEST(CryptoBip39Mnemonic, NonAsciiPassphraseNeedsTheNfkdStatement)
{
    const auto m = *b::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    const std::string accented = "caf\xc3\xa9";   // "café" with a precomposed e-acute: not NFKD
    const auto refused = b::to_seed(m, accented);
    ASSERT_FALSE(refused);
    EXPECT_EQ(refused.unwrap_err(), errc::non_canonical);
    const std::string nfkd = "cafe\xcc\x81";      // the NFKD form, as the caller would have normalised it
    EXPECT_TRUE(b::to_seed(m, nfkd, b::passphrase_form::nfkd));
    EXPECT_NE(to_hex(b::to_seed(m, nfkd, b::passphrase_form::nfkd)->reveal()), to_hex(b::to_seed(m)->reveal()));
}

TEST(CryptoBip39Mnemonic, MoveWipesAndCloneCopies)
{
    auto m = *b::parse("legal winner thank year wave sausage worth useful legal winner thank yellow");
    const auto c = m.clone();
    const auto moved = std::move(m);
    EXPECT_EQ(moved, c);
    EXPECT_EQ(m.size(), 0u);
    EXPECT_EQ(m.index(0), 0);
}

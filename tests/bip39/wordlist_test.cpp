//
//  wordlist_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/bip39/wordlist.hpp>

#include <gtest/gtest.h>

#include <string>

namespace b = snicholls::crypto::bip39;

static_assert(b::english.size() == 2048);
static_assert(b::english[0] == "abandon" && b::english[2047] == "zoo");
static_assert(b::english[3] == "about");
static_assert(b::find_word_ct(b::pack_word("zoo")) == 2047);
static_assert(b::find_word_ct(b::pack_word("abandon")) == 0);
static_assert(b::find_word_ct(b::pack_word("zzz")) == b::word_list_size);
static_assert(b::pack_word("") == 0 && b::pack_word("abcdefghi") == 0);
static_assert(noexcept(b::find_word_ct(0)));

TEST(CryptoBip39Wordlist, EveryWordIsFoundAtItsIndex)
{
    for (std::size_t i = 0; i < b::word_list_size; ++i)
        ASSERT_EQ(b::find_word_ct(b::pack_word(b::english[i])), i) << b::english[i];
}

TEST(CryptoBip39Wordlist, NearMissesAreNotFound)
{
    for (const char* w : {"abando", "abandons", "Abandon", "zo", "zooo", "a", ""})
        EXPECT_EQ(b::find_word_ct(b::pack_word(w)), b::word_list_size) << w;
    EXPECT_EQ(b::find_word_ct(0), b::word_list_size);
}

TEST(CryptoBip39Wordlist, PackedWordsAreLittleEndianLetters)
{
    EXPECT_EQ(b::pack_word("abc"), 0x636261u);
    EXPECT_EQ(b::english_packed[2047], b::pack_word("zoo"));
}

//
//  wordlist_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// BIP-39's English word list, and a lookup whose time does not depend on the word.
#include <snicholls/crypto/bip39/wordlist.hpp>

#include <cstdio>
#include <string>

int main()
{
    //! [wordlist]
    namespace bip39 = snicholls::crypto::bip39;
    static_assert(bip39::english[2047] == "zoo");                            // the table is compile-time data
    const auto i = bip39::find_word_ct(bip39::pack_word("legal"));          // scans all 2048: constant time
    const auto missing = bip39::find_word_ct(bip39::pack_word("bitcoin"));  // not a BIP-39 word
    //! [wordlist]
    std::printf("\"legal\" is word %llu (%s); \"bitcoin\" -> %llu (= word_list_size: not in the list)\n",
                static_cast<unsigned long long>(i), std::string(bip39::english[i]).c_str(),
                static_cast<unsigned long long>(missing));
    return i == 1019 && bip39::english[i] == "legal" && missing == bip39::word_list_size ? 0 : 1;
}

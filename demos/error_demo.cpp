//
//  error_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Every expected failure is a value of snicholls::crypto::errc, carried by snicholls::result.
#include <snicholls/core/result.hpp>
#include <snicholls/crypto/error.hpp>

#include <cstdio>
#include <string>

//! [errors]
// A function that can fail on its input returns result<V, errc>; the caller matches on the value
snicholls::result<int, snicholls::crypto::errc> word_count(int words)
{
    if (words % 3 != 0 || words < 12 || words > 24)
        return snicholls::err(snicholls::crypto::errc::invalid_mnemonic_length);
    return snicholls::ok(words);
}

int main()
{
    const auto good = word_count(12);
    const auto bad = word_count(13);
    std::printf("12 words: %s\n", good ? "ok" : "error");
    std::printf("13 words: %s\n", std::string(snicholls::crypto::to_string(bad.unwrap_err())).c_str());
    //! [errors]
    return good && !bad && bad.unwrap_err() == snicholls::crypto::errc::invalid_mnemonic_length ? 0 : 1;
}

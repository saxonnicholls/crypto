//
//  path_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// Derivation paths: strict parsing, formatting, and the standard wallet paths.
#include <snicholls/crypto/hd/path.hpp>

#include <array>
#include <cstdio>
#include <string>

int main()
{
    namespace hd = snicholls::crypto::hd;
    //! [path]
    constexpr auto eth = hd::bip44_path(hd::coin_type::ethereum, 0, 0, 0);    // m/44'/60'/0'/0/0, at compile time
    static_assert(eth && eth->size() == 5 && !eth->all_hardened());
    const auto btc = hd::bip84_path(hd::coin_type::bitcoin, 0, 0, 0);         // m/84'/0'/0'/0/0
    const auto sol = hd::derivation_path::parse("m/44h/501h/0h/0h");          // h, H and ' all mark hardened
    const auto bad = hd::derivation_path::parse("m/44'/060'");                // a leading zero: refused

    std::array<char, hd::derivation_path::max_text_length> buf{};
    const std::string eth_text(buf.data(), eth->format(buf));
    const std::string btc_text(buf.data(), btc->format(buf));
    const std::string sol_text(buf.data(), sol->format(buf));                 // written back with '
    //! [path]
    std::printf("%s\n%s\n%s (all hardened: %s)\nm/44'/060' -> %s\n", eth_text.c_str(), btc_text.c_str(), sol_text.c_str(),
                sol->all_hardened() ? "yes" : "no", std::string(snicholls::crypto::to_string(bad.unwrap_err())).c_str());
    return eth_text == "m/44'/60'/0'/0/0" && btc_text == "m/84'/0'/0'/0/0" && sol_text == "m/44'/501'/0'/0'" &&
                   sol->all_hardened() && bad.unwrap_err() == snicholls::crypto::errc::invalid_path
               ? 0
               : 1;
}

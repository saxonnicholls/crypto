//
//  base58_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Base58 with Bitcoin's, XRPL's and Flickr's alphabets: encode, decode, and a refused character.
#include <snicholls/crypto/address/base58.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

int main()
{
    //! [base58]
    namespace address = snicholls::crypto::address;
    const std::array<std::uint8_t, 4> bytes{0x00, 0x00, 0x28, 0x7f};
    const auto bitcoin = address::base58_encode(bytes);                          // "1145k": "11" for the two zero bytes
    const auto xrpl = address::base58_encode(bytes, address::xrpl_base58);       // "rrhnk": a zero byte is an "r" in XRPL's
    const auto flickr = address::base58_encode(bytes, address::flickr_base58);
    const auto back = address::base58_decode(std::string(bitcoin->data(), bitcoin->size()));
    const auto refused = address::base58_decode("11O0");                        // 'O' and '0' are not digits

    std::array<char, 16> buffer{};                                              // or into a buffer of your own
    const auto written = address::base58_encode_to(bytes, buffer);
    //! [base58]
    const std::string b(bitcoin->data(), bitcoin->size()), x(xrpl->data(), xrpl->size()), f(flickr->data(), flickr->size());
    std::printf("bitcoin %s, xrpl %s, flickr %s; round trip %s; \"11O0\" refused: %s; %zu characters written\n", b.c_str(),
                x.c_str(), f.c_str(), back && back->size() == 4 && (*back)[3] == 0x7f ? "ok" : "FAILED",
                std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str(), *written);
    return b == "1145k" && x == "rrhnk" && f == "1145K" && back && !refused && *written == 5 ? 0 : 1;
}

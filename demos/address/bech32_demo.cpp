//
//  bech32_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// Bech32, bech32m and segwit addresses: encode, decode, the output script, and a refused address.
#include <snicholls/crypto/address/bech32.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <span>
#include <string>

int main()
{
    //! [bech32]
    namespace address = snicholls::crypto::address;
    // A P2WPKH program (HASH160 of a published test key) as a mainnet address: version 0, so bech32
    constexpr auto program = snicholls::crypto::test::hex<20>("751e76e8199196d454941c45d1b3a323f1433bd6");
    const auto p2wpkh = address::segwit_encode("bc", 0, program);
    // Upper case is accepted (QR codes); the program comes back with its output script
    const auto decoded = address::segwit_decode("bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
    const auto script = decoded->script_pubkey();
    // A version-1 address written with bech32 instead of bech32m is refused (BIP-350)
    const auto wrong = address::segwit_decode("bc", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd");
    // Raw bech32m with an HRP of your own: regroup bytes into 5-bit values, encode, decode
    const auto five = address::convert_bits<8, 5, true, 32>(program);
    const auto text = address::bech32_encode("demo", std::span<const std::uint8_t>(five->data(), five->size()),
                                             address::bech32_variant::bech32m);
    const auto raw = address::bech32_decode(std::string(text->data(), text->size()));
    const auto bytes = address::convert_bits<5, 8, false, 32>(std::span<const std::uint8_t>(raw->values.data(), raw->values.size()));
    const std::uint32_t check = address::bech32_polymod("demo", {});   // the BCH polymod, for those who need it
    //! [bech32]
    const std::string a(p2wpkh->data(), p2wpkh->size()), t(text->data(), text->size());
    const std::string s = snicholls::crypto::test::to_hex(std::span<const std::uint8_t>(script.data(), script.size()));
    std::printf("p2wpkh  %s\nscript  %s\nbech32m %s\nwrong variant refused: %s\n", a.c_str(), s.c_str(), t.c_str(),
                std::string(snicholls::crypto::to_string(wrong.unwrap_err())).c_str());
    const bool round_trip = bytes && bytes->size() == 20 && std::equal(bytes->begin(), bytes->end(), program.begin());
    return a == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" && s == "0014751e76e8199196d454941c45d1b3a323f1433bd6" &&
                   !wrong && raw->variant == address::bech32_variant::bech32m && round_trip && check != 0
               ? 0
               : 1;
}

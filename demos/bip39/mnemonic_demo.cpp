//
//  mnemonic_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// Entropy to words, words back to entropy, and the BIP-39 seed. Trezor's first test vector: never a real wallet.
#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <array>
#include <cstdio>
#include <string>

int main()
{
    namespace bip39 = snicholls::crypto::bip39;
    using snicholls::crypto::test::to_hex;

    //! [mnemonic]
    const std::array<std::uint8_t, 16> entropy{0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
                                               0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f};
    auto words = bip39::from_entropy(entropy);                  // result<mnemonic, errc>: checksum appended

    std::array<char, bip39::max_text_length> text{};
    const std::size_t n = words->to_text(text);                 // "legal winner thank ... yellow", no allocation

    auto parsed = bip39::parse(std::string_view(text.data(), n));   // canonical text only, checksum verified
    const auto back = bip39::to_entropy(*parsed);                     // the 16 bytes again, in secret_bytes
    const auto seed = bip39::to_seed(*parsed, "TREZOR");              // PBKDF2-HMAC-SHA512, 2048 rounds

    const auto typo = bip39::parse("legal winner thank year wave sausage worth useful legal winner thank thank");
    const auto shouted = bip39::parse("LEGAL winner thank year wave sausage worth useful legal winner thank yellow");
    const auto accented = bip39::to_seed(*parsed, "caf\xc3\xa9");     // non-ASCII without the NFKD statement
    //! [mnemonic]

    const std::string s(text.data(), n);
    std::printf("words:   %s\n", s.c_str());
    std::printf("entropy: %s\n", to_hex(back.reveal().first(parsed->entropy_size())).c_str());
    std::printf("seed:    %s\n", to_hex(seed->reveal()).c_str());
    std::printf("wrong last word: %s; upper case: %s; non-ASCII passphrase: %s\n",
                std::string(snicholls::crypto::to_string(typo.unwrap_err())).c_str(),
                std::string(snicholls::crypto::to_string(shouted.unwrap_err())).c_str(),
                std::string(snicholls::crypto::to_string(accented.unwrap_err())).c_str());
    const bool good = s == "legal winner thank year wave sausage worth useful legal winner thank yellow" &&
                      to_hex(back.reveal().first(16)) == "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f" &&
                      to_hex(seed->reveal()) ==
                          "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607" &&
                      typo.unwrap_err() == snicholls::crypto::errc::invalid_checksum &&
                      shouted.unwrap_err() == snicholls::crypto::errc::non_canonical &&
                      accented.unwrap_err() == snicholls::crypto::errc::non_canonical;
    return good ? 0 : 1;
}

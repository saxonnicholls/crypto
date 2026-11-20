//
//  base58check_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Base58check: a Bitcoin address, an XRPL address, and a typing error caught by the checksum.
#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

int main()
{
    //! [base58check]
    namespace address = snicholls::crypto::address;
    // Version 0x00 and the HASH160 of private key 1's compressed public key (a published test key)
    constexpr auto payload = snicholls::crypto::test::hex<21>("00751e76e8199196d454941c45d1b3a323f1433bd6");
    const auto bitcoin = address::base58check_encode_exact(payload);             // fixed size: cannot fail
    const auto xrpl = address::base58check_encode_exact(payload, address::xrpl_base58);
    const auto checksum = address::base58check_checksum(payload);
    const auto decoded = address::base58check_decode_exact<21>("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    const auto typo = address::base58check_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMh");   // last letter's case
    const auto any = address::base58check_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");     // any length up to 128
    const auto encoded = address::base58check_encode(std::span<const std::uint8_t>(payload));
    //! [base58check]
    const std::string b(bitcoin.data(), bitcoin.size()), x(xrpl.data(), xrpl.size());
    std::printf("bitcoin %s\nxrpl    %s\nchecksum %s; decoded back: %s; typo: %s\n", b.c_str(), x.c_str(),
                snicholls::crypto::test::to_hex(checksum).c_str(), decoded && *decoded == payload ? "yes" : "no",
                std::string(snicholls::crypto::to_string(typo.unwrap_err())).c_str());
    return b == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" && decoded && *decoded == payload && !typo &&
                   typo.unwrap_err() == snicholls::crypto::errc::invalid_checksum && any && any->size() == 21 && encoded &&
                   std::string(encoded->data(), encoded->size()) == b
               ? 0
               : 1;
}

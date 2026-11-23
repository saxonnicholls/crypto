//
//  aes256_gcm_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// AES-256-GCM (JWE's A256GCM): the GCM specification's test case 15 sealed and opened, then a changed tag refused.
#include <snicholls/crypto/aead/aes256_gcm.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>
#include <vector>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::hex_bytes;
    using snicholls::crypto::test::to_hex;
    //! [gcm]
    namespace aead = snicholls::crypto::aead;
    const auto key = hex<32>("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");   // the specification's test key
    const auto nonce = hex<12>("cafebabefacedbaddecaf888");                                          // never repeated under a key
    const auto message = hex_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72");
    std::vector<std::uint8_t> sealed(message.size()), opened(message.size());
    const aead::tag tag = aead::aes256_gcm_seal(key, nonce, {}, message, sealed).unwrap();
    const auto ok = aead::aes256_gcm_open(key, nonce, {}, sealed, tag, opened);
    auto bad = tag;
    bad[15] ^= 1;
    const auto refused = aead::aes256_gcm_open(key, nonce, {}, sealed, bad, opened);   // authentication_failed
    //! [gcm]
    std::printf("ciphertext %s\ntag %s; opened: %s; changed tag: %s\n", to_hex(sealed).c_str(), to_hex(tag).c_str(), ok.is_ok() ? "yes" : "no",
                refused.is_ok() ? "accepted" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str());
    return ok.is_ok() && !refused.is_ok() && to_hex(sealed).substr(0, 32) == "522dc1f099567d07f47f37a32a84427d" ? 0 : 1;
}

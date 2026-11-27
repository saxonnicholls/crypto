//
//  aes128_gcm_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// AES-128-GCM (TLS 1.3's TLS_AES_128_GCM_SHA256, JOSE's A128GCM): the GCM specification's test case 4 sealed and
// opened, then a changed tag refused.
#include <snicholls/crypto/aead/aes128_gcm.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>
#include <vector>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::hex_bytes;
    using snicholls::crypto::test::to_hex;
    //! [gcm128]
    namespace aead = snicholls::crypto::aead;
    const auto key = hex<16>("feffe9928665731c6d6a8f9467308308");   // the specification's test key
    const auto nonce = hex<12>("cafebabefacedbaddecaf888");         // never repeated under a key
    const auto aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const auto message = hex_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    std::vector<std::uint8_t> sealed(message.size()), opened(message.size());
    const aead::tag tag = aead::aes128_gcm_seal(key, nonce, aad, message, sealed).unwrap();
    const auto ok = aead::aes128_gcm_open(key, nonce, aad, sealed, tag, opened);
    auto bad = tag;
    bad[15] ^= 1;
    const auto refused = aead::aes128_gcm_open(key, nonce, aad, sealed, bad, opened);   // authentication_failed
    //! [gcm128]
    std::printf("ciphertext %s\ntag %s; opened: %s; changed tag: %s\n", to_hex(sealed).c_str(), to_hex(tag).c_str(), ok.is_ok() ? "yes" : "no",
                refused.is_ok() ? "accepted" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str());
    return ok.is_ok() && !refused.is_ok() && to_hex(tag) == "5bc94fbc3221a5db94fae95ae7121a47" ? 0 : 1;
}

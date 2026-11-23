//
//  aes_key_wrap_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// AES-256 key wrap (JWE's A256KW): RFC 3394 section 4.6 wrapped and unwrapped, then a changed wrapping refused.
#include <snicholls/crypto/aead/aes_key_wrap.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <vector>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::hex_bytes;
    using snicholls::crypto::test::to_hex;
    //! [keywrap]
    namespace aead = snicholls::crypto::aead;
    const auto kek = hex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");   // RFC 3394's test KEK
    const auto cek = hex_bytes("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");  // the key to protect
    std::vector<std::uint8_t> wrapped(cek.size() + 8), unwrapped(cek.size());
    const auto wrap = aead::aes256_key_wrap(kek, cek, wrapped);
    const auto unwrap = aead::aes256_key_unwrap(kek, wrapped, unwrapped);
    auto changed = wrapped;
    changed[0] ^= 1;
    const auto refused = aead::aes256_key_unwrap(kek, changed, unwrapped);   // authentication_failed
    //! [keywrap]
    std::printf("wrapped %s\nunwrapped: %s; changed: %s\n", to_hex(wrapped).c_str(), unwrap.is_ok() ? "yes" : "no", refused.is_ok() ? "accepted" : "refused");
    return wrap.is_ok() && unwrap.is_ok() && !refused.is_ok() &&
                   to_hex(wrapped) == "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"
               ? 0
               : 1;
}

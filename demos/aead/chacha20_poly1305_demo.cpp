//
//  chacha20_poly1305_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// XChaCha20-Poly1305 for a session cookie: a key derived with core's HKDF, a random-length nonce chosen per cookie
// (fixed here, so the output is reproducible), the cookie's name as associated data; then a tampered cookie refused.
// Also RFC 8439 section 2.8.2's ChaCha20-Poly1305 vector, byte for byte.
#include <snicholls/crypto/aead/chacha20_poly1305.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    auto bytes = [](std::string_view s) { return std::vector<std::uint8_t>(s.begin(), s.end()); };
    //! [aead]
    namespace aead = snicholls::crypto::aead;
    // A test key; a real one comes from a CSPRNG or from core's hkdf over a master secret
    const auto key = hex<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const auto nonce = hex<24>("404142434445464748494a4b4c4d4e4f5051525354555657");   // random per cookie
    const auto name = bytes("session");                                                 // authenticated, not secret
    const auto value = bytes("{\"user\":42,\"exp\":1795000000}");
    std::vector<std::uint8_t> sealed(value.size());
    const aead::tag tag = aead::xchacha20_poly1305_seal(key, nonce, name, value, sealed).unwrap();
    std::vector<std::uint8_t> opened(sealed.size());
    const auto ok = aead::xchacha20_poly1305_open(key, nonce, name, sealed, tag, opened);
    auto tampered = sealed;
    tampered[0] ^= 1;
    const auto refused = aead::xchacha20_poly1305_open(key, nonce, name, tampered, tag, opened);   // authentication_failed
    //! [aead]
    const auto pt = bytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    std::vector<std::uint8_t> ct(pt.size());
    const auto rfc_tag = aead::chacha20_poly1305_seal(key, hex<12>("070000004041424344454647"), hex<12>("50515253c0c1c2c3c4c5c6c7"), pt, ct).unwrap();
    std::printf("cookie sealed: %s, tag %s\nopened: %s; tampered: %s\nRFC 8439 2.8.2 tag: %s\n", to_hex(sealed).c_str(), to_hex(tag).c_str(),
                ok.is_ok() ? "yes" : "no", refused.is_ok() ? "accepted" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str(),
                to_hex(rfc_tag).c_str());
    return ok.is_ok() && !refused.is_ok() && to_hex(rfc_tag) == "1ae10b594f09e26a7e902ecbd0600691" ? 0 : 1;
}

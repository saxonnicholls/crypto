//
//  ecdsa_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ECDSA on P-256 (ES256): RFC 6979 appendix A.2.5's published test key signs "sample"; the signature is RFC 6979's
// byte for byte, verifies, round-trips through JOSE's r || s and DER, and fails for another message.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/p256/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    auto sha256 = [](std::string_view s) {
        snicholls::crypto::detail::sha256 h;
        h.update(s);
        return h.finish();
    };
    //! [p256]
    namespace p256 = snicholls::crypto::p256;
    // RFC 6979's published test key; a real key comes from a CSPRNG
    const auto key = p256::private_key::from_bytes(hex<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")).unwrap();
    const p256::public_key pub = key.public_key();
    const auto hash = sha256("sample");                       // for a JWS: SHA-256 of "header.payload"
    const p256::signature sig = p256::sign(key, hash);         // RFC 6979: deterministic
    const auto jose = sig.jose();                              // ES256's 64-byte r || s
    const auto ok = p256::verify(pub, hash, p256::signature::from_jose(jose));
    const auto wrong = p256::verify(pub, sha256("other"), sig);   // errc::invalid_signature
    //! [p256]
    const auto der = sig.der();
    const bool der_back = p256::signature::from_der(std::span<const std::uint8_t>(der.data(), der.size())).unwrap() == sig;
    std::printf("public key %s\nES256 r || s %s\nverifies: %s; other message: %s; DER round trip: %s\n",
                to_hex(pub.compressed()).c_str(), to_hex(jose).c_str(), ok.is_ok() ? "yes" : "no",
                wrong.is_ok() ? "accepted" : "refused", der_back ? "yes" : "no");
    return to_hex(sig.r) == "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" &&
                   to_hex(sig.s) == "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8" && ok.is_ok() &&
                   !wrong.is_ok() && der_back
               ? 0
               : 1;
}

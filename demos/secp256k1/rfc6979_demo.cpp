//
//  rfc6979_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Deterministic ECDSA nonces: RFC 6979's own P-256 example.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/rfc6979.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using snicholls::crypto::test::hex;
    //! [rfc6979]
    // RFC 6979 A.2.5: P-256's order, its test key, SHA-256("sample")
    const auto order = hex<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    const auto key = hex<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    const auto hash = snicholls::crypto::detail::sha256::hash(snicholls::crypto::test::bytes_of("sample"));
    snicholls::crypto::secp256k1::rfc6979 nonces(key, hash, order);
    const auto k = nonces.next();   // the first candidate in [1, q - 1]; next() again if r or s came out zero
    //! [rfc6979]
    const std::string text = snicholls::crypto::test::to_hex(k.reveal());
    std::printf("k = %s\n", text.c_str());
    return text == "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60" ? 0 : 1;
}

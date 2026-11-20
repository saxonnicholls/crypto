//
//  keys_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// secp256k1 keys: a validated private key, its public key, and the SEC1 encodings.
#include <snicholls/crypto/secp256k1/keys.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using namespace snicholls::crypto::secp256k1;
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [keys]
    // A published test key (never one that holds funds)
    const auto key = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000001"));
    if (!key)
        return 1;
    const public_key pub = key->public_key();                         // d G, constant time
    const auto compressed = pub.compressed();                          // 33 bytes: 02/03 || x
    const auto parsed = public_key::parse(pub.uncompressed());         // validated: on the curve, not the identity
    const auto zero = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000000"));
    //! [keys]
    const std::string c = to_hex(compressed);
    std::printf("public key of 1: %s\nuncompressed parses back: %s; zero key refused: %s\n", c.c_str(),
                parsed && *parsed == pub ? "yes" : "no", zero ? "no" : "yes");
    return c == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" && parsed && *parsed == pub && !zero ? 0 : 1;
}

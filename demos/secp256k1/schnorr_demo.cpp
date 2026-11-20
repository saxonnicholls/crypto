//
//  schnorr_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// BIP-340 Schnorr signatures: BIP-340's first test vector, signed and verified.
#include <snicholls/crypto/secp256k1/schnorr.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <array>
#include <cstdio>
#include <string>

int main()
{
    using namespace snicholls::crypto::secp256k1;
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [schnorr]
    const auto key = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000003")).unwrap();
    const std::array<std::uint8_t, 32> message{};   // BIP-340 vector 0: 32 zero bytes
    const std::array<std::uint8_t, 32> aux{};       // auxiliary randomness: fresh random bytes in real use
    const xonly_public_key pub = xonly_public_key_of(key);
    const schnorr_signature sig = schnorr_sign(key, message, aux);
    const auto ok = schnorr_verify(pub, message, sig);
    //! [schnorr]
    const std::string s = to_hex(sig.bytes);
    std::printf("public key %s\nsignature  %s\nverifies: %s\n", to_hex(pub.bytes).c_str(), s.c_str(), ok ? "yes" : "no");
    return ok && s == "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
               ? 0
               : 1;
}

//
//  ed25519_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Ed25519: a key pair from a seed, a signature, and verification, with RFC 8032's TEST 2 key.
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [ed25519]
    namespace ed25519 = snicholls::crypto::ed25519;
    // The seed is the private key: from a CSPRNG, or SLIP-10. This is RFC 8032's published TEST 2 seed.
    const auto kp = ed25519::key_pair::from_seed(hex<32>("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    const std::uint8_t message[] = {0x72};
    const ed25519::signature sig = kp.sign(message);                           // deterministic: no randomness
    const auto ok = ed25519::verify(kp.public_key(), message, sig);            // result<void, errc>
    const std::uint8_t other[] = {0x73};
    const auto bad = ed25519::verify(kp.public_key(), other, sig);             // errc::invalid_signature
    //! [ed25519]
    std::printf("public key %s\nsignature  %s\nverifies: %s; another message: %s\n", to_hex(kp.public_key().bytes).c_str(),
                to_hex(sig.bytes).c_str(), ok.is_ok() ? "yes" : "no",
                bad.is_ok() ? "verifies" : std::string(snicholls::crypto::to_string(bad.unwrap_err())).c_str());
    return to_hex(sig.bytes) == "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" &&
                   ok.is_ok() && !bad.is_ok()
               ? 0
               : 1;
}

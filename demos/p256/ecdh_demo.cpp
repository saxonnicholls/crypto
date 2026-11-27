//
//  ecdh_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// ECDH on P-256: RFC 7518 appendix C's two keys agree the same shared secret, and a point off the curve is refused.
#include <snicholls/crypto/p256/ecdh.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [p256_ecdh]
    namespace p256 = snicholls::crypto::p256;
    // RFC 7518 appendix C's published test keys: Alice's ephemeral key and Bob's static key
    const auto alice = p256::private_key::from_bytes(hex<32>("d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a")).unwrap();
    const auto bob = p256::private_key::from_bytes(hex<32>("5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc")).unwrap();
    auto z_alice = p256::shared_secret(alice, bob.public_key());   // result<secret_bytes<32>, errc>
    auto z_bob = p256::shared_secret(bob, alice.public_key());
    // A key built from a point that is not on the curve is refused, not multiplied
    auto off = bob.public_key().point();
    off.y = off.y + p256::field_element::from_u64(1);
    const auto refused = p256::shared_secret(alice, p256::public_key(off));   // errc::invalid_public_key
    //! [p256_ecdh]
    const bool agree = z_alice.is_ok() && z_bob.is_ok() && z_alice.unwrap() == z_bob.unwrap();
    const std::string z = agree ? to_hex(z_alice.unwrap().reveal()) : std::string();
    std::printf("shared secret %s (both sides agree: %s)\npoint off the curve: %s\n", z.c_str(), agree ? "yes" : "no",
                refused.is_ok() ? "accepted" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str());
    return agree && z == "9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4" && !refused.is_ok() ? 0 : 1;
}

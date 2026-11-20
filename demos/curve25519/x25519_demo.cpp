//
//  x25519_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// X25519: Alice and Bob agree a secret (RFC 7748, section 6.1), and a small-order key is refused.
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using snicholls::crypto::secret_bytes;
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [x25519]
    namespace x25519 = snicholls::crypto::x25519;
    // Secrets come from a CSPRNG or a KDF; these are RFC 7748's published test secrets
    const secret_bytes<32> alice(hex<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const secret_bytes<32> bob(hex<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    const x25519::public_key alice_pub = x25519::public_key_from_secret(alice);
    const x25519::public_key bob_pub = x25519::public_key_from_secret(bob);
    auto k_alice = x25519::shared_secret(alice, bob_pub);                      // result<secret_bytes<32>, errc>
    auto k_bob = x25519::shared_secret(bob, alice_pub);
    const auto refused = x25519::shared_secret(alice, x25519::public_key{});   // u = 0: errc::small_order
    //! [x25519]
    const bool agree = k_alice.is_ok() && k_bob.is_ok() && k_alice.unwrap() == k_bob.unwrap();
    const std::string k = agree ? to_hex(k_alice.unwrap().reveal()) : std::string();
    std::printf("shared secret %s (both sides agree: %s)\nzero public key: %s\n", k.c_str(), agree ? "yes" : "no",
                refused.is_ok() ? "accepted" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str());
    return agree && k == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" && !refused.is_ok() ? 0 : 1;
}

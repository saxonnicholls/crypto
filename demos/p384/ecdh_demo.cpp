//
//  ecdh_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// ECDH on P-384 (TLS 1.3's secp384r1): two keys agree the same 48-byte shared secret, and a point off the curve is
// refused.
#include <snicholls/crypto/p384/ecdh.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [p384_ecdh]
    namespace p384 = snicholls::crypto::p384;
    // RFC 6979 A.2.6's published test key and a fixed pattern; a real key comes from a CSPRNG
    const auto alice = p384::private_key::from_bytes(
        hex<48>("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5")).unwrap();
    const auto bob = p384::private_key::from_bytes(
        hex<48>("0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210")).unwrap();
    auto z_alice = p384::shared_secret(alice, bob.public_key());   // result<secret_bytes<48>, errc>
    auto z_bob = p384::shared_secret(bob, alice.public_key());
    // A key built from a point that is not on the curve is refused, not multiplied
    auto off = bob.public_key().point();
    off.y = off.y + p384::field_element::from_u64(1);
    const auto refused = p384::shared_secret(alice, p384::public_key(off));   // errc::invalid_public_key
    //! [p384_ecdh]
    const bool agree = z_alice.is_ok() && z_bob.is_ok() && z_alice.unwrap() == z_bob.unwrap();
    const std::string z = agree ? to_hex(z_alice.unwrap().reveal()) : std::string();
    std::printf("shared secret %s (both sides agree: %s)\npoint off the curve: %s\n", z.c_str(), agree ? "yes" : "no",
                refused.is_ok() ? "accepted" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str());
    return agree && z.size() == 96 && !refused.is_ok() ? 0 : 1;
}

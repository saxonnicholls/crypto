//
//  ecdsa_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ECDSA over secp256k1: sign, verify, recover, Ethereum's v, DER.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using namespace snicholls::crypto::secp256k1;
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [ecdsa]
    const auto key = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000001")).unwrap();
    const auto hash = snicholls::crypto::detail::sha256::hash(snicholls::crypto::test::bytes_of("Satoshi Nakamoto"));

    const recoverable_signature sig = sign(key, hash);                 // RFC 6979, low-S, recovery id
    const auto checked = verify(key.public_key(), hash, sig.sig, high_s::reject);   // Bitcoin's rule
    const auto recovered = recover(hash, sig.sig, sig.recovery_id);   // the key, from the signature alone
    const auto eth = recover_ethereum(hash, sig.ethereum());           // r || s || v, v = 27 or 28
    const auto der = sig.sig.der();                                    // strict DER, at most 72 bytes
    const auto parsed = signature::from_der(der);
    //! [ecdsa]
    const std::string r = to_hex(sig.sig.r);
    std::printf("r = %s\ns = %s\nrecovery id %d; verifies: %s; recovers the key: %s; ecrecover: %s; DER %zu bytes, parses back: %s\n",
                r.c_str(), to_hex(sig.sig.s).c_str(), sig.recovery_id, checked ? "yes" : "no",
                recovered && *recovered == key.public_key() ? "yes" : "no", eth && *eth == key.public_key() ? "yes" : "no",
                der.size(), parsed && *parsed == sig.sig ? "yes" : "no");
    return r == "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8" && checked && recovered &&
                   *recovered == key.public_key() && eth && *eth == key.public_key() && parsed && *parsed == sig.sig
               ? 0
               : 1;
}

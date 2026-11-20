//
//  slip10_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// SLIP-10 for Ed25519: SLIP-10's test vector 1, and a non-hardened index refused.
#include <snicholls/crypto/hd/slip10.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using namespace snicholls::crypto::hd;
    using snicholls::crypto::test::to_hex;
    //! [slip10]
    const auto seed = snicholls::crypto::test::hex<16>("000102030405060708090a0b0c0d0e0f");   // SLIP-10 vector 1
    const auto master = slip10_ed25519_key::from_seed(seed).unwrap();
    const auto node = master.derive(derivation_path::parse("m/0'/1'/2'").unwrap());   // hardened only
    const auto signer = node->key_pair();                                              // an Ed25519 key pair
    const auto soft = master.derive(derivation_path::parse("m/0'/1").unwrap());        // refused, never hardened
    //! [slip10]
    const std::string pub = to_hex(node->public_key().bytes);
    std::printf("m/0'/1'/2' public key %s\nnon-hardened refused: %s\n", pub.c_str(), soft ? "no" : "yes");
    return pub == "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1" && signer.public_key() == node->public_key() && !soft &&
                   soft.unwrap_err() == snicholls::crypto::errc::hardened_required
               ? 0
               : 1;
}

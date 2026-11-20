//
//  bip32_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// BIP-32: BIP-32's test vector 1, from the seed to an xprv, and an xpub's own children.
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>

int main()
{
    using namespace snicholls::crypto::hd;
    //! [bip32]
    const auto seed = snicholls::crypto::test::hex<16>("000102030405060708090a0b0c0d0e0f");   // BIP-32 vector 1
    const auto master = extended_private_key::from_seed(seed);
    if (!master)
        return 1;
    const auto path = derivation_path::parse("m/0'/1/2'").unwrap();
    const auto node = master->derive(path);                       // CKDpriv, constant time
    auto xprv = node->to_text();                                   // key material: wiped below
    const auto xpub = node->public_key().to_text();               // public: share it
    const auto watched = node->public_key().derive_child(2);      // CKDpub: an xpub derives its non-hardened children
    const auto refused = node->public_key().derive_child(hardened(2));   // but never a hardened one
    const auto back = extended_public_key::parse(std::string_view(xpub.data(), xpub.size()));
    //! [bip32]
    const std::string prv(xprv.begin(), xprv.end()), pub(xpub.begin(), xpub.end());
    snicholls::crypto::secure_wipe(xprv);
    std::printf("m/0'/1/2'\n  %s\n  %s\nxpub child 2 matches the private one: %s; hardened from xpub refused: %s\n", pub.c_str(),
                prv.c_str(), watched && *watched == node->derive_child(2)->public_key() ? "yes" : "no",
                !refused && refused.unwrap_err() == snicholls::crypto::errc::hardened_required ? "yes" : "no");
    return prv == "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM" &&
                   pub == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5" &&
                   watched && back && *back == node->public_key() && !refused
               ? 0
               : 1;
}

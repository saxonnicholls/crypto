//
//  module.h
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The Cryptofuzz module for snicholls-crypto (fuzz/cryptofuzz/README.md): secp256k1 keys, ECDSA (RFC 6979
//  signing, verification, recovery), BIP-340 verification, and Ed25519, for Cryptofuzz's differential driver to
//  compare with every other module it is built with. Copied into cryptofuzz/modules/snicholls-crypto/.
//

#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class snicholls_crypto : public Module {
    public:
        snicholls_crypto(void);
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<bool> OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::ECC_PublicKey> OpECDSA_Recover(operation::ECDSA_Recover& op) override;
        std::optional<component::Schnorr_Signature> OpSchnorr_Sign(operation::Schnorr_Sign& op) override;
        std::optional<bool> OpSchnorr_Verify(operation::Schnorr_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */

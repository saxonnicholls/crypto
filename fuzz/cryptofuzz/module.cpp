//
//  module.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The Cryptofuzz module for snicholls-crypto. Cryptofuzz passes numbers as decimal strings, and Ed25519 keys and
//  signatures as the big-endian integers of their bytes (as its Botan and noble modules do). An operation this
//  library does not offer (a nonce chosen by the caller, a digest other than NULL or SHA-256, another curve)
//  returns std::nullopt, which Cryptofuzz reads as "not supported".
//

#include "module.h"

#include <cryptofuzz/util.h>

#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/secp256k1/schnorr.hpp>

#include <array>
#include <cstring>

namespace cryptofuzz {
namespace module {

namespace sc = ::snicholls::crypto;

snicholls_crypto::snicholls_crypto(void) :
    Module("snicholls-crypto") {
}

namespace snicholls_crypto_detail {

template <std::size_t N>
std::optional<std::array<uint8_t, N>> Bytes(const std::string& dec) {
    const auto v = util::DecToBin(dec, N);
    if ( v == std::nullopt || v->size() != N ) {
        return std::nullopt;
    }
    std::array<uint8_t, N> out{};
    std::memcpy(out.data(), v->data(), N);
    return out;
}

/* The 32-byte hash an ECDSA operation signs or verifies: the cleartext itself (Cryptofuzz's ECDSA_Pad) for the
 * NULL digest, or its SHA-256 */
std::optional<std::array<uint8_t, 32>> Hash(const component::DigestType& digest, const component::Cleartext& cleartext) {
    std::array<uint8_t, 32> h{};
    if ( digest.Get() == CF_DIGEST("NULL") ) {
        const auto ct = cleartext.ECDSA_Pad(32);
        std::memcpy(h.data(), ct.GetPtr(), 32);
    } else if ( digest.Get() == CF_DIGEST("SHA256") ) {
        h = sc::detail::sha256::hash(std::span<const uint8_t>(cleartext.GetPtr(), cleartext.GetSize()));
    } else {
        return std::nullopt;
    }
    return h;
}

component::ECC_PublicKey Point(const sc::secp256k1::public_key& k) {
    const auto xy = k.xy();
    return { util::BinToDec(xy.data(), 32), util::BinToDec(xy.data() + 32, 32) };
}

std::optional<sc::secp256k1::public_key> Parse(const component::BignumPair& pub) {
    const auto x = Bytes<32>(pub.first.ToTrimmedString());
    const auto y = Bytes<32>(pub.second.ToTrimmedString());
    if ( x == std::nullopt || y == std::nullopt ) {
        return std::nullopt;
    }
    std::array<uint8_t, 65> u{};
    u[0] = 0x04;
    std::memcpy(u.data() + 1, x->data(), 32);
    std::memcpy(u.data() + 33, y->data(), 32);
    const auto k = sc::secp256k1::public_key::parse(u);
    if ( !k ) {
        return std::nullopt;
    }
    return *k;
}

std::optional<sc::secp256k1::signature> Signature(const component::BignumPair& rs) {
    const auto r = Bytes<32>(rs.first.ToTrimmedString());
    const auto s = Bytes<32>(rs.second.ToTrimmedString());
    if ( r == std::nullopt || s == std::nullopt ) {
        return std::nullopt;
    }
    sc::secp256k1::signature sig;
    sig.r = *r;
    sig.s = *s;
    return sig;
}

} /* namespace snicholls_crypto_detail */

namespace d = snicholls_crypto_detail;

std::optional<component::ECC_PublicKey> snicholls_crypto::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        const auto priv = d::Bytes<32>(op.priv.ToTrimmedString());
        if ( priv == std::nullopt ) {
            return std::nullopt;
        }
        const auto key = sc::secp256k1::private_key::from_bytes(*priv);
        if ( !key ) {
            return std::nullopt;
        }
        return d::Point(key->public_key());
    }
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
        const auto seed = d::Bytes<32>(op.priv.ToTrimmedString());
        if ( seed == std::nullopt ) {
            return std::nullopt;
        }
        const auto pub = sc::ed25519::public_key_from_seed(*seed);
        return component::ECC_PublicKey{ util::BinToDec(pub.bytes.data(), 32), "0" };
    }
    return std::nullopt;
}

std::optional<bool> snicholls_crypto::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return std::nullopt;
    }
    if ( !d::Bytes<32>(op.pub.first.ToTrimmedString()) || !d::Bytes<32>(op.pub.second.ToTrimmedString()) ) {
        return std::nullopt;   /* not a 256-bit coordinate: outside what a SEC1 encoding can say */
    }
    return d::Parse(op.pub) != std::nullopt;
}

std::optional<component::ECDSA_Signature> snicholls_crypto::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        if ( !op.UseRFC6979Nonce() ) {
            return std::nullopt;   /* no caller-chosen nonces: RFC 6979 only */
        }
        const auto priv = d::Bytes<32>(op.priv.ToTrimmedString());
        const auto h = d::Hash(op.digestType, op.cleartext);
        if ( priv == std::nullopt || h == std::nullopt ) {
            return std::nullopt;
        }
        const auto key = sc::secp256k1::private_key::from_bytes(*priv);
        if ( !key ) {
            return std::nullopt;
        }
        const auto sig = sc::secp256k1::sign(*key, *h);
        return component::ECDSA_Signature(
                { util::BinToDec(sig.sig.r.data(), 32), util::BinToDec(sig.sig.s.data(), 32) },
                d::Point(key->public_key()));
    }
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
        const auto seed = d::Bytes<32>(op.priv.ToTrimmedString());
        if ( seed == std::nullopt ) {
            return std::nullopt;
        }
        const auto kp = sc::ed25519::key_pair::from_seed(*seed);
        const auto sig = kp.sign(std::span<const uint8_t>(op.cleartext.GetPtr(), op.cleartext.GetSize()));
        return component::ECDSA_Signature(
                { util::BinToDec(sig.bytes.data(), 32), util::BinToDec(sig.bytes.data() + 32, 32) },
                { util::BinToDec(kp.public_key().bytes.data(), 32), "0" });
    }
    return std::nullopt;
}

std::optional<bool> snicholls_crypto::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        const auto h = d::Hash(op.digestType, op.cleartext);
        const auto sig = d::Signature(op.signature.signature);
        if ( h == std::nullopt || sig == std::nullopt ) {
            return std::nullopt;
        }
        const auto pub = d::Parse(op.signature.pub);
        if ( pub == std::nullopt ) {
            return false;
        }
        /* Textbook ECDSA, as Cryptofuzz's other modules verify: either s */
        return static_cast<bool>(sc::secp256k1::verify(*pub, *h, *sig, sc::secp256k1::high_s::accept));
    }
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
        const auto pub = d::Bytes<32>(op.signature.pub.first.ToTrimmedString());
        const auto r = d::Bytes<32>(op.signature.signature.first.ToTrimmedString());
        const auto s = d::Bytes<32>(op.signature.signature.second.ToTrimmedString());
        if ( pub == std::nullopt || r == std::nullopt || s == std::nullopt ) {
            return std::nullopt;
        }
        sc::ed25519::signature sig;
        std::memcpy(sig.bytes.data(), r->data(), 32);
        std::memcpy(sig.bytes.data() + 32, s->data(), 32);
        return static_cast<bool>(sc::ed25519::verify(sc::ed25519::public_key{*pub},
                    std::span<const uint8_t>(op.cleartext.GetPtr(), op.cleartext.GetSize()), sig));
    }
    return std::nullopt;
}

std::optional<component::ECC_PublicKey> snicholls_crypto::OpECDSA_Recover(operation::ECDSA_Recover& op) {
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) || op.id > 3 ) {
        return std::nullopt;
    }
    const auto h = d::Hash(op.digestType, op.cleartext);
    const auto sig = d::Signature(op.signature);
    if ( h == std::nullopt || sig == std::nullopt ) {
        return std::nullopt;
    }
    const auto key = sc::secp256k1::recover(*h, *sig, op.id, sc::secp256k1::high_s::accept);
    if ( !key ) {
        return std::nullopt;
    }
    return d::Point(*key);
}

std::optional<component::Schnorr_Signature> snicholls_crypto::OpSchnorr_Sign(operation::Schnorr_Sign& op) {
    /* Cryptofuzz's BIP-340 nonce is libsecp256k1's signing without aux_rand, which libsecp256k1 defines as
     * aux_rand = 32 zero bytes (its precomputed ZERO_MASK); a caller-chosen nonce is not offered */
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) || !op.UseBIP340Nonce() ) {
        return std::nullopt;
    }
    const auto priv = d::Bytes<32>(op.priv.ToTrimmedString());
    if ( priv == std::nullopt ) {
        return std::nullopt;
    }
    const auto key = sc::secp256k1::private_key::from_bytes(*priv);
    if ( !key ) {
        return std::nullopt;
    }
    std::array<uint8_t, 32> message_hash{};
    std::span<const uint8_t> message(op.cleartext.GetPtr(), op.cleartext.GetSize());
    if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        message_hash = sc::detail::sha256::hash(message);
        message = message_hash;
    } else if ( op.digestType.Get() != CF_DIGEST("NULL") ) {
        return std::nullopt;
    }
    const std::array<uint8_t, 32> aux{};
    const auto sig = sc::secp256k1::schnorr_sign(*key, message, aux);
    const auto x = sc::secp256k1::xonly_public_key_of(*key);
    return component::Schnorr_Signature(
            { util::BinToDec(sig.bytes.data(), 32), util::BinToDec(sig.bytes.data() + 32, 32) },
            { util::BinToDec(x.bytes.data(), 32), "0" });
}

std::optional<bool> snicholls_crypto::OpSchnorr_Verify(operation::Schnorr_Verify& op) {
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) || op.digestType.Get() != CF_DIGEST("NULL") ) {
        return std::nullopt;
    }
    const auto x = d::Bytes<32>(op.signature.pub.first.ToTrimmedString());
    const auto r = d::Bytes<32>(op.signature.signature.first.ToTrimmedString());
    const auto s = d::Bytes<32>(op.signature.signature.second.ToTrimmedString());
    if ( x == std::nullopt || r == std::nullopt || s == std::nullopt ) {
        return std::nullopt;
    }
    sc::secp256k1::schnorr_signature sig;
    std::memcpy(sig.bytes.data(), r->data(), 32);
    std::memcpy(sig.bytes.data() + 32, s->data(), 32);
    return static_cast<bool>(sc::secp256k1::schnorr_verify(sc::secp256k1::xonly_public_key{*x},
                std::span<const uint8_t>(op.cleartext.GetPtr(), op.cleartext.GetSize()), sig));
}

} /* namespace module */
} /* namespace cryptofuzz */

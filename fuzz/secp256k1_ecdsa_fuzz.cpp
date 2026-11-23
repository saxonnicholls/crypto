//
//  secp256k1_ecdsa_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of secp256k1 keys and ECDSA against libsecp256k1 and OpenSSL: key validity, public keys,
//  RFC 6979 signatures byte for byte with their recovery id, then a signature made adversarial (r or s replaced
//  by 0, n - 1, n, n + 1, p, high-S, bits flipped) verified under both policies and recovered. Any difference not
//  covered by a stated rule (tests/fixtures/README.md, "Other implementations") aborts with the case.
//
#include "support/fuzz_support.hpp"
#include "support/openssl_oracle.hpp"

#include <snicholls/crypto/secp256k1/ecdsa.hpp>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

namespace f = snicholls::crypto::fuzz;
using namespace snicholls::crypto::secp256k1;

static secp256k1_context* ctx()
{
    static secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return c;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("secp256k1_ecdsa", data, size);
    f::input in(data, size);
    const std::uint8_t mode = in.byte();
    auto sk = in.take<32>();
    if (mode & 1)
        sk = f::secp256k1_edge(in.byte());
    const auto h = in.take<32>();
    const char* T = "secp256k1_ecdsa";

    const auto ours = private_key::from_bytes(sk);
    const bool theirs = secp256k1_ec_seckey_verify(ctx(), sk.data()) == 1;
    if (static_cast<bool>(ours) != theirs)
        f::divergence(T, "key validity of " + f::hex(sk));
    if (!ours)
        return 0;

    // The public key
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx(), &pk, sk.data()))
        f::divergence(T, "libsecp256k1 refused a valid key");
    std::array<std::uint8_t, 33> c{};
    std::size_t clen = 33;
    secp256k1_ec_pubkey_serialize(ctx(), c.data(), &clen, &pk, SECP256K1_EC_COMPRESSED);
    const auto pub = ours->public_key();
    if (pub.compressed() != c)
        f::divergence(T, "public key of " + f::hex(sk));

    // RFC 6979, low-S, the recovery id: byte for byte
    const auto sig = sign(*ours, h);
    secp256k1_ecdsa_recoverable_signature rs;
    if (!secp256k1_ecdsa_sign_recoverable(ctx(), &rs, h.data(), sk.data(), nullptr, nullptr))
        f::divergence(T, "libsecp256k1 could not sign");
    std::array<std::uint8_t, 64> compact{};
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx(), compact.data(), &recid, &rs);
    if (sig.sig.compact() != compact || sig.recovery_id != recid)
        f::divergence(T, "signature of " + f::hex(h) + " by " + f::hex(sk));
    if (!f::openssl::ecdsa_verify(pub.uncompressed(), h, compact))
        f::divergence(T, "OpenSSL does not verify our signature");

    // An adversarial signature
    auto r = sig.sig.r, s = sig.sig.s;
    if (mode & 2)
        r = f::secp256k1_edge(in.byte());
    if (mode & 4)
        s = f::secp256k1_edge(in.byte());
    if (mode & 8) {   // high-S: n - s, from the table's n
        const auto n = f::secp256k1_edge(3);
        int borrow = 0;
        for (int i = 31; i >= 0; --i) {
            int d = n[i] - s[i] - borrow;
            borrow = d < 0;
            s[i] = static_cast<std::uint8_t>(d + (borrow ? 256 : 0));
        }
    }
    if (mode & 16) {
        const std::uint8_t at = in.byte();
        (at & 0x80 ? s : r)[at & 31] ^= static_cast<std::uint8_t>(1u << (in.byte() & 7));
    }
    signature adv;
    adv.r = r;
    adv.s = s;
    const auto adv_compact = adv.compact();
    const bool ours_reject = static_cast<bool>(verify(pub, h, adv, high_s::reject));
    const bool ours_accept = static_cast<bool>(verify(pub, h, adv, high_s::accept));
    secp256k1_ecdsa_signature ls;
    bool lib_reject = false, lib_accept = false;
    if (secp256k1_ecdsa_signature_parse_compact(ctx(), &ls, adv_compact.data())) {
        lib_reject = secp256k1_ecdsa_verify(ctx(), &ls, h.data(), &pk) == 1;
        secp256k1_ecdsa_signature_normalize(ctx(), &ls, &ls);
        lib_accept = secp256k1_ecdsa_verify(ctx(), &ls, h.data(), &pk) == 1;
    }
    if (ours_reject != lib_reject)
        f::divergence(T, "verify (reject high-S) of " + f::hex(adv_compact));
    if (ours_accept != lib_accept)
        f::divergence(T, "verify (accept high-S) of " + f::hex(adv_compact));
    if (ours_accept != f::openssl::ecdsa_verify(pub.uncompressed(), h, adv_compact))
        f::divergence(T, "verify against OpenSSL of " + f::hex(adv_compact));

    // Recovery with every id: libsecp256k1 recovers high-S as this library's high_s::accept does
    for (int id = 0; id < 4; ++id) {
        const auto key = recover(h, adv, static_cast<std::uint8_t>(id), high_s::accept);
        secp256k1_ecdsa_recoverable_signature lrs;
        secp256k1_pubkey lpk;
        const bool lib = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx(), &lrs, adv_compact.data(), id) &&
                         secp256k1_ecdsa_recover(ctx(), &lpk, &lrs, h.data());
        if (static_cast<bool>(key) != lib)
            f::divergence(T, "recovery (id " + std::to_string(id) + ") from " + f::hex(adv_compact));
        if (lib) {
            std::array<std::uint8_t, 33> lc{};
            std::size_t n = 33;
            secp256k1_ec_pubkey_serialize(ctx(), lc.data(), &n, &lpk, SECP256K1_EC_COMPRESSED);
            if (key->compressed() != lc)
                f::divergence(T, "recovered key (id " + std::to_string(id) + ") from " + f::hex(adv_compact));
        }
    }
    return 0;
}

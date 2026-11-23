//
//  secp256k1_schnorr_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of BIP-340 against libsecp256k1's schnorrsig module: signatures byte for byte with the
//  same auxiliary randomness over messages of any length, then verification of a key, message and signature made
//  adversarial (r at or above p, s at or above n, bits flipped, another key).
//
#include "support/fuzz_support.hpp"

#include <snicholls/crypto/secp256k1/schnorr.hpp>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

namespace f = snicholls::crypto::fuzz;
using namespace snicholls::crypto::secp256k1;

static secp256k1_context* ctx()
{
    static secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return c;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("secp256k1_schnorr", data, size);
    const char* T = "secp256k1_schnorr";
    f::input in(data, size);
    const std::uint8_t mode = in.byte();
    const auto sk = in.take<32>();
    auto aux = in.take<32>();
    const auto m = in.take_upto(160);
    const auto key = private_key::from_bytes(sk);
    secp256k1_keypair kp;
    if (static_cast<bool>(key) != (secp256k1_keypair_create(ctx(), &kp, sk.data()) == 1))
        f::divergence(T, "key validity " + f::hex(sk));
    if (!key)
        return 0;

    const auto ours = schnorr_sign(*key, m, aux);
    secp256k1_schnorrsig_extraparams extra = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    extra.ndata = aux.data();
    std::array<std::uint8_t, 64> lib{};
    if (!secp256k1_schnorrsig_sign_custom(ctx(), lib.data(), m.data(), m.size(), &kp, &extra))
        f::divergence(T, "libsecp256k1 could not sign");
    if (ours.bytes != lib)
        f::divergence(T, "signature of " + f::hex(m) + " by " + f::hex(sk) + " with " + f::hex(aux));
    secp256k1_xonly_pubkey xpk;
    secp256k1_keypair_xonly_pub(ctx(), &xpk, nullptr, &kp);
    std::array<std::uint8_t, 32> x{};
    secp256k1_xonly_pubkey_serialize(ctx(), x.data(), &xpk);
    if (xonly_public_key_of(*key).bytes != x)
        f::divergence(T, "x-only key of " + f::hex(sk));

    // Adversarial verification
    xonly_public_key vk{x};
    schnorr_signature sig = ours;
    auto msg = m;
    if (mode & 1)
        vk.bytes = in.take<32>();
    if (mode & 2) {
        const auto e = f::secp256k1_edge(in.byte());
        std::copy(e.begin(), e.end(), sig.bytes.begin() + ((mode & 4) ? 32 : 0));
    }
    if (mode & 8)
        sig.bytes[in.byte() & 63] ^= static_cast<std::uint8_t>(1u << (in.byte() & 7));
    if ((mode & 16) && !msg.empty())
        msg[in.byte() % msg.size()] ^= 1;
    const bool o = static_cast<bool>(schnorr_verify(vk, msg, sig));
    secp256k1_xonly_pubkey lx;
    const bool l = secp256k1_xonly_pubkey_parse(ctx(), &lx, vk.bytes.data()) == 1 &&
                   secp256k1_schnorrsig_verify(ctx(), sig.bytes.data(), msg.data(), msg.size(), &lx) == 1;
    if (o != l)
        f::divergence(T, "verify " + f::hex(vk.bytes) + " " + f::hex(msg) + " " + f::hex(sig.bytes));
    return 0;
}

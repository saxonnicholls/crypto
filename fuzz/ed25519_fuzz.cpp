//
//  ed25519_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of Ed25519 against libsodium and OpenSSL: keys and signatures byte for byte, then
//  verification of a key, R and S made adversarial (every small-order point in every encoding, S + L, bits
//  flipped, arbitrary bytes). The verifiers' rules differ, and each difference must be the stated one
//  (tests/fixtures/README.md): libsodium refuses small-order A and R, which this library accepts when the
//  cofactorless equation holds; OpenSSL decodes A without RFC 8032's canonical checks, which this library refuses.
//
#include "support/fuzz_support.hpp"
#include "support/openssl_oracle.hpp"

#include <snicholls/crypto/curve25519/ed25519.hpp>

#include <sodium.h>

namespace f = snicholls::crypto::fuzz;
using namespace snicholls::crypto::ed25519;
using snicholls::crypto::curve25519::point;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("ed25519", data, size);
    static const bool ready = sodium_init() >= 0;
    (void)ready;
    const char* T = "ed25519";
    f::input in(data, size);
    const std::uint8_t mode = in.byte();
    const auto seed = in.take<32>();
    const auto m = in.take_upto(200);

    const auto kp = key_pair::from_seed(seed);
    const auto ours = kp.sign(m);
    std::array<std::uint8_t, 32> pk{};
    std::array<std::uint8_t, 64> sk{};
    crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
    std::array<std::uint8_t, 64> lib{};
    crypto_sign_detached(lib.data(), nullptr, m.data(), m.size(), sk.data());
    if (kp.public_key().bytes != pk || ours.bytes != lib)
        f::divergence(T, "key or signature (libsodium) for seed " + f::hex(seed) + " message " + f::hex(m));
    std::array<std::uint8_t, 32> opk{};
    const auto osig = f::openssl::ed25519_sign(seed, m, opk);
    if (!osig || opk != pk || *osig != ours.bytes)
        f::divergence(T, "key or signature (OpenSSL) for seed " + f::hex(seed));

    // Adversarial verification
    public_key a = kp.public_key();
    signature sig = ours;
    auto msg = m;
    if (mode & 1)
        a.bytes = f::curve25519_small_order(in.byte());
    if (mode & 2) {
        const auto r = f::curve25519_small_order(in.byte());
        std::copy(r.begin(), r.end(), sig.bytes.begin());
    }
    if (mode & 4)
        std::fill(sig.bytes.begin() + 32, sig.bytes.end(), 0);
    if (mode & 8) {   // S + L
        static constexpr std::uint8_t l[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                               0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
        unsigned carry = 0;
        for (int i = 0; i < 32; ++i) {
            const unsigned t = sig.bytes[32 + i] + l[i] + carry;
            sig.bytes[32 + i] = static_cast<std::uint8_t>(t);
            carry = t >> 8;
        }
    }
    if (mode & 16)
        a.bytes = in.take<32>();
    if (mode & 32)
        sig.bytes[in.byte() & 63] ^= static_cast<std::uint8_t>(1u << (in.byte() & 7));

    const bool o = static_cast<bool>(verify(a, msg, sig));
    const bool s = crypto_sign_verify_detached(sig.bytes.data(), msg.data(), msg.size(), a.bytes.data()) == 0;
    const bool ossl = f::openssl::ed25519_verify(a.bytes, msg, sig.bytes);
    const auto da = point::decode(a.bytes);
    const auto dr = point::decode(std::span<const std::uint8_t, 32>(sig.bytes.data(), 32));
    const bool small = (da && da->is_small_order()) || (dr && dr->is_small_order());
    const std::string c = f::hex(a.bytes) + " " + f::hex(msg) + " " + f::hex(sig.bytes);
    // libsodium: what it accepts this library accepts; what only this library accepts has a small-order A or R
    if (s && !o)
        f::divergence(T, "libsodium accepts, this library refuses: " + c);
    if (o && !s && !small)
        f::divergence(T, "this library accepts, libsodium refuses, no small-order point: " + c);
    // OpenSSL: the same equation; it alone accepts only where A does not decode here (non-canonical)
    if (o && !ossl)
        f::divergence(T, "this library accepts, OpenSSL refuses: " + c);
    if (ossl && !o && da)
        f::divergence(T, "OpenSSL accepts a canonical key this library refuses: " + c);
    return 0;
}

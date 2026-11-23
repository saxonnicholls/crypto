//
//  aead_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of ChaCha20-Poly1305 and XChaCha20-Poly1305 against libsodium: seal byte for byte for any
//  key, nonce, associated data and message, then open agreeing on the sealed output and on a tampered ciphertext,
//  tag or associated data.
//
#include "support/fuzz_support.hpp"

#include <snicholls/crypto/aead/chacha20_poly1305.hpp>

#include <sodium.h>

#include <vector>

namespace f = snicholls::crypto::fuzz;
namespace aead = snicholls::crypto::aead;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    static const bool ready = sodium_init() >= 0;
    (void)ready;
    f::control("aead", data, size);
    const char* T = "aead";
    f::input in(data, size);
    const std::uint8_t mode = in.byte();
    const auto key = in.take<32>();
    const auto n24 = in.take<24>();
    auto ad = in.take_upto(64);
    auto msg = in.rest();
    const bool x = mode & 1;
    const std::span<const std::uint8_t, 12> n12(n24.data(), 12);

    std::vector<std::uint8_t> ours(msg.size());
    const auto tag = (x ? aead::xchacha20_poly1305_seal(key, n24, ad, msg, ours) : aead::chacha20_poly1305_seal(key, n12, ad, msg, ours)).unwrap();
    std::vector<std::uint8_t> theirs(msg.size() + 16);
    unsigned long long len = 0;
    if (x)
        crypto_aead_xchacha20poly1305_ietf_encrypt(theirs.data(), &len, msg.data(), msg.size(), ad.data(), ad.size(), nullptr, n24.data(), key.data());
    else
        crypto_aead_chacha20poly1305_ietf_encrypt(theirs.data(), &len, msg.data(), msg.size(), ad.data(), ad.size(), nullptr, n12.data(), key.data());
    if (!std::equal(ours.begin(), ours.end(), theirs.begin()) || !std::equal(tag.begin(), tag.end(), theirs.begin() + msg.size()))
        f::divergence(T, std::string(x ? "XChaCha20" : "ChaCha20") + "-Poly1305 seal: key " + f::hex(key) + " message " + f::hex(msg));

    // open, possibly tampered
    auto ct = ours;
    auto t = tag;
    if ((mode & 2) && !ct.empty())
        ct[in.byte() % ct.size()] ^= static_cast<std::uint8_t>(1u << (mode >> 5));
    if (mode & 4)
        t[mode % 16] ^= 0x80;
    if ((mode & 8) && !ad.empty())
        ad[0] ^= 1;
    std::vector<std::uint8_t> out(ct.size());
    const bool o = static_cast<bool>(x ? aead::xchacha20_poly1305_open(key, n24, ad, ct, t, out)
                                       : aead::chacha20_poly1305_open(key, n12, ad, ct, t, out));
    std::vector<std::uint8_t> joined(ct);
    joined.insert(joined.end(), t.begin(), t.end());
    std::vector<std::uint8_t> sout(ct.size() + 1);
    unsigned long long slen = 0;
    const int s = x ? crypto_aead_xchacha20poly1305_ietf_decrypt(sout.data(), &slen, nullptr, joined.data(), joined.size(), ad.data(), ad.size(), n24.data(), key.data())
                    : crypto_aead_chacha20poly1305_ietf_decrypt(sout.data(), &slen, nullptr, joined.data(), joined.size(), ad.data(), ad.size(), n12.data(), key.data());
    if (o != (s == 0))
        f::divergence(T, std::string("open verdict (ours ") + (o ? "valid" : "invalid") + "), mode " + std::to_string(mode));
    if (o && !std::equal(out.begin(), out.end(), sout.begin()))
        f::divergence(T, "open plaintext");
    return 0;
}

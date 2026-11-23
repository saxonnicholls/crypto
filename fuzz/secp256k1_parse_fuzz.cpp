//
//  secp256k1_parse_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of the secp256k1 decoders on arbitrary bytes, against libsecp256k1 and OpenSSL: SEC1
//  public keys (libsecp256k1's stated rule: it also reads the hybrid 0x06 / 0x07 form, which this library
//  refuses), DER signatures (libsecp256k1 reads a negative or overflowing INTEGER as zero; OpenSSL refuses what
//  does not re-encode to itself; this library refuses negative integers and any above 2^256), and BIP-340 x-only
//  keys.
//
#include "support/fuzz_support.hpp"
#include "support/openssl_oracle.hpp"

#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/secp256k1/schnorr.hpp>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

namespace f = snicholls::crypto::fuzz;
using namespace snicholls::crypto::secp256k1;

static secp256k1_context* ctx()
{
    static secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return c;
}

// This library's DER integer rule, and libsecp256k1's reading of the same bytes (BIP-66's structure is common)
struct der_view {
    bool structure = false;
    std::span<const std::uint8_t> r, s;
};

static der_view der_structure(std::span<const std::uint8_t> d)
{
    der_view v;
    const std::size_t n = d.size();
    if (n < 8 || n > 72 || d[0] != 0x30 || d[1] != n - 2 || d[2] != 0x02)
        return v;
    const std::size_t lr = d[3];
    if (lr == 0 || 5 + lr >= n || d[4 + lr] != 0x02)
        return v;
    const std::size_t ls = d[5 + lr];
    if (ls == 0 || lr + ls + 6 != n)
        return v;
    v.structure = true;
    v.r = d.subspan(4, lr);
    v.s = d.subspan(6 + lr, ls);
    return v;
}

static bool padded(std::span<const std::uint8_t> v)
{
    return v.size() > 1 && ((v[0] == 0 && !(v[1] & 0x80)) || (v[0] == 0xff && (v[1] & 0x80)));
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("secp256k1_parse", data, size);
    const char* T = "secp256k1_parse";
    const std::span<const std::uint8_t> bytes(data, size);

    // SEC1
    {
        const auto ours = public_key::parse(bytes);
        secp256k1_pubkey pk;
        const bool lib = secp256k1_ec_pubkey_parse(ctx(), &pk, data, size) == 1;
        const bool hybrid = size == 65 && (data[0] == 6 || data[0] == 7);
        if (static_cast<bool>(ours) != lib && !(hybrid && lib && !ours))
            f::divergence(T, "SEC1 " + f::hex(bytes));
        if (ours && lib) {
            std::array<std::uint8_t, 33> c{};
            std::size_t n = 33;
            secp256k1_ec_pubkey_serialize(ctx(), c.data(), &n, &pk, SECP256K1_EC_COMPRESSED);
            if (ours->compressed() != c)
                f::divergence(T, "SEC1 key read differently " + f::hex(bytes));
        }
    }

    // DER
    {
        const auto ours = signature::from_der(bytes);
        secp256k1_ecdsa_signature ls;
        const bool lib = secp256k1_ecdsa_signature_parse_der(ctx(), &ls, data, size) == 1;
        const auto v = der_structure(bytes);
        const bool negative = v.structure && ((v.r[0] & 0x80) || (v.s[0] & 0x80));
        const bool wide = v.structure && ((v.r.size() == 33 && v.r[0]) || v.r.size() > 33 || (v.s.size() == 33 && v.s[0]) ||
                                          v.s.size() > 33);
        if (ours && !lib)
            f::divergence(T, "DER read here, refused by libsecp256k1: " + f::hex(bytes));
        if (lib && !ours && !(negative || wide))
            f::divergence(T, "DER refused here, read by libsecp256k1 for no stated reason: " + f::hex(bytes));
        if (v.structure && (padded(v.r) || padded(v.s)) && (ours || lib))
            f::divergence(T, "a padded DER integer was read: " + f::hex(bytes));
        if (ours && lib) {
            std::array<std::uint8_t, 64> c{};
            secp256k1_ecdsa_signature_serialize_compact(ctx(), c.data(), &ls);
            // libsecp256k1 reads an integer at or above n as zero (its stated rule); below n both read the integer
            const auto n = f::secp256k1_edge(3);
            auto below_n = [&](const std::array<std::uint8_t, 32>& x) { return std::lexicographical_compare(x.begin(), x.end(), n.begin(), n.end()); };
            std::array<std::uint8_t, 32> want_r = below_n(ours->r) ? ours->r : std::array<std::uint8_t, 32>{};
            std::array<std::uint8_t, 32> want_s = below_n(ours->s) ? ours->s : std::array<std::uint8_t, 32>{};
            if (!std::equal(want_r.begin(), want_r.end(), c.begin()) || !std::equal(want_s.begin(), want_s.end(), c.begin() + 32))
                f::divergence(T, "DER read differently: " + f::hex(bytes));
        }
        const bool strict = f::openssl::der_is_canonical(bytes);
        if (ours && !strict)
            f::divergence(T, "DER read here that OpenSSL does not re-encode: " + f::hex(bytes));
        if (strict && !ours && !(negative || wide))
            f::divergence(T, "canonical DER (OpenSSL) refused here for no stated reason: " + f::hex(bytes));
    }

    // BIP-340 x-only keys: whether 32 bytes are a key, as schnorr_verify's first step and libsecp256k1 decide
    if (size >= 32) {
        secp256k1_xonly_pubkey x;
        const bool lib = secp256k1_xonly_pubkey_parse(ctx(), &x, data) == 1;
        xonly_public_key key;
        std::copy(data, data + 32, key.bytes.begin());
        schnorr_signature sig;
        const auto r = schnorr_verify(key, {}, sig);
        const bool ours_key = r || r.unwrap_err() != snicholls::crypto::errc::invalid_public_key;
        if (ours_key != lib)
            f::divergence(T, "x-only key validity " + f::hex(bytes.first(32)));
    }
    return 0;
}

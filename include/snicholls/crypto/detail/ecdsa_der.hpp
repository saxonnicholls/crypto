//
//  ecdsa_der.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The DER form of an ECDSA signature, SEQUENCE { r INTEGER, s INTEGER } (SEC 1, X.509, JOSE's counterpart is
//  r || s), for a group of L-byte scalars (32: secp256k1 and P-256; 48: P-384): the encoding, and a strict decoding
//  (BIP-66's rules: minimal lengths and integers, non-negative, at most 8 L bits, nothing trailing). Range checks
//  against the group order are the caller's.
//
//  Variable time; public data only (a signature is public). constexpr, no allocation.
//

#ifndef snicholls_crypto_detail_ecdsa_der_hpp
#define snicholls_crypto_detail_ecdsa_der_hpp

#include <snicholls/core/containers/inplace_vector.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace snicholls::crypto::detail {

// The DER of an L-byte group's signature: at most 2 + 2 (2 + 1 + L) bytes (72 for 256 bits, 104 for 384)
template <std::size_t L>
using der_signature_n = containers::inplace_vector<std::uint8_t, 6 + 2 * (L + 1)>;

using der_signature = der_signature_n<32>;

// SEQUENCE { INTEGER r, INTEGER s }: each integer minimal, with a zero byte before a first byte whose top bit is set.
// Each is appended straight from r or s (copying through intermediate vectors makes GCC 15 at -O3 with AVX2 report a
// false -Wstringop-overflow); nothing can find the result full. The length fits one byte (at most 102 here)
template <std::size_t L>
constexpr der_signature_n<L> ecdsa_der_encode_n(const std::array<std::uint8_t, L>& r, const std::array<std::uint8_t, L>& s) noexcept
{
    static_assert(6 + 2 * (L + 1) - 2 < 128, "the SEQUENCE's length is one byte");
    der_signature_n<L> out;
    auto integer = [&out](const std::array<std::uint8_t, L>& v) {
        std::size_t i = 0;
        while (i < L - 1 && v[i] == 0)
            ++i;
        const std::size_t sign = v[i] >> 7;
        (void)out.try_push_back(0x02);
        (void)out.try_push_back(static_cast<std::uint8_t>(sign + L - i));
        if (sign != 0)
            (void)out.try_push_back(0);
        for (; i < L; ++i)
            (void)out.try_push_back(v[i]);
    };
    (void)out.try_push_back(0x30);
    (void)out.try_push_back(0);
    integer(r);
    integer(s);
    out[1] = static_cast<std::uint8_t>(out.size() - 2);
    return out;
}

constexpr der_signature ecdsa_der_encode(const std::array<std::uint8_t, 32>& r, const std::array<std::uint8_t, 32>& s) noexcept
{
    return ecdsa_der_encode_n<32>(r, s);
}

// The strict reading: r and s as L big-endian bytes, or std::nullopt for anything but DER of two non-negative
// integers below 2^(8 L)
template <std::size_t L>
constexpr std::optional<std::pair<std::array<std::uint8_t, L>, std::array<std::uint8_t, L>>>
ecdsa_der_decode_n(std::span<const std::uint8_t> der) noexcept
{
    const std::size_t n = der.size();
    if (n < 8 || n > 6 + 2 * (L + 1) || der[0] != 0x30 || der[1] != n - 2 || der[2] != 0x02)
        return std::nullopt;
    const std::size_t len_r = der[3];
    if (len_r == 0 || 5 + len_r >= n || der[4 + len_r] != 0x02)
        return std::nullopt;
    const std::size_t len_s = der[5 + len_r];
    if (len_s == 0 || len_r + len_s + 6 != n)
        return std::nullopt;
    std::array<std::uint8_t, L> r{}, s{};
    auto integer = [](std::span<const std::uint8_t> v, std::array<std::uint8_t, L>& out) {
        if (v[0] & 0x80)
            return false;   // negative
        if (v.size() > 1 && v[0] == 0 && !(v[1] & 0x80))
            return false;   // padding beyond the sign byte
        if (v.size() > L + 1 || (v.size() == L + 1 && v[0] != 0))
            return false;   // more than 8 L bits
        const std::size_t skip = v.size() == L + 1 ? 1 : 0;
        const std::size_t pad = L - (v.size() - skip);
        for (std::size_t i = 0; i < v.size() - skip; ++i)
            out[pad + i] = v[skip + i];
        return true;
    };
    if (!integer(der.subspan(4, len_r), r) || !integer(der.subspan(6 + len_r, len_s), s))
        return std::nullopt;
    return std::pair{r, s};
}

constexpr std::optional<std::pair<std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>>>
ecdsa_der_decode(std::span<const std::uint8_t> der) noexcept
{
    return ecdsa_der_decode_n<32>(der);
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_ecdsa_der_hpp */

//
//  ecdsa_der.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The DER form of an ECDSA signature over a 256-bit group, SEQUENCE { r INTEGER, s INTEGER } (SEC 1, X.509, JOSE's
//  counterpart is r || s): the encoding, and a strict decoding (BIP-66's rules: minimal lengths and integers,
//  non-negative, at most 256 bits, nothing trailing). Range checks against the group order are the caller's.
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

using der_signature = containers::inplace_vector<std::uint8_t, 72>;

// SEQUENCE { INTEGER r, INTEGER s }: each integer minimal, with a zero byte before a first byte whose top bit is set.
// Each is appended straight from r or s (copying through intermediate vectors makes GCC 15 at -O3 with AVX2 report a
// false -Wstringop-overflow); nothing can find the result full: 2 + 35 + 35 bytes at most
constexpr der_signature ecdsa_der_encode(const std::array<std::uint8_t, 32>& r, const std::array<std::uint8_t, 32>& s) noexcept
{
    der_signature out;
    auto integer = [&out](const std::array<std::uint8_t, 32>& v) {
        std::size_t i = 0;
        while (i < 31 && v[i] == 0)
            ++i;
        const std::size_t sign = v[i] >> 7;
        (void)out.try_push_back(0x02);
        (void)out.try_push_back(static_cast<std::uint8_t>(sign + 32 - i));
        if (sign != 0)
            (void)out.try_push_back(0);
        for (; i < 32; ++i)
            (void)out.try_push_back(v[i]);
    };
    (void)out.try_push_back(0x30);
    (void)out.try_push_back(0);
    integer(r);
    integer(s);
    out[1] = static_cast<std::uint8_t>(out.size() - 2);
    return out;
}

// The strict reading: r and s as 32 big-endian bytes, or std::nullopt for anything but DER of two non-negative
// integers below 2^256
constexpr std::optional<std::pair<std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>>>
ecdsa_der_decode(std::span<const std::uint8_t> der) noexcept
{
    const std::size_t n = der.size();
    if (n < 8 || n > 72 || der[0] != 0x30 || der[1] != n - 2 || der[2] != 0x02)
        return std::nullopt;
    const std::size_t len_r = der[3];
    if (len_r == 0 || 5 + len_r >= n || der[4 + len_r] != 0x02)
        return std::nullopt;
    const std::size_t len_s = der[5 + len_r];
    if (len_s == 0 || len_r + len_s + 6 != n)
        return std::nullopt;
    std::array<std::uint8_t, 32> r{}, s{};
    auto integer = [](std::span<const std::uint8_t> v, std::array<std::uint8_t, 32>& out) {
        if (v[0] & 0x80)
            return false;   // negative
        if (v.size() > 1 && v[0] == 0 && !(v[1] & 0x80))
            return false;   // padding beyond the sign byte
        if (v.size() > 33 || (v.size() == 33 && v[0] != 0))
            return false;   // more than 256 bits
        const std::size_t skip = v.size() == 33 ? 1 : 0;
        const std::size_t pad = 32 - (v.size() - skip);
        for (std::size_t i = 0; i < v.size() - skip; ++i)
            out[pad + i] = v[skip + i];
        return true;
    };
    if (!integer(der.subspan(4, len_r), r) || !integer(der.subspan(6 + len_r, len_s), s))
        return std::nullopt;
    return std::pair{r, s};
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_ecdsa_der_hpp */

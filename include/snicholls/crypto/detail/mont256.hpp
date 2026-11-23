//
//  mont256.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Arithmetic modulo a 256-bit odd modulus in Montgomery form, on four 64-bit limbs, for moduli that are not of the
//  form 2^256 - c with a small c (P-256's p and n). Values are kept fully reduced, below m, as a R mod m with
//  R = 2^256.
//
//  Constant time throughout: every loop has a fixed trip count, the final subtraction of each operation is selected
//  by a mask, never a branch, and the exponentiations take a public exponent (Fermat's inverse, the square root).
//  constexpr throughout; the 64 x 64 -> 128 multiply is core's.
//

#ifndef snicholls_crypto_detail_mont256_hpp
#define snicholls_crypto_detail_mont256_hpp

#include <snicholls/core/detail/wide_mul.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/limbs.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace snicholls::crypto::detail {

// A modulus m and its constants: m0 = -m^-1 mod 2^64, r2 = R^2 mod m, one = R mod m
struct mont256_params {
    limbs4 m{};
    std::uint64_t m0 = 0;
    limbs4 r2{};
    limbs4 one{};
};

// The constants of an odd modulus, computed once (at compile time for the curve's constants)
constexpr mont256_params make_mont256(const limbs4& m) noexcept
{
    mont256_params p;
    p.m = m;
    std::uint64_t inv = 1;
    for (int i = 0; i < 6; ++i)
        inv *= 2 - m[0] * inv;
    p.m0 = ~inv + 1;
    // R mod m and R^2 mod m by doubling 1, 256 and 512 times, each step reduced (public constants: variable time)
    limbs4 x{1, 0, 0, 0};
    for (int i = 0; i < 512; ++i) {
        const std::uint64_t top = x[3] >> 63;
        x = {x[0] << 1, (x[1] << 1) | (x[0] >> 63), (x[2] << 1) | (x[1] >> 63), (x[3] << 1) | (x[2] >> 63)};
        limbs4 t{};
        const std::uint64_t borrow = sub4(t, x, m);
        if (top || !borrow)
            x = t;
        if (i == 255)
            p.one = x;
    }
    p.r2 = x;
    return p;
}

// a - m if a >= m (with carry the 257th bit of a), in constant time
constexpr limbs4 mont256_reduce_once(const limbs4& a, std::uint64_t carry, const limbs4& m) noexcept
{
    limbs4 t{};
    const std::uint64_t borrow = sub4(t, a, m);
    // keep a when it was below m: no carry in and a borrow out
    const std::uint64_t keep = ct::mask_from_bit(borrow & (carry ^ 1));
    return select4(keep, a, t);
}

// a b R^-1 mod m, for a, b < m: CIOS with a constant-time final subtraction
constexpr limbs4 mont256_mul(const limbs4& a, const limbs4& b, const mont256_params& p) noexcept
{
    std::array<std::uint64_t, 6> t{};
    for (std::size_t i = 0; i < 4; ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const auto prod = snicholls::detail::umul128(a[j], b[i]);
            std::uint64_t lo = prod.low, hi = prod.high, c = 0;
            lo = add_carry(lo, t[j], c);
            hi += c;
            c = 0;
            lo = add_carry(lo, carry, c);
            hi += c;
            t[j] = lo;
            carry = hi;
        }
        std::uint64_t c = 0;
        t[4] = add_carry(t[4], carry, c);
        t[5] = c;
        const std::uint64_t q = t[0] * p.m0;
        carry = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const auto prod = snicholls::detail::umul128(q, p.m[j]);
            std::uint64_t lo = prod.low, hi = prod.high;
            c = 0;
            lo = add_carry(lo, t[j], c);
            hi += c;
            c = 0;
            lo = add_carry(lo, carry, c);
            hi += c;
            if (j > 0)
                t[j - 1] = lo;
            carry = hi;
        }
        c = 0;
        t[3] = add_carry(t[4], carry, c);
        t[4] = t[5] + c;
    }
    return mont256_reduce_once({t[0], t[1], t[2], t[3]}, t[4], p.m);
}

constexpr limbs4 mont256_add(const limbs4& a, const limbs4& b, const mont256_params& p) noexcept
{
    limbs4 s{};
    const std::uint64_t carry = add4(s, a, b);
    return mont256_reduce_once(s, carry, p.m);
}

constexpr limbs4 mont256_sub(const limbs4& a, const limbs4& b, const mont256_params& p) noexcept
{
    limbs4 d{};
    const std::uint64_t borrow = sub4(d, a, b);
    limbs4 back{};
    add4(back, d, p.m);
    return select4(ct::mask_from_bit(borrow), back, d);
}

constexpr limbs4 mont256_to(const limbs4& a, const mont256_params& p) noexcept { return mont256_mul(a, p.r2, p); }

constexpr limbs4 mont256_from(const limbs4& a, const mont256_params& p) noexcept { return mont256_mul(a, {1, 0, 0, 0}, p); }

// a^e for a public exponent e (both in and out of Montgomery form as a is): square and multiply, every bit squared
constexpr limbs4 mont256_pow(const limbs4& a, const limbs4& e, const mont256_params& p) noexcept
{
    limbs4 r = p.one;
    for (std::size_t i = 256; i-- > 0;) {
        r = mont256_mul(r, r, p);
        if ((e[i / 64] >> (i % 64)) & 1)   // the exponent is public
            r = mont256_mul(r, a, p);
    }
    return r;
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_mont256_hpp */

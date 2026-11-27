//
//  mont.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Arithmetic modulo an odd modulus of N 64-bit limbs in Montgomery form (R = 2^(64 N)), for moduli that are not of
//  the form 2^k - c with a small c: P-256's p and n (N = 4, mont256.hpp's names) and P-384's (N = 6). Values are kept
//  fully reduced, below m, as a R mod m.
//
//  Constant time throughout: every loop has a fixed trip count, the final subtraction of each operation is selected
//  by a mask, never a branch, and mont_pow takes a public exponent (Fermat's inverse, the square root). For RSA's
//  private operation, where the modulus (a prime factor) and the exponent are secret, make_mont_ct computes the
//  constants without a branch on the modulus and mont_pow_ct is a fixed 4-bit window whose table is scanned whole.
//  constexpr throughout; the 64 x 64 -> 128 multiply is core's.
//

#ifndef snicholls_crypto_detail_mont_hpp
#define snicholls_crypto_detail_mont_hpp

#include <snicholls/core/detail/wide_mul.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/limbs.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace snicholls::crypto::detail {

template <std::size_t N>
using limbs_n = std::array<std::uint64_t, N>;

// r = a + b mod 2^(64 N); returns the carry out
template <std::size_t N>
constexpr std::uint64_t add_n(limbs_n<N>& r, const limbs_n<N>& a, const limbs_n<N>& b) noexcept
{
    std::uint64_t c = 0;
    for (std::size_t i = 0; i < N; ++i)
        r[i] = add_carry(a[i], b[i], c);
    return c;
}

// r = a - b mod 2^(64 N); returns the borrow out
template <std::size_t N>
constexpr std::uint64_t sub_n(limbs_n<N>& r, const limbs_n<N>& a, const limbs_n<N>& b) noexcept
{
    std::uint64_t c = 0;
    for (std::size_t i = 0; i < N; ++i)
        r[i] = sub_borrow(a[i], b[i], c);
    return c;
}

template <std::size_t N>
constexpr limbs_n<N> select_n(std::uint64_t mask, const limbs_n<N>& a, const limbs_n<N>& b) noexcept
{
    limbs_n<N> r{};
    for (std::size_t i = 0; i < N; ++i)
        r[i] = ct::select(mask, a[i], b[i]);
    return r;
}

template <std::size_t N>
constexpr std::uint64_t mask_is_zero_n(const limbs_n<N>& a) noexcept
{
    std::uint64_t x = 0;
    for (std::size_t i = 0; i < N; ++i)
        x |= a[i];
    return ct::mask_is_zero(x);
}

template <std::size_t N>
constexpr std::uint64_t mask_equal_n(const limbs_n<N>& a, const limbs_n<N>& b) noexcept
{
    std::uint64_t x = 0;
    for (std::size_t i = 0; i < N; ++i)
        x |= a[i] ^ b[i];
    return ct::mask_is_zero(x);
}

// 8 N big-endian bytes to limbs and back
template <std::size_t N>
constexpr limbs_n<N> from_be_n(std::span<const std::uint8_t, 8 * N> b) noexcept
{
    limbs_n<N> r{};
    for (std::size_t i = 0; i < N; ++i) {
        std::uint64_t x = 0;
        for (std::size_t j = 0; j < 8; ++j)
            x = (x << 8) | b[8 * i + j];
        r[N - 1 - i] = x;
    }
    return r;
}

template <std::size_t N>
constexpr std::array<std::uint8_t, 8 * N> to_be_n(const limbs_n<N>& a) noexcept
{
    std::array<std::uint8_t, 8 * N> b{};
    for (std::size_t i = 0; i < N; ++i)
        for (std::size_t j = 0; j < 8; ++j)
            b[8 * i + j] = static_cast<std::uint8_t>(a[N - 1 - i] >> (56 - 8 * j));
    return b;
}

// A modulus m and its constants: m0 = -m^-1 mod 2^64, r2 = R^2 mod m, one = R mod m
template <std::size_t N>
struct mont_params {
    limbs_n<N> m{};
    std::uint64_t m0 = 0;
    limbs_n<N> r2{};
    limbs_n<N> one{};
};

// The constants of an odd modulus, computed once (at compile time for the curves' constants)
template <std::size_t N>
constexpr mont_params<N> make_mont(const limbs_n<N>& m) noexcept
{
    mont_params<N> p;
    p.m = m;
    std::uint64_t inv = 1;
    for (int i = 0; i < 6; ++i)
        inv *= 2 - m[0] * inv;
    p.m0 = ~inv + 1;
    // R mod m and R^2 mod m by doubling 1, 64 N and 128 N times, each step reduced (public constants: variable time)
    limbs_n<N> x{};
    x[0] = 1;
    for (std::size_t i = 0; i < 128 * N; ++i) {
        const std::uint64_t top = x[N - 1] >> 63;
        for (std::size_t j = N; j-- > 1;)
            x[j] = (x[j] << 1) | (x[j - 1] >> 63);
        x[0] <<= 1;
        limbs_n<N> t{};
        const std::uint64_t borrow = sub_n<N>(t, x, m);
        if (top || !borrow)
            x = t;
        if (i == 64 * N - 1)
            p.one = x;
    }
    p.r2 = x;
    return p;
}

// a - m if a >= m (with carry the bit above a), in constant time
template <std::size_t N>
constexpr limbs_n<N> mont_reduce_once(const limbs_n<N>& a, std::uint64_t carry, const limbs_n<N>& m) noexcept
{
    limbs_n<N> t{};
    const std::uint64_t borrow = sub_n<N>(t, a, m);
    // keep a when it was below m: no carry in and a borrow out
    const std::uint64_t keep = ct::mask_from_bit(borrow & (carry ^ 1));
    return select_n<N>(keep, a, t);
}

// a b R^-1 mod m, for a, b < m: CIOS with a constant-time final subtraction
template <std::size_t N>
constexpr limbs_n<N> mont_mul(const limbs_n<N>& a, const limbs_n<N>& b, const mont_params<N>& p) noexcept
{
    std::array<std::uint64_t, N + 2> t{};
    for (std::size_t i = 0; i < N; ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < N; ++j) {
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
        t[N] = add_carry(t[N], carry, c);
        t[N + 1] = c;
        const std::uint64_t q = t[0] * p.m0;
        carry = 0;
        for (std::size_t j = 0; j < N; ++j) {
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
        t[N - 1] = add_carry(t[N], carry, c);
        t[N] = t[N + 1] + c;
    }
    limbs_n<N> r{};
    for (std::size_t i = 0; i < N; ++i)
        r[i] = t[i];
    return mont_reduce_once<N>(r, t[N], p.m);
}

template <std::size_t N>
constexpr limbs_n<N> mont_add(const limbs_n<N>& a, const limbs_n<N>& b, const mont_params<N>& p) noexcept
{
    limbs_n<N> s{};
    const std::uint64_t carry = add_n<N>(s, a, b);
    return mont_reduce_once<N>(s, carry, p.m);
}

template <std::size_t N>
constexpr limbs_n<N> mont_sub(const limbs_n<N>& a, const limbs_n<N>& b, const mont_params<N>& p) noexcept
{
    limbs_n<N> d{};
    const std::uint64_t borrow = sub_n<N>(d, a, b);
    limbs_n<N> back{};
    add_n<N>(back, d, p.m);
    return select_n<N>(ct::mask_from_bit(borrow), back, d);
}

template <std::size_t N>
constexpr limbs_n<N> mont_to(const limbs_n<N>& a, const mont_params<N>& p) noexcept
{
    return mont_mul<N>(a, p.r2, p);
}

template <std::size_t N>
constexpr limbs_n<N> mont_from(const limbs_n<N>& a, const mont_params<N>& p) noexcept
{
    limbs_n<N> one{};
    one[0] = 1;
    return mont_mul<N>(a, one, p);
}

// The constants of a secret odd modulus (an RSA prime): as make_mont, each doubling reduced by a masked subtraction
template <std::size_t N>
constexpr mont_params<N> make_mont_ct(const limbs_n<N>& m) noexcept
{
    mont_params<N> p;
    p.m = m;
    std::uint64_t inv = 1;
    for (int i = 0; i < 6; ++i)
        inv *= 2 - m[0] * inv;
    p.m0 = ~inv + 1;
    limbs_n<N> x{};
    x[0] = 1;
    for (std::size_t i = 0; i < 128 * N; ++i) {   // x < m before each step, so 2 x < 2 m: one subtraction reduces it
        const std::uint64_t top = x[N - 1] >> 63;
        for (std::size_t j = N; j-- > 1;)
            x[j] = (x[j] << 1) | (x[j - 1] >> 63);
        x[0] <<= 1;
        x = mont_reduce_once<N>(x, top, m);
        if (i == 64 * N - 1)   // the position is public
            p.one = x;
    }
    p.r2 = x;
    secure_wipe(x);
    return p;
}

// a^e for a secret exponent e of 64 N bits (a in and out of Montgomery form): a fixed 4-bit window, four squarings and
// one multiplication for every nibble whatever its value, the table entry read by a masked scan of all 16
template <std::size_t N>
constexpr limbs_n<N> mont_pow_ct(const limbs_n<N>& a, const limbs_n<N>& e, const mont_params<N>& p) noexcept
{
    std::array<limbs_n<N>, 16> table{};
    table[0] = p.one;
    for (std::size_t j = 1; j < 16; ++j)
        table[j] = mont_mul<N>(table[j - 1], a, p);
    limbs_n<N> r = p.one;
    for (std::size_t i = 16 * N; i-- > 0;) {
        for (int k = 0; k < 4; ++k)
            r = mont_mul<N>(r, r, p);
        const std::uint64_t nib = (e[i / 16] >> (4 * (i % 16))) & 0xf;
        limbs_n<N> t{};
        for (std::size_t j = 0; j < 16; ++j)
            t = select_n<N>(ct::mask_equal(j, nib), table[j], t);
        r = mont_mul<N>(r, t, p);
        secure_wipe(t);
    }
    secure_wipe(table);
    return r;
}

// a^e for a public exponent e (both in and out of Montgomery form as a is): square and multiply, every bit squared
template <std::size_t N>
constexpr limbs_n<N> mont_pow(const limbs_n<N>& a, const limbs_n<N>& e, const mont_params<N>& p) noexcept
{
    limbs_n<N> r = p.one;
    for (std::size_t i = 64 * N; i-- > 0;) {
        r = mont_mul<N>(r, r, p);
        if ((e[i / 64] >> (i % 64)) & 1)   // the exponent is public
            r = mont_mul<N>(r, a, p);
    }
    return r;
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_mont_hpp */

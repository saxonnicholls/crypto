//
//  limbs.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  256-bit arithmetic on four 64-bit limbs, least significant first, for moduli of the form m = 2^256 - c with a
//  small c (secp256k1's p, c = 2^32 + 977, one limb; its group order n, c < 2^129, three limbs).
//
//  Constant time throughout: every loop has a fixed trip count, every carry is computed with arithmetic (the
//  comparisons compile to setb / adc, never to a branch), and every reduction runs the same number of passes
//  whatever the value. Values are kept fully reduced, below m, between operations.
//
//  constexpr throughout. The 64 x 64 -> 128 multiply is core's (one instruction at run time on GCC and Clang).
//

#ifndef snicholls_crypto_detail_limbs_hpp
#define snicholls_crypto_detail_limbs_hpp

#include <snicholls/core/detail/wide_mul.hpp>
#include <snicholls/crypto/constant_time.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace snicholls::crypto::detail {

using limbs4 = std::array<std::uint64_t, 4>;
using limbs8 = std::array<std::uint64_t, 8>;

// a + b + carry; carry in and out is 0 or 1
constexpr std::uint64_t add_carry(std::uint64_t a, std::uint64_t b, std::uint64_t& carry) noexcept
{
    const std::uint64_t s = a + b;
    const std::uint64_t c1 = s < a;
    const std::uint64_t t = s + carry;
    const std::uint64_t c2 = t < s;
    carry = c1 | c2;
    return t;
}

// a - b - borrow; borrow in and out is 0 or 1
constexpr std::uint64_t sub_borrow(std::uint64_t a, std::uint64_t b, std::uint64_t& borrow) noexcept
{
    const std::uint64_t d = a - b;
    const std::uint64_t b1 = a < b;
    const std::uint64_t t = d - borrow;
    const std::uint64_t b2 = d < borrow;
    borrow = b1 | b2;
    return t;
}

// r = a + b mod 2^256; returns the carry out
constexpr std::uint64_t add4(limbs4& r, const limbs4& a, const limbs4& b) noexcept
{
    std::uint64_t c = 0;
    for (std::size_t i = 0; i < 4; ++i)
        r[i] = add_carry(a[i], b[i], c);
    return c;
}

// r = a - b mod 2^256; returns the borrow out
constexpr std::uint64_t sub4(limbs4& r, const limbs4& a, const limbs4& b) noexcept
{
    std::uint64_t c = 0;
    for (std::size_t i = 0; i < 4; ++i)
        r[i] = sub_borrow(a[i], b[i], c);
    return c;
}

// The full 512-bit product
constexpr limbs8 mul4(const limbs4& a, const limbs4& b) noexcept
{
    limbs8 r{};
    for (std::size_t i = 0; i < 4; ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const auto p = snicholls::detail::umul128(a[i], b[j]);
            std::uint64_t lo = p.low, hi = p.high, c = 0;
            lo = add_carry(lo, r[i + j], c);
            hi += c;
            c = 0;
            lo = add_carry(lo, carry, c);
            hi += c;
            r[i + j] = lo;
            carry = hi;
        }
        r[i + 4] = carry;
    }
    return r;
}

constexpr limbs4 select4(std::uint64_t mask, const limbs4& a, const limbs4& b) noexcept
{
    limbs4 r{};
    for (std::size_t i = 0; i < 4; ++i)
        r[i] = ct::select(mask, a[i], b[i]);
    return r;
}

constexpr std::uint64_t mask_is_zero4(const limbs4& a) noexcept { return ct::mask_is_zero(a[0] | a[1] | a[2] | a[3]); }

constexpr std::uint64_t mask_equal4(const limbs4& a, const limbs4& b) noexcept
{
    return ct::mask_is_zero((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]));
}

// All ones if a < b
constexpr std::uint64_t mask_less4(const limbs4& a, const limbs4& b) noexcept
{
    limbs4 t{};
    return ct::mask_from_bit(sub4(t, a, b));
}

// A modulus m = 2^256 - c, with c in NC limbs
template <std::size_t NC>
struct pseudo_mersenne {
    limbs4 m;                            // the modulus
    std::array<std::uint64_t, NC> c;     // 2^256 - m
    limbs4 c4;                           // c as four limbs
};

// x = lo(x) + hi(x) * c, one folding pass: the product row hi * c, then one carry chain over all eight limbs
template <std::size_t NC>
constexpr void fold(limbs8& x, const pseudo_mersenne<NC>& mod) noexcept
{
    limbs8 row{};   // hi(x) * c, at most 4 + NC limbs
    for (std::size_t i = 0; i < 4; ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < NC; ++j) {
            const auto p = snicholls::detail::umul128(x[4 + i], mod.c[j]);
            std::uint64_t lo = p.low, hi = p.high, c = 0;
            lo = add_carry(lo, row[i + j], c);
            hi += c;
            c = 0;
            lo = add_carry(lo, carry, c);
            hi += c;
            row[i + j] = lo;
            carry = hi;
        }
        row[i + NC] = carry;
    }
    std::uint64_t carry = 0;
    for (std::size_t k = 0; k < 8; ++k)
        x[k] = add_carry(k < 4 ? x[k] : 0, row[k], carry);
}

// x mod m for any 512-bit x: four folds (enough for c < 2^130, as analysed for both secp256k1 moduli), then one
// conditional subtraction, both always run
template <std::size_t NC>
constexpr limbs4 reduce8(limbs8 x, const pseudo_mersenne<NC>& mod) noexcept
{
    fold(x, mod);
    fold(x, mod);
    fold(x, mod);
    fold(x, mod);
    const limbs4 v{x[0], x[1], x[2], x[3]};
    limbs4 t{};
    const std::uint64_t ge = add4(t, v, mod.c4);   // v + c overflows exactly when v >= m; then t = v - m
    return select4(ct::mask_from_bit(ge), t, v);
}

// (a + b) mod m, for a, b < m
template <std::size_t NC>
constexpr limbs4 mod_add(const limbs4& a, const limbs4& b, const pseudo_mersenne<NC>& mod) noexcept
{
    limbs4 s{}, t{};
    const std::uint64_t c1 = add4(s, a, b);
    const std::uint64_t c2 = add4(t, s, mod.c4);
    return select4(ct::mask_from_bit(c1 | c2), t, s);
}

// (a - b) mod m, for a, b < m
template <std::size_t NC>
constexpr limbs4 mod_sub(const limbs4& a, const limbs4& b, const pseudo_mersenne<NC>& mod) noexcept
{
    limbs4 d{}, t{};
    const std::uint64_t borrow = sub4(d, a, b);
    sub4(t, d, mod.c4);   // d + m mod 2^256
    return select4(ct::mask_from_bit(borrow), t, d);
}

template <std::size_t NC>
constexpr limbs4 mod_mul(const limbs4& a, const limbs4& b, const pseudo_mersenne<NC>& mod) noexcept
{
    return reduce8(mul4(a, b), mod);
}

// a^e mod m. The exponent is public (p - 2, n - 2, (p + 1) / 4): branching on its bits leaks nothing about a.
// A 4-bit fixed window: 14 multiplications for the table, then four squarings and at most one multiplication per
// nibble.
template <std::size_t NC>
constexpr limbs4 mod_pow_public(const limbs4& a, const limbs4& e, const pseudo_mersenne<NC>& mod) noexcept
{
    std::array<limbs4, 16> t{};
    t[0] = {1, 0, 0, 0};
    t[1] = a;
    for (std::size_t j = 2; j < 16; ++j)
        t[j] = mod_mul(t[j - 1], a, mod);
    limbs4 r{1, 0, 0, 0};
    for (std::size_t i = 64; i-- > 0;) {
        if (i != 63) {
            r = mod_mul(r, r, mod);
            r = mod_mul(r, r, mod);
            r = mod_mul(r, r, mod);
            r = mod_mul(r, r, mod);
        }
        const std::uint64_t nib = (e[i / 16] >> (4 * (i % 16))) & 0xf;
        if (nib != 0)
            r = mod_mul(r, t[nib], mod);
    }
    return r;
}

// Big-endian bytes to limbs and back
constexpr limbs4 from_be(std::span<const std::uint8_t, 32> b) noexcept
{
    limbs4 r{};
    for (std::size_t i = 0; i < 4; ++i) {
        std::uint64_t x = 0;
        for (std::size_t j = 0; j < 8; ++j)
            x = (x << 8) | b[8 * i + j];
        r[3 - i] = x;
    }
    return r;
}

constexpr std::array<std::uint8_t, 32> to_be(const limbs4& a) noexcept
{
    std::array<std::uint8_t, 32> b{};
    for (std::size_t i = 0; i < 4; ++i)
        for (std::size_t j = 0; j < 8; ++j)
            b[8 * i + j] = static_cast<std::uint8_t>(a[3 - i] >> (56 - 8 * j));
    return b;
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_limbs_hpp */

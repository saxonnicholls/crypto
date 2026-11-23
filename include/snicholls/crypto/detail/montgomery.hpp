//
//  montgomery.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Arithmetic modulo an odd public modulus of up to 4096 bits, in Montgomery form, for RSA signature verification:
//  big-endian bytes to limbs and back, and s^e mod n with a public exponent below 2^64.
//
//  Variable time; public data only. Every input here is public (an RSA public key and a signature), so loops run
//  over the modulus's actual length and the exponent's bits decide multiplications. Nothing secret may be passed in.
//
//  No allocation: values are arrays of max_limbs 64-bit limbs, least significant first, of which the modulus's
//  length is used. constexpr throughout; the 64 x 64 -> 128 multiply is core's.
//

#ifndef snicholls_crypto_detail_montgomery_hpp
#define snicholls_crypto_detail_montgomery_hpp

#include <snicholls/core/detail/wide_mul.hpp>
#include <snicholls/crypto/detail/limbs.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace snicholls::crypto::detail {

inline constexpr std::size_t mont_max_limbs = 64;   // 4096 bits
using wide = std::array<std::uint64_t, mont_max_limbs>;

// Big-endian bytes to limbs; std::nullopt when the value does not fit max_limbs
constexpr std::optional<wide> wide_from_be(std::span<const std::uint8_t> b) noexcept
{
    std::size_t start = 0;
    while (start < b.size() && b[start] == 0)
        ++start;
    if (b.size() - start > mont_max_limbs * 8)
        return std::nullopt;
    wide out{};
    std::size_t bit = 0;
    for (std::size_t i = b.size(); i > start; --i, bit += 8)
        out[bit / 64] |= static_cast<std::uint64_t>(b[i - 1]) << (bit % 64);
    return out;
}

// Limbs to exactly out.size() big-endian bytes (the value must fit)
constexpr void wide_to_be(const wide& a, std::span<std::uint8_t> out) noexcept
{
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::size_t bit = 8 * (out.size() - 1 - i);
        out[i] = bit / 64 < mont_max_limbs ? static_cast<std::uint8_t>(a[bit / 64] >> (bit % 64)) : 0;
    }
}

// The number of significant bits
constexpr std::size_t wide_bits(const wide& a) noexcept
{
    for (std::size_t i = mont_max_limbs; i > 0; --i)
        if (a[i - 1] != 0) {
            std::size_t bits = 64 * (i - 1);
            for (std::uint64_t v = a[i - 1]; v != 0; v >>= 1)
                ++bits;
            return bits;
        }
    return 0;
}

// a < b, over the first k limbs
constexpr bool wide_less(const wide& a, const wide& b, std::size_t k) noexcept
{
    for (std::size_t i = k; i > 0; --i)
        if (a[i - 1] != b[i - 1])
            return a[i - 1] < b[i - 1];
    return false;
}

// a -= b over the first k limbs; the borrow out
constexpr std::uint64_t wide_sub(wide& a, const wide& b, std::size_t k) noexcept
{
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < k; ++i)
        a[i] = sub_borrow(a[i], b[i], borrow);
    return borrow;
}

// A modulus and its Montgomery constants: R = 2^(64 k), n0 = -n^-1 mod 2^64, r2 = R^2 mod n
class montgomery {
public:
    // std::nullopt when n is even, or below 3, or wider than max_limbs
    [[nodiscard]] static constexpr std::optional<montgomery> make(const wide& n) noexcept
    {
        const std::size_t bits = wide_bits(n);
        if (bits < 2 || (n[0] & 1) == 0)
            return std::nullopt;
        montgomery m;
        m.n_ = n;
        m.k_ = (bits + 63) / 64;
        // Newton's iteration for n[0]^-1 mod 2^64: each step doubles the correct low bits
        std::uint64_t inv = 1;
        for (int i = 0; i < 6; ++i)
            inv *= 2 - n[0] * inv;
        m.n0_ = ~inv + 1;
        // R^2 mod n by doubling 1, reduced at each step, 2 * 64 k times
        wide x{};
        x[0] = 1;
        for (std::size_t i = 0; i < 128 * m.k_; ++i)
            m.double_mod(x);
        m.r2_ = x;
        return m;
    }

    [[nodiscard]] constexpr const wide& modulus() const noexcept { return n_; }
    [[nodiscard]] constexpr std::size_t limbs() const noexcept { return k_; }

    // a b R^-1 mod n, for a, b < n (CIOS)
    [[nodiscard]] constexpr wide mul(const wide& a, const wide& b) const noexcept
    {
        std::array<std::uint64_t, mont_max_limbs + 2> t{};
        for (std::size_t i = 0; i < k_; ++i) {
            std::uint64_t carry = 0;
            for (std::size_t j = 0; j < k_; ++j)
                t[j] = mac(t[j], a[j], b[i], carry);
            std::uint64_t c = 0;
            t[k_] = add_carry(t[k_], carry, c);
            t[k_ + 1] = c;
            const std::uint64_t m = t[0] * n0_;
            carry = 0;
            (void)mac(t[0], m, n_[0], carry);
            for (std::size_t j = 1; j < k_; ++j)
                t[j - 1] = mac(t[j], m, n_[j], carry);
            c = 0;
            t[k_ - 1] = add_carry(t[k_], carry, c);
            t[k_] = t[k_ + 1] + c;
        }
        wide r{};
        for (std::size_t i = 0; i < k_; ++i)
            r[i] = t[i];
        if (t[k_] != 0 || !wide_less(r, n_, k_))
            wide_sub(r, n_, k_);
        return r;
    }

    // s^e mod n, for s < n and a public e
    [[nodiscard]] constexpr wide pow(const wide& s, std::uint64_t e) const noexcept
    {
        const wide sm = mul(s, r2_);   // s R mod n
        wide one{};
        one[0] = 1;
        wide acc = mul(one, r2_);      // R mod n
        bool started = false;
        for (int bit = 63; bit >= 0; --bit) {
            if (started)
                acc = mul(acc, acc);
            if ((e >> bit) & 1) {
                acc = started ? mul(acc, sm) : sm;
                started = true;
            }
        }
        return mul(acc, one);          // out of Montgomery form
    }

private:
    constexpr montgomery() noexcept = default;

    // t + a b + carry, the low word returned and the high word left in carry
    static constexpr std::uint64_t mac(std::uint64_t t, std::uint64_t a, std::uint64_t b, std::uint64_t& carry) noexcept
    {
        const auto p = snicholls::detail::umul128(a, b);
        std::uint64_t lo = p.low, hi = p.high, c = 0;
        lo = add_carry(lo, t, c);
        hi += c;
        c = 0;
        lo = add_carry(lo, carry, c);
        hi += c;
        carry = hi;
        return lo;
    }

    // x = 2 x mod n, for x < n
    constexpr void double_mod(wide& x) const noexcept
    {
        std::uint64_t top = 0;
        for (std::size_t i = 0; i < k_; ++i) {
            const std::uint64_t next = x[i] >> 63;
            x[i] = (x[i] << 1) | top;
            top = next;
        }
        if (top != 0 || !wide_less(x, n_, k_))
            wide_sub(x, n_, k_);
    }

    wide n_{};
    wide r2_{};
    std::size_t k_ = 0;
    std::uint64_t n0_ = 0;
};

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_montgomery_hpp */

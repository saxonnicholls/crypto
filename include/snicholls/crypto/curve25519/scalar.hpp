//
//  scalar.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `curve25519::scalar`: integers modulo L = 2^252 + 27742317777372353535851937790883648493, the order of
/// edwards25519's prime subgroup; constant-time and `constexpr`.
/// \ingroup curve25519
///
/// \overview
/// Ed25519's secret scalar, its nonce r, the challenge k and the signature's S. Stored as 32 little-endian bytes,
/// always below L. `reduce` takes a 64-byte hash to a scalar; `mul_add` computes S = k a + r; `is_canonical` is the
/// S < L check that keeps signatures from being malleable.
///
/// \relations
/// - `curve25519/edwards.hpp`: multiplies points by these.
/// - `curve25519/ed25519.hpp`: the user.
/// - Group: \ref curve25519.
///
/// \impls
/// One: the reduction works on 64 signed 64-bit digits of 8 bits each, folding the top digits down by L's low part
/// (the method TweetNaCl popularised), then a final carry pass; every loop has a fixed trip count.
///
/// \contracts
/// - Value type, trivially copyable, no allocation; every member `constexpr` and `noexcept`.
/// - `reduce`, `mul_add`, `from_bytes_reduced`: constant time in their arguments.
/// - `is_canonical` / `from_canonical`: constant time; `from_canonical` returns `std::nullopt` for S >= L (that branch
///   is on a public signature).
/// - A scalar holding a secret is wiped by its owner (`ed25519::key_pair` does); the type stays trivially copyable.
///
/// \errors
/// None: a non-canonical encoding is `std::nullopt`.
///
/// \examples
/// \snippet curve25519/scalar_demo.cpp scalar
///
/// \perf
/// Measured inside the Ed25519 benchmarks.
///
/// \testing
/// `tests/curve25519/scalar_test.cpp` (L and L - 1, 2^512 - 1 reduced, products checked against schoolbook values),
/// `demos/curve25519/scalar_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`.
///
/// \gotchas
/// Relies on C++20's arithmetic right shift of negative integers (defined since C++20).
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_curve25519_scalar_hpp
#define snicholls_crypto_curve25519_scalar_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace snicholls::crypto::curve25519 {

namespace detail {

// L, little-endian bytes
inline constexpr std::array<std::int64_t, 32> order_digits{
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};

// x (64 signed digits of about 8 bits, little-endian) modulo L, as 32 bytes; x is consumed
constexpr std::array<std::uint8_t, 32> reduce_digits(std::array<std::int64_t, 64>& x) noexcept
{
    for (std::size_t i = 63; i >= 32; --i) {
        std::int64_t carry = 0;
        std::size_t j = i - 32;
        for (; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * order_digits[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    std::int64_t carry = 0;
    for (std::size_t j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * order_digits[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (std::size_t j = 0; j < 32; ++j)
        x[j] -= carry * order_digits[j];
    std::array<std::uint8_t, 32> r{};
    for (std::size_t i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = static_cast<std::uint8_t>(x[i] & 255);
    }
    return r;
}

} // namespace detail

/// \brief An integer modulo L, the order of edwards25519's prime subgroup.
/// \ingroup curve25519
class scalar {
public:
    /// \brief Zero.
    constexpr scalar() noexcept = default;

    /// \brief A small value.
    /// \param v The value.
    /// \return The scalar.
    [[nodiscard]] static constexpr scalar from_u64(std::uint64_t v) noexcept
    {
        std::array<std::uint8_t, 32> b{};
        for (std::size_t i = 0; i < 8; ++i)
            b[i] = static_cast<std::uint8_t>(v >> (8 * i));
        std::array<std::uint8_t, 64> w{};
        for (std::size_t i = 0; i < 32; ++i)
            w[i] = b[i];
        return reduce(w);
    }

    /// \brief A 64-byte little-endian integer (a SHA-512 digest) reduced modulo L, in constant time.
    /// \param b The bytes.
    /// \return The scalar.
    [[nodiscard]] static constexpr scalar reduce(std::span<const std::uint8_t, 64> b) noexcept
    {
        std::array<std::int64_t, 64> x{};
        for (std::size_t i = 0; i < 64; ++i)
            x[i] = b[i];
        return scalar(detail::reduce_digits(x));
    }

    /// \brief A 32-byte little-endian integer reduced modulo L, in constant time.
    /// \param b The bytes.
    /// \return The scalar.
    [[nodiscard]] static constexpr scalar from_bytes_reduced(std::span<const std::uint8_t, 32> b) noexcept
    {
        std::array<std::uint8_t, 64> w{};
        for (std::size_t i = 0; i < 32; ++i)
            w[i] = b[i];
        return reduce(w);
    }

    /// \brief Whether 32 little-endian bytes are below L, in constant time.
    /// \param b The bytes.
    /// \return `true` for a canonical scalar.
    [[nodiscard]] static constexpr bool is_canonical(std::span<const std::uint8_t, 32> b) noexcept
    {
        // The borrow out of b - L
        std::uint64_t borrow = 0;
        for (std::size_t i = 0; i < 32; ++i) {
            const std::uint64_t d = std::uint64_t{b[i]} - static_cast<std::uint64_t>(detail::order_digits[i]) - borrow;
            borrow = (d >> 63) & 1;
        }
        return ct::mask_from_bit(borrow) != 0;
    }

    /// \brief A canonical 32-byte encoding (S < L), for public data.
    /// \param b The bytes.
    /// \return The scalar, or `std::nullopt` when b is L or more.
    [[nodiscard]] static constexpr std::optional<scalar> from_canonical(std::span<const std::uint8_t, 32> b) noexcept
    {
        if (!is_canonical(b))
            return std::nullopt;
        std::array<std::uint8_t, 32> c{};
        for (std::size_t i = 0; i < 32; ++i)
            c[i] = b[i];
        return scalar(c);
    }

    /// \brief a b + c modulo L, in constant time.
    /// \param a A scalar.
    /// \param b Another.
    /// \param c The addend.
    /// \return a b + c.
    [[nodiscard]] static constexpr scalar mul_add(const scalar& a, const scalar& b, const scalar& c) noexcept
    {
        std::array<std::int64_t, 64> x{};
        for (std::size_t i = 0; i < 32; ++i)
            x[i] = c.b_[i];
        for (std::size_t i = 0; i < 32; ++i)
            for (std::size_t j = 0; j < 32; ++j)
                x[i + j] += std::int64_t{a.b_[i]} * std::int64_t{b.b_[j]};
        const scalar r(detail::reduce_digits(x));
        secure_wipe(x);
        return r;
    }

    /// \brief The 32-byte little-endian encoding.
    /// \return The bytes.
    [[nodiscard]] constexpr const std::array<std::uint8_t, 32>& to_bytes() const noexcept { return b_; }

    /// \brief Four bits, for fixed-window multiplication.
    /// \param i Which nibble, 0 (least significant) to 63; public.
    /// \return Bits 4i to 4i + 3.
    [[nodiscard]] constexpr std::uint64_t nibble(std::size_t i) const noexcept { return (b_[i / 2] >> (4 * (i % 2))) & 0xf; }

    /// \brief Equality, in constant time.
    /// \param a A scalar.
    /// \param b Another.
    /// \return Whether they are equal.
    [[nodiscard]] friend constexpr bool operator==(const scalar& a, const scalar& b) noexcept { return ct::equal(a.b_, b.b_); }

private:
    constexpr explicit scalar(const std::array<std::uint8_t, 32>& b) noexcept : b_(b) {}
    std::array<std::uint8_t, 32> b_{};
};

} // namespace snicholls::crypto::curve25519

#endif /* snicholls_crypto_curve25519_scalar_hpp */

//
//  field.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief The field of P-256: integers modulo p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
/// \ingroup p256
///
/// \overview
/// `field_element` holds an integer modulo P-256's prime in Montgomery form; addition, subtraction, multiplication,
/// Fermat's inverse and the square root (p = 3 mod 4). Used by `p256/point.hpp`.
///
/// \relations
/// `detail/mont256.hpp` (the arithmetic, shared with `p256/scalar.hpp`); `p256/point.hpp`. Group: \ref p256.
///
/// \impls
/// One: Montgomery multiplication (CIOS, four 64-bit limbs) with a masked final subtraction.
///
/// \contracts
/// Constant time throughout, for secret or public values alike (no branch or index on a value); `from_bytes`
/// declassifies only whether the bytes were canonical. `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `from_bytes` returns std::nullopt for a value at or above p.
///
/// \examples
/// \snippet p256/field_demo.cpp field
///
/// \perf
/// One multiplication: 16 64-bit products and a reduction of the same size. See BENCHMARKS.md (`p256/ecdsa`).
///
/// \testing
/// `tests/p256/field_test.cpp`: identities at compile time (inverse, square root, distributivity), boundary values.
/// `demos/p256/field_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`; core's `result.hpp` and SHA-256; `detail/mont256.hpp`.
///
/// \gotchas
/// Values are in Montgomery form: compare them with `==` only against other `field_element`s, and read them with
/// `to_bytes` or `canonical`.
///
/// \status
/// Experimental (0.3).

#ifndef snicholls_crypto_p256_field_hpp
#define snicholls_crypto_p256_field_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/limbs.hpp>
#include <snicholls/crypto/detail/mont256.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

/// \brief P-256 (secp256r1, NIST FIPS 186-5, SEC 2): its field, scalars, points and ECDSA.
namespace snicholls::crypto::p256 {

namespace detail {
inline constexpr crypto::detail::mont256_params field_params = crypto::detail::make_mont256(crypto::detail::from_be(
    std::array<std::uint8_t, 32>{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
} // namespace detail

/// \brief An integer modulo p, kept in Montgomery form, fully reduced.
/// \ingroup p256
class field_element {
public:
    /// \brief Zero.
    constexpr field_element() noexcept = default;

    /// \brief A small value.
    /// \param v The value.
    /// \return v, as an element.
    [[nodiscard]] static constexpr field_element from_u64(std::uint64_t v) noexcept
    {
        return field_element(crypto::detail::mont256_to({v, 0, 0, 0}, P()));
    }

    /// \brief 32 big-endian bytes, refused when not below the modulus (strict input). Constant time in the bytes.
    /// \param b The bytes.
    /// \return The element, or std::nullopt at or above the modulus.
    [[nodiscard]] static constexpr std::optional<field_element> from_bytes(std::span<const std::uint8_t, 32> b) noexcept
    {
        std::uint64_t below = 0;
        const field_element e = from_bytes_ct(b, below);
        if (!ct::declassify(below))   // whether a value is canonical is public: it is refused
            return std::nullopt;
        return e;
    }

    /// \brief 32 big-endian bytes reduced once (the value minus the modulus when at or above it), with whether it was
    /// below, as a mask, in constant time.
    /// \param b The bytes.
    /// \param below Set to all ones when the value was below the modulus, zero otherwise.
    /// \return The element.
    [[nodiscard]] static constexpr field_element from_bytes_ct(std::span<const std::uint8_t, 32> b, std::uint64_t& below) noexcept
    {
        const auto v = crypto::detail::from_be(b);
        crypto::detail::limbs4 t{};
        const std::uint64_t borrow = crypto::detail::sub4(t, v, P().m);
        below = ct::mask_from_bit(borrow);
        return field_element(crypto::detail::mont256_to(crypto::detail::select4(below, v, t), P()));
    }

    /// \brief The canonical value as 32 big-endian bytes.
    /// \return The bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 32> to_bytes() const noexcept
    {
        return crypto::detail::to_be(crypto::detail::mont256_from(v_, P()));
    }

    /// \brief The canonical value as four limbs, least significant first.
    /// \return The limbs.
    [[nodiscard]] constexpr crypto::detail::limbs4 canonical() const noexcept { return crypto::detail::mont256_from(v_, P()); }

    /// \brief Sum.
    /// \param a An element.
    /// \param b Another.
    /// \return a + b.
    [[nodiscard]] friend constexpr field_element operator+(const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::mont256_add(a.v_, b.v_, P()));
    }

    /// \brief Difference.
    /// \param a An element.
    /// \param b Another.
    /// \return a - b.
    [[nodiscard]] friend constexpr field_element operator-(const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::mont256_sub(a.v_, b.v_, P()));
    }

    /// \brief Negation.
    /// \param a An element.
    /// \return -a.
    [[nodiscard]] friend constexpr field_element operator-(const field_element& a) noexcept { return field_element() - a; }

    /// \brief Product.
    /// \param a An element.
    /// \param b Another.
    /// \return a b.
    [[nodiscard]] friend constexpr field_element operator*(const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::mont256_mul(a.v_, b.v_, P()));
    }

    /// \brief Square.
    /// \return The square.
    [[nodiscard]] constexpr field_element square() const noexcept { return *this * *this; }

    /// \brief The inverse by Fermat's little theorem (a^(m-2), the exponent public): constant time; 0 maps to 0.
    /// \return The inverse.
    [[nodiscard]] constexpr field_element inverse() const noexcept
    {
        crypto::detail::limbs4 e = P().m;
        e[0] -= 2;   // m is odd and above 2: no borrow
        return field_element(crypto::detail::mont256_pow(v_, e, P()));
    }

    /// \brief The square root, a^((p+1)/4) as p = 3 mod 4, with whether a is a square as a mask; constant time.
    /// \param is_square Set to all ones when a is a square.
    /// \return A square root when a is a square.
    [[nodiscard]] constexpr field_element sqrt_ct(std::uint64_t& is_square) const noexcept
    {
        crypto::detail::limbs4 e = P().m;   // (p + 1) / 4: p + 1 = 2^256 - 2^224 + 2^192 + 2^96
        crypto::detail::limbs4 one{1, 0, 0, 0};
        crypto::detail::add4(e, e, one);
        e = {(e[0] >> 2) | (e[1] << 62), (e[1] >> 2) | (e[2] << 62), (e[2] >> 2) | (e[3] << 62), e[3] >> 2};
        const field_element r(crypto::detail::mont256_pow(v_, e, P()));
        is_square = crypto::detail::mask_equal4(r.square().v_, v_);
        return r;
    }

    /// \brief Whether the canonical value is odd (0 or 1).
    /// \return The low bit.
    [[nodiscard]] constexpr std::uint64_t is_odd() const noexcept { return canonical()[0] & 1; }

    /// \brief Whether the element is zero, as a mask (constant time).
    /// \return All ones for zero.
    [[nodiscard]] constexpr std::uint64_t is_zero_mask() const noexcept { return crypto::detail::mask_is_zero4(v_); }

    /// \brief Whether the element is zero (public data only).
    /// \return True for zero.
    [[nodiscard]] constexpr bool is_zero() const noexcept { return is_zero_mask() != 0; }

    /// \brief a if mask is all ones, b if it is zero, in constant time.
    /// \param mask All ones or zero.
    /// \param a One element.
    /// \param b Another.
    /// \return The selected element.
    [[nodiscard]] static constexpr field_element select(std::uint64_t mask, const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::select4(mask, a.v_, b.v_));
    }

    /// \brief Equality (variable time: public data only).
    /// \param a An element.
    /// \param b Another.
    /// \return Whether they are equal.
    [[nodiscard]] friend constexpr bool operator==(const field_element& a, const field_element& b) noexcept = default;

private:
    constexpr explicit field_element(const crypto::detail::limbs4& v) noexcept : v_(v) {}
    static constexpr const crypto::detail::mont256_params& P() noexcept { return detail::field_params; }

    crypto::detail::limbs4 v_{};
};

} // namespace snicholls::crypto::p256

#endif /* snicholls_crypto_p256_field_hpp */

//
//  scalar.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `secp256k1::scalar`: arithmetic modulo the group order n, constant-time and `constexpr`.
/// \ingroup secp256k1
///
/// \overview
/// Private keys, nonces, signature components and hashes reduced into the group. Four 64-bit limbs, always below
/// n = 2^256 - 0x14551231950B75FC4402DA1732FC9BEBF; every operation runs in time independent of the value.
///
/// \relations
/// - `secp256k1/field.hpp`: the same arithmetic modulo p.
/// - `secp256k1/ecdsa.hpp`, `secp256k1/schnorr.hpp`: the users.
/// - Group: \ref secp256k1.
///
/// \impls
/// One: 4 x 64-bit limbs, the product folded four times by 2^256 = c (mod n), then one conditional subtraction.
///
/// \contracts
/// - Value type, trivially copyable, no allocation; every member `constexpr` and `noexcept`.
/// - Constant time in the value, `inverse` included (Fermat with the public exponent n - 2).
/// - `from_bytes` (strict) branches on whether the encoding is in range; use `from_bytes_ct` for a secret.
/// - A scalar holding a secret is wiped by its owner (`secp256k1::private_key` does); the type itself does not wipe,
///   so that it stays trivially copyable for the arithmetic.
///
/// \errors
/// None: an out-of-range encoding is `std::nullopt` or a zero validity mask.
///
/// \examples
/// \snippet secp256k1/scalar_demo.cpp scalar
///
/// \perf
/// Measured inside the curve benchmarks, not on its own.
///
/// \testing
/// `tests/secp256k1/scalar_test.cpp`, `demos/secp256k1/scalar_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`; core's `detail/wide_mul.hpp`.
///
/// \gotchas
/// None known.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secp256k1_scalar_hpp
#define snicholls_crypto_secp256k1_scalar_hpp

#include <snicholls/crypto/detail/limbs.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace snicholls::crypto::secp256k1 {

namespace detail {
inline constexpr crypto::detail::pseudo_mersenne<3> order_modulus{
    {0xBFD25E8CD0364141ull, 0xBAAEDCE6AF48A03Bull, 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull},
    {0x402DA1732FC9BEBFull, 0x4551231950B75FC4ull, 0x1ull},
    {0x402DA1732FC9BEBFull, 0x4551231950B75FC4ull, 0x1ull, 0}};
inline constexpr crypto::detail::limbs4 half_order{0xDFE92F46681B20A0ull, 0x5D576E7357A4501Dull, 0xFFFFFFFFFFFFFFFFull,
                                                   0x7FFFFFFFFFFFFFFFull};
} // namespace detail

/// \brief An integer modulo n, the order of secp256k1's group.
/// \ingroup secp256k1
class scalar {
public:
    /// \brief Zero.
    constexpr scalar() noexcept = default;

    /// \brief A small value.
    /// \param v The value.
    /// \return The scalar.
    [[nodiscard]] static constexpr scalar from_u64(std::uint64_t v) noexcept { return scalar({v, 0, 0, 0}); }

    /// \brief The group order n, as big-endian bytes (it is not itself a scalar).
    /// \return n.
    [[nodiscard]] static constexpr std::array<std::uint8_t, 32> order_bytes() noexcept
    {
        return crypto::detail::to_be(detail::order_modulus.m);
    }

    /// \brief A 32-byte big-endian value, if it is below n (public data: branches on validity).
    /// \param b The bytes.
    /// \return The scalar, or `std::nullopt` for a value at or above n.
    [[nodiscard]] static constexpr std::optional<scalar> from_bytes(std::span<const std::uint8_t, 32> b) noexcept
    {
        std::uint64_t valid = 0;
        const scalar s = from_bytes_ct(b, valid);
        if (!valid)
            return std::nullopt;
        return s;
    }

    /// \brief A 32-byte big-endian value and whether it is below n, in constant time.
    /// \param b The bytes.
    /// \param[out] below_order All ones if the value is below n, zero otherwise.
    /// \return The value reduced modulo n (equal to it when `below_order`).
    [[nodiscard]] static constexpr scalar from_bytes_ct(std::span<const std::uint8_t, 32> b, std::uint64_t& below_order) noexcept
    {
        const auto l = crypto::detail::from_be(b);
        below_order = crypto::detail::mask_less4(l, detail::order_modulus.m);
        crypto::detail::limbs4 t{};
        crypto::detail::add4(t, l, detail::order_modulus.c4);   // l - n mod 2^256
        return scalar(crypto::detail::select4(below_order, l, t));
    }

    /// \brief A 32-byte big-endian value reduced modulo n (a hash as ECDSA's z), in constant time.
    /// \param b The bytes.
    /// \return The value mod n.
    [[nodiscard]] static constexpr scalar from_bytes_reduced(std::span<const std::uint8_t, 32> b) noexcept
    {
        std::uint64_t ignored = 0;
        return from_bytes_ct(b, ignored);
    }

    /// \brief The 32-byte big-endian encoding.
    /// \return The bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 32> to_bytes() const noexcept { return crypto::detail::to_be(v_); }

    /// \brief The limbs, least significant first.
    /// \return The limbs.
    [[nodiscard]] constexpr const std::array<std::uint64_t, 4>& limbs() const noexcept { return v_; }

    /// \brief Four bits of the value, for fixed-window multiplication.
    /// \param i Which nibble, 0 (least significant) to 63; public.
    /// \return Bits 4i to 4i + 3.
    [[nodiscard]] constexpr std::uint64_t nibble(std::size_t i) const noexcept { return (v_[i / 16] >> (4 * (i % 16))) & 0xf; }

    /// \brief Sum.
    /// \param a A scalar.
    /// \param b Another.
    /// \return a + b mod n.
    [[nodiscard]] friend constexpr scalar operator+(const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::mod_add(a.v_, b.v_, detail::order_modulus));
    }
    /// \brief Difference.
    /// \param a A scalar.
    /// \param b Another.
    /// \return a - b mod n.
    [[nodiscard]] friend constexpr scalar operator-(const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::mod_sub(a.v_, b.v_, detail::order_modulus));
    }
    /// \brief Negation.
    /// \param a A scalar.
    /// \return -a mod n.
    [[nodiscard]] friend constexpr scalar operator-(const scalar& a) noexcept { return scalar{} - a; }
    /// \brief Product.
    /// \param a A scalar.
    /// \param b Another.
    /// \return a * b mod n.
    [[nodiscard]] friend constexpr scalar operator*(const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::mod_mul(a.v_, b.v_, detail::order_modulus));
    }

    /// \brief The inverse, by Fermat: this^(n-2). Zero maps to zero.
    /// \return 1 / this mod n.
    [[nodiscard]] constexpr scalar inverse() const noexcept
    {
        constexpr crypto::detail::limbs4 e{0xBFD25E8CD036413Full, 0xBAAEDCE6AF48A03Bull, 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull};
        return scalar(crypto::detail::mod_pow_public(v_, e, detail::order_modulus));
    }

    /// \brief All ones if this is zero.
    /// \return The mask.
    [[nodiscard]] constexpr std::uint64_t is_zero_mask() const noexcept { return crypto::detail::mask_is_zero4(v_); }
    /// \brief Whether this is zero.
    /// \return `true` for zero.
    [[nodiscard]] constexpr bool is_zero() const noexcept { return is_zero_mask() != 0; }
    /// \brief All ones if this is above n / 2 (a "high" s).
    /// \return The mask.
    [[nodiscard]] constexpr std::uint64_t is_high_mask() const noexcept { return crypto::detail::mask_less4(detail::half_order, v_); }
    /// \brief Whether this is above n / 2.
    /// \return `true` for a high value.
    [[nodiscard]] constexpr bool is_high() const noexcept { return is_high_mask() != 0; }

    /// \brief `a` where `mask` is all ones, `b` where it is zero, in constant time.
    /// \param mask All ones or zero.
    /// \param a The scalar chosen by all ones.
    /// \param b The scalar chosen by zero.
    /// \return The selection.
    [[nodiscard]] static constexpr scalar select(std::uint64_t mask, const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::select4(mask, a.v_, b.v_));
    }

    /// \brief Constant-time equality.
    /// \param a A scalar.
    /// \param b Another.
    /// \return Whether they are equal.
    [[nodiscard]] friend constexpr bool operator==(const scalar& a, const scalar& b) noexcept
    {
        return crypto::detail::mask_equal4(a.v_, b.v_) != 0;
    }

private:
    constexpr explicit scalar(const crypto::detail::limbs4& v) noexcept : v_(v) {}
    crypto::detail::limbs4 v_{};
};

} // namespace snicholls::crypto::secp256k1

#endif /* snicholls_crypto_secp256k1_scalar_hpp */

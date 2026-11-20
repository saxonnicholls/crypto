//
//  field.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `secp256k1::field_element`: arithmetic modulo p = 2^256 - 2^32 - 977, constant-time and `constexpr`.
/// \ingroup secp256k1
///
/// \overview
/// The coordinates of secp256k1 points. Four 64-bit limbs, always fully reduced; addition, subtraction,
/// multiplication, inversion and square roots with no branch or memory index that depends on the value. Every
/// operation is `constexpr`, so tables of points (the multiples of G) are built by the compiler.
///
/// Use it through `point.hpp`; it is public so that callers can check coordinates and tests can pin identities.
///
/// \relations
/// - `secp256k1/scalar.hpp`: the same arithmetic modulo the group order n.
/// - `secp256k1/point.hpp`: the curve y^2 = x^3 + 7 over this field.
/// - Group: \ref secp256k1.
///
/// \impls
/// One: 4 x 64-bit limbs with the 2^256 = c (mod p) fold, c = 2^32 + 977. libsecp256k1 uses 5 x 52 with lazy
/// reduction, which is faster; this is the shortest constant-time form, and fast enough for wallets and servers
/// (see the benchmarks).
///
/// \contracts
/// - Value type, trivially copyable, no allocation; every member `constexpr` and `noexcept`.
/// - Constant time in the value for every operation, including `inverse` (Fermat, a fixed public exponent) and
///   `sqrt` (one fixed exponentiation, then a constant-time check).
/// - `from_bytes` rejects (returns `std::nullopt`) a value at or above p; that branch is on the validity of an
///   encoding, which is public in every use here.
///
/// \errors
/// None: an invalid encoding is `std::nullopt`, a missing square root is `std::nullopt`.
///
/// \examples
/// \snippet secp256k1/field_demo.cpp field
///
/// \perf
/// Measured inside the curve benchmarks (`benchmarks/secp256k1/ecdsa_benchmark.cpp`), not on its own.
///
/// \testing
/// `tests/secp256k1/field_test.cpp` (identities at compile time, inverses and roots against exponentiation,
/// boundary values p - 1, 0, 1), `demos/secp256k1/field_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`; core's `detail/wide_mul.hpp`.
///
/// \gotchas
/// None known.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secp256k1_field_hpp
#define snicholls_crypto_secp256k1_field_hpp

#include <snicholls/crypto/detail/limbs.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <span>

/// \brief secp256k1: the field, the scalars, the curve, ECDSA and BIP-340 Schnorr.
namespace snicholls::crypto::secp256k1 {

namespace detail {
inline constexpr crypto::detail::pseudo_mersenne<1> field_modulus{
    {0xFFFFFFFEFFFFFC2Full, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull},
    {0x1000003D1ull},
    {0x1000003D1ull, 0, 0, 0}};
} // namespace detail

/// \brief An element of GF(p), p = 2^256 - 2^32 - 977.
/// \ingroup secp256k1
class field_element {
public:
    /// \brief Zero.
    constexpr field_element() noexcept = default;

    /// \brief A small value.
    /// \param v The value, below 2^64.
    /// \return The element.
    [[nodiscard]] static constexpr field_element from_u64(std::uint64_t v) noexcept { return field_element({v, 0, 0, 0}); }

    /// \brief The element with these limbs, least significant first.
    /// \pre The value is below p.
    /// \param l The limbs.
    /// \return The element.
    [[nodiscard]] static constexpr field_element from_limbs(const std::array<std::uint64_t, 4>& l) noexcept { return field_element(l); }

    /// \brief A 32-byte big-endian value, if it is below p.
    /// \param b The bytes.
    /// \return The element, or `std::nullopt` for a value at or above p.
    [[nodiscard]] static constexpr std::optional<field_element> from_bytes(std::span<const std::uint8_t, 32> b) noexcept
    {
        const auto l = crypto::detail::from_be(b);
        if (!crypto::detail::mask_less4(l, detail::field_modulus.m))
            return std::nullopt;
        return field_element(l);
    }

    /// \brief The 32-byte big-endian encoding.
    /// \return The bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 32> to_bytes() const noexcept { return crypto::detail::to_be(v_); }

    /// \brief The limbs, least significant first.
    /// \return The limbs.
    [[nodiscard]] constexpr const std::array<std::uint64_t, 4>& limbs() const noexcept { return v_; }

    /// \brief Sum.
    /// \param a An element.
    /// \param b Another.
    /// \return a + b mod p.
    [[nodiscard]] friend constexpr field_element operator+(const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::mod_add(a.v_, b.v_, detail::field_modulus));
    }
    /// \brief Difference.
    /// \param a An element.
    /// \param b Another.
    /// \return a - b mod p.
    [[nodiscard]] friend constexpr field_element operator-(const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::mod_sub(a.v_, b.v_, detail::field_modulus));
    }
    /// \brief Negation.
    /// \param a An element.
    /// \return -a mod p.
    [[nodiscard]] friend constexpr field_element operator-(const field_element& a) noexcept { return field_element{} - a; }
    /// \brief Product.
    /// \param a An element.
    /// \param b Another.
    /// \return a * b mod p.
    [[nodiscard]] friend constexpr field_element operator*(const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::mod_mul(a.v_, b.v_, detail::field_modulus));
    }

    /// \brief The square.
    /// \return this^2 mod p.
    [[nodiscard]] constexpr field_element square() const noexcept { return *this * *this; }

    /// \brief The inverse, by Fermat: this^(p-2). Zero maps to zero.
    /// \return 1 / this mod p.
    [[nodiscard]] constexpr field_element inverse() const noexcept
    {
        constexpr crypto::detail::limbs4 e{0xFFFFFFFEFFFFFC2Dull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull};
        return field_element(crypto::detail::mod_pow_public(v_, e, detail::field_modulus));
    }

    /// \brief A square root, this^((p+1)/4), and whether it is one.
    /// \param[out] is_square All ones if the result squares to this, zero if this has no square root.
    /// \return The candidate root (meaningless when `is_square` is zero).
    [[nodiscard]] constexpr field_element sqrt_ct(std::uint64_t& is_square) const noexcept
    {
        constexpr crypto::detail::limbs4 e{0xFFFFFFFFBFFFFF0Cull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull, 0x3FFFFFFFFFFFFFFFull};
        const field_element r(crypto::detail::mod_pow_public(v_, e, detail::field_modulus));
        is_square = crypto::detail::mask_equal4(r.square().v_, v_);
        return r;
    }

    /// \brief A square root, for public data.
    /// \return The root whose square is this (either of the two), or `std::nullopt` for a non-residue.
    [[nodiscard]] constexpr std::optional<field_element> sqrt() const noexcept
    {
        std::uint64_t ok = 0;
        const field_element r = sqrt_ct(ok);
        if (!ok)
            return std::nullopt;
        return r;
    }

    /// \brief All ones if this is zero.
    /// \return The mask.
    [[nodiscard]] constexpr std::uint64_t is_zero_mask() const noexcept { return crypto::detail::mask_is_zero4(v_); }
    /// \brief Whether this is zero.
    /// \return `true` for zero.
    [[nodiscard]] constexpr bool is_zero() const noexcept { return is_zero_mask() != 0; }
    /// \brief The low bit of the canonical value (the "sign" SEC1 and BIP-340 use).
    /// \return 1 if odd, 0 if even.
    [[nodiscard]] constexpr std::uint64_t is_odd() const noexcept { return v_[0] & 1; }

    /// \brief `a` where `mask` is all ones, `b` where it is zero, in constant time.
    /// \param mask All ones or zero.
    /// \param a The element chosen by all ones.
    /// \param b The element chosen by zero.
    /// \return The selection.
    [[nodiscard]] static constexpr field_element select(std::uint64_t mask, const field_element& a, const field_element& b) noexcept
    {
        return field_element(crypto::detail::select4(mask, a.v_, b.v_));
    }

    /// \brief Constant-time equality.
    /// \param a An element.
    /// \param b Another.
    /// \return Whether they are equal.
    [[nodiscard]] friend constexpr bool operator==(const field_element& a, const field_element& b) noexcept
    {
        return crypto::detail::mask_equal4(a.v_, b.v_) != 0;
    }

private:
    constexpr explicit field_element(const crypto::detail::limbs4& v) noexcept : v_(v) {}
    crypto::detail::limbs4 v_{};
};

} // namespace snicholls::crypto::secp256k1

#endif /* snicholls_crypto_secp256k1_field_hpp */

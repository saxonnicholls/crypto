//
//  scalar.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Scalars of P-256: integers modulo the group order n.
/// \ingroup p256
///
/// \overview
/// `scalar` holds an integer modulo P-256's group order n in Montgomery form: private keys, nonces and the
/// ECDSA arithmetic of `p256/ecdsa.hpp`.
///
/// \relations
/// `detail/mont256.hpp`; `p256/ecdsa.hpp`. Group: \ref p256.
///
/// \impls
/// One: Montgomery multiplication (CIOS, four 64-bit limbs) with a masked final subtraction; Fermat's inverse.
///
/// \contracts
/// Constant time throughout: a private key or a nonce never decides a branch or an index; `from_bytes`
/// declassifies only whether the bytes were below n. `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `from_bytes` returns std::nullopt for a value at or above n.
///
/// \examples
/// \snippet p256/scalar_demo.cpp scalar
///
/// \perf
/// See BENCHMARKS.md (`p256/ecdsa`).
///
/// \testing
/// `tests/p256/scalar_test.cpp`: identities at compile time, n - 1, reduction of values at and above n.
/// `demos/p256/scalar_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`; core's `result.hpp` and SHA-256; `detail/mont256.hpp`.
///
/// \gotchas
/// A scalar of zero is a valid element but not a valid private key: `p256/ecdsa.hpp`'s `private_key` refuses it.
///
/// \status
/// Experimental (0.3).

#ifndef snicholls_crypto_p256_scalar_hpp
#define snicholls_crypto_p256_scalar_hpp

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
inline constexpr crypto::detail::mont256_params order_params = crypto::detail::make_mont256(crypto::detail::from_be(
    std::array<std::uint8_t, 32>{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51}));
} // namespace detail

/// \brief An integer modulo n, kept in Montgomery form, fully reduced.
/// \ingroup p256
class scalar {
public:
    /// \brief Zero.
    constexpr scalar() noexcept = default;

    /// \brief A small value.
    /// \param v The value.
    /// \return v, as an element.
    [[nodiscard]] static constexpr scalar from_u64(std::uint64_t v) noexcept
    {
        return scalar(crypto::detail::mont256_to({v, 0, 0, 0}, P()));
    }

    /// \brief 32 big-endian bytes, refused when not below the modulus (strict input). Constant time in the bytes.
    /// \param b The bytes.
    /// \return The element, or std::nullopt at or above the modulus.
    [[nodiscard]] static constexpr std::optional<scalar> from_bytes(std::span<const std::uint8_t, 32> b) noexcept
    {
        std::uint64_t below = 0;
        const scalar e = from_bytes_ct(b, below);
        if (!ct::declassify(below))   // whether a value is canonical is public: it is refused
            return std::nullopt;
        return e;
    }

    /// \brief 32 big-endian bytes reduced once (the value minus the modulus when at or above it), with whether it was
    /// below, as a mask, in constant time.
    /// \param b The bytes.
    /// \param below Set to all ones when the value was below the modulus, zero otherwise.
    /// \return The element.
    [[nodiscard]] static constexpr scalar from_bytes_ct(std::span<const std::uint8_t, 32> b, std::uint64_t& below) noexcept
    {
        const auto v = crypto::detail::from_be(b);
        crypto::detail::limbs4 t{};
        const std::uint64_t borrow = crypto::detail::sub4(t, v, P().m);
        below = ct::mask_from_bit(borrow);
        return scalar(crypto::detail::mont256_to(crypto::detail::select4(below, v, t), P()));
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
    [[nodiscard]] friend constexpr scalar operator+(const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::mont256_add(a.v_, b.v_, P()));
    }

    /// \brief Difference.
    /// \param a An element.
    /// \param b Another.
    /// \return a - b.
    [[nodiscard]] friend constexpr scalar operator-(const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::mont256_sub(a.v_, b.v_, P()));
    }

    /// \brief Negation.
    /// \param a An element.
    /// \return -a.
    [[nodiscard]] friend constexpr scalar operator-(const scalar& a) noexcept { return scalar() - a; }

    /// \brief Product.
    /// \param a An element.
    /// \param b Another.
    /// \return a b.
    [[nodiscard]] friend constexpr scalar operator*(const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::mont256_mul(a.v_, b.v_, P()));
    }

    /// \brief Square.
    /// \return The square.
    [[nodiscard]] constexpr scalar square() const noexcept { return *this * *this; }

    /// \brief The inverse by Fermat's little theorem (a^(m-2), the exponent public): constant time; 0 maps to 0.
    /// \return The inverse.
    [[nodiscard]] constexpr scalar inverse() const noexcept
    {
        crypto::detail::limbs4 e = P().m;
        e[0] -= 2;   // m is odd and above 2: no borrow
        return scalar(crypto::detail::mont256_pow(v_, e, P()));
    }

    /// \brief 32 big-endian bytes reduced modulo n (a hash; values below 2^256 < 2n need one subtraction).
    /// \param b The bytes.
    /// \return b mod n.
    [[nodiscard]] static constexpr scalar from_bytes_reduced(std::span<const std::uint8_t, 32> b) noexcept
    {
        std::uint64_t below = 0;
        return from_bytes_ct(b, below);
    }

    /// \brief The group order n, big-endian.
    /// \return n.
    [[nodiscard]] static constexpr std::array<std::uint8_t, 32> order_bytes() noexcept { return crypto::detail::to_be(P().m); }

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
    [[nodiscard]] static constexpr scalar select(std::uint64_t mask, const scalar& a, const scalar& b) noexcept
    {
        return scalar(crypto::detail::select4(mask, a.v_, b.v_));
    }

    /// \brief Equality (variable time: public data only).
    /// \param a An element.
    /// \param b Another.
    /// \return Whether they are equal.
    [[nodiscard]] friend constexpr bool operator==(const scalar& a, const scalar& b) noexcept = default;

private:
    constexpr explicit scalar(const crypto::detail::limbs4& v) noexcept : v_(v) {}
    static constexpr const crypto::detail::mont256_params& P() noexcept { return detail::order_params; }

    crypto::detail::limbs4 v_{};
};

} // namespace snicholls::crypto::p256

#endif /* snicholls_crypto_p256_scalar_hpp */

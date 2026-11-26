//
//  mont_residue.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  An integer modulo an odd modulus of N 64-bit limbs, kept fully reduced in Montgomery form (detail/mont.hpp): the
//  one class behind P-256's and P-384's field elements and scalars (p256::field_element, p256::scalar,
//  p384::field_element, p384::scalar are its instances, each modulus a distinct type).
//
//  Modulus is a type with `static constexpr const mont_params<N>& params()`.
//
//  Constant time throughout: a value never decides a branch or an index. Revealed on purpose: `from_bytes` declassifies
//  whether the bytes were below the modulus (it refuses them otherwise), and `is_zero` and `==` are for public data.
//  The exponentiations (inverse, square root) take public exponents. constexpr, noexcept, no allocation.
//

#ifndef snicholls_crypto_detail_mont_residue_hpp
#define snicholls_crypto_detail_mont_residue_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/mont.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace snicholls::crypto::detail {

template <std::size_t N, class Modulus>
class mont_residue {
public:
    static constexpr std::size_t limbs = N;           // the number of 64-bit limbs
    static constexpr std::size_t size_bytes = 8 * N;   // the big-endian encoding's length

    // Zero
    constexpr mont_residue() noexcept = default;

    // A small value
    [[nodiscard]] static constexpr mont_residue from_u64(std::uint64_t v) noexcept
    {
        limbs_n<N> a{};
        a[0] = v;
        return mont_residue(mont_to<N>(a, P()));
    }

    // 8 N big-endian bytes, refused when not below the modulus (strict input); constant time in the bytes
    [[nodiscard]] static constexpr std::optional<mont_residue> from_bytes(std::span<const std::uint8_t, 8 * N> b) noexcept
    {
        std::uint64_t below = 0;
        const mont_residue e = from_bytes_ct(b, below);
        if (!ct::declassify(below))   // whether a value is canonical is public: it is refused
            return std::nullopt;
        return e;
    }

    // 8 N big-endian bytes reduced once (minus the modulus when at or above it), with whether it was below as a mask
    [[nodiscard]] static constexpr mont_residue from_bytes_ct(std::span<const std::uint8_t, 8 * N> b, std::uint64_t& below) noexcept
    {
        const auto v = from_be_n<N>(b);
        limbs_n<N> t{};
        const std::uint64_t borrow = sub_n<N>(t, v, P().m);
        below = ct::mask_from_bit(borrow);
        return mont_residue(mont_to<N>(select_n<N>(below, v, t), P()));
    }

    // 8 N big-endian bytes reduced modulo m (a hash): values below 2^(64 N) < 2 m need one subtraction
    [[nodiscard]] static constexpr mont_residue from_bytes_reduced(std::span<const std::uint8_t, 8 * N> b) noexcept
    {
        std::uint64_t below = 0;
        return from_bytes_ct(b, below);
    }

    // The modulus, big-endian (for a scalar, the group order: order_bytes)
    [[nodiscard]] static constexpr std::array<std::uint8_t, 8 * N> modulus_bytes() noexcept { return to_be_n<N>(P().m); }
    [[nodiscard]] static constexpr std::array<std::uint8_t, 8 * N> order_bytes() noexcept { return modulus_bytes(); }

    // The canonical value as big-endian bytes, and as limbs (least significant first)
    [[nodiscard]] constexpr std::array<std::uint8_t, 8 * N> to_bytes() const noexcept { return to_be_n<N>(mont_from<N>(v_, P())); }
    [[nodiscard]] constexpr limbs_n<N> canonical() const noexcept { return mont_from<N>(v_, P()); }

    [[nodiscard]] friend constexpr mont_residue operator+(const mont_residue& a, const mont_residue& b) noexcept
    {
        return mont_residue(mont_add<N>(a.v_, b.v_, P()));
    }
    [[nodiscard]] friend constexpr mont_residue operator-(const mont_residue& a, const mont_residue& b) noexcept
    {
        return mont_residue(mont_sub<N>(a.v_, b.v_, P()));
    }
    [[nodiscard]] friend constexpr mont_residue operator-(const mont_residue& a) noexcept { return mont_residue() - a; }
    [[nodiscard]] friend constexpr mont_residue operator*(const mont_residue& a, const mont_residue& b) noexcept
    {
        return mont_residue(mont_mul<N>(a.v_, b.v_, P()));
    }
    [[nodiscard]] constexpr mont_residue square() const noexcept { return *this * *this; }

    // The inverse by Fermat (a^(m-2), the exponent public): constant time; 0 maps to 0
    [[nodiscard]] constexpr mont_residue inverse() const noexcept
    {
        limbs_n<N> e = P().m;
        e[0] -= 2;   // m is odd and above 2: no borrow
        return mont_residue(mont_pow<N>(v_, e, P()));
    }

    // The square root a^((m+1)/4), for m = 3 mod 4, with whether a is a square as a mask; constant time
    [[nodiscard]] constexpr mont_residue sqrt_ct(std::uint64_t& is_square) const noexcept
    {
        limbs_n<N> e = P().m, one{};
        one[0] = 1;
        add_n<N>(e, e, one);   // m + 1 < 2^(64 N): m's top bit is set but m + 1 does not carry out (m is not all ones)
        for (std::size_t i = 0; i < N; ++i)
            e[i] = (e[i] >> 2) | (i + 1 < N ? e[i + 1] << 62 : 0);
        const mont_residue r(mont_pow<N>(v_, e, P()));
        is_square = mask_equal_n<N>(r.square().v_, v_);
        return r;
    }

    // Whether the canonical value is odd (0 or 1)
    [[nodiscard]] constexpr std::uint64_t is_odd() const noexcept { return canonical()[0] & 1; }

    // Whether the element is zero, as a mask (constant time), and as a bool (public data only)
    [[nodiscard]] constexpr std::uint64_t is_zero_mask() const noexcept { return mask_is_zero_n<N>(v_); }
    [[nodiscard]] constexpr bool is_zero() const noexcept { return is_zero_mask() != 0; }

    // a if mask is all ones, b if it is zero, in constant time
    [[nodiscard]] static constexpr mont_residue select(std::uint64_t mask, const mont_residue& a, const mont_residue& b) noexcept
    {
        return mont_residue(select_n<N>(mask, a.v_, b.v_));
    }

    // Equality (variable time: public data only)
    [[nodiscard]] friend constexpr bool operator==(const mont_residue& a, const mont_residue& b) noexcept = default;

private:
    constexpr explicit mont_residue(const limbs_n<N>& v) noexcept : v_(v) {}
    static constexpr const mont_params<N>& P() noexcept { return Modulus::params(); }

    limbs_n<N> v_{};
};

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_mont_residue_hpp */

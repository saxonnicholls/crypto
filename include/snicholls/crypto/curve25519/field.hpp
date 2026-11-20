//
//  field.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `curve25519::field_element`: arithmetic modulo p = 2^255 - 19, constant-time and `constexpr`.
/// \ingroup curve25519
///
/// \overview
/// The coordinates of Curve25519 (X25519's Montgomery form) and edwards25519 (Ed25519's twisted Edwards form). Five
/// limbs of 51 bits, kept weakly reduced (each limb a little above 2^51 at most) between operations and reduced to
/// the canonical value only when encoded. Every operation is `constexpr` and runs in time independent of the value.
///
/// Use it through `edwards.hpp`, `ed25519.hpp` and `x25519.hpp`; it is public so that tests can pin identities and
/// callers can check coordinates.
///
/// \relations
/// - `curve25519/scalar.hpp`: arithmetic modulo the group order L.
/// - `curve25519/edwards.hpp`, `curve25519/x25519.hpp`: the curves over this field.
/// - Group: \ref curve25519.
///
/// \impls
/// One: 5 x 51-bit limbs (the "donna 64" representation). Products are 128-bit, taken from core's
/// `snicholls::detail::umul128` (one instruction at run time on GCC and Clang, four 32-bit multiplies in a constant
/// expression or on MSVC). The 4 x 64 limbs of `detail/limbs.hpp` were not reused: 2^255 - 19 leaves one spare bit,
/// so 51-bit limbs absorb the carries of additions without a carry chain and the reduction by 19 is one
/// multiplication, where the 4 x 64 form would need its full fold after every addition.
///
/// \contracts
/// - Value type, trivially copyable, no allocation; every member `constexpr` and `noexcept`.
/// - Constant time in the value for every operation: no branch or index depends on a limb. `invert` and
///   `pow22523` are fixed addition chains; `sqrt_ratio` is a fixed exponentiation followed by masked selections.
/// - `from_bytes` ignores bit 255 (the caller decides what it means: the sign of x for Ed25519, nothing for X25519)
///   and accepts the non-canonical values p to 2^255 - 1, which then behave as their residues;
///   `is_canonical` tells them apart.
///
/// \errors
/// None: a missing square root is a zero mask from `sqrt_ratio`.
///
/// \examples
/// \snippet curve25519/field_demo.cpp field
///
/// \perf
/// Measured inside the Ed25519 and X25519 benchmarks, not on its own.
///
/// \testing
/// `tests/curve25519/field_test.cpp` (identities at compile time, the constants d and sqrt(-1) proved by their
/// defining equations, canonical encoding at p - 1, p and 2^255 - 1), `demos/curve25519/field_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `detail/wide_mul.hpp`.
///
/// \gotchas
/// Two elements equal as residues can have different limbs; compare with `==`, which compares canonical encodings.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_curve25519_field_hpp
#define snicholls_crypto_curve25519_field_hpp

#include <snicholls/core/detail/wide_mul.hpp>
#include <snicholls/crypto/constant_time.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

/// \brief The arithmetic Ed25519 and X25519 share: the field, the scalars modulo L, and edwards25519.
namespace snicholls::crypto::curve25519 {

namespace detail {

inline constexpr std::uint64_t mask51 = (std::uint64_t{1} << 51) - 1;

// A 128-bit accumulator built on core's 64 x 64 -> 128 multiply
struct u128 {
    std::uint64_t lo;
    std::uint64_t hi;
};

constexpr u128 mul64(std::uint64_t a, std::uint64_t b) noexcept
{
    const auto p = snicholls::detail::umul128(a, b);
    return {p.low, p.high};
}

constexpr u128 add128(u128 a, u128 b) noexcept
{
    const std::uint64_t lo = a.lo + b.lo;
    return {lo, a.hi + b.hi + (lo < a.lo)};
}

// (a >> 51) when it fits 64 bits, as it always does here
constexpr std::uint64_t shr51(u128 a) noexcept { return (a.lo >> 51) | (a.hi << 13); }

} // namespace detail

/// \brief An element of GF(2^255 - 19).
/// \ingroup curve25519
class field_element {
public:
    /// \brief The limbs, least significant first, 51 bits each (a little more between operations).
    using limbs_type = std::array<std::uint64_t, 5>;

    /// \brief Zero.
    constexpr field_element() noexcept = default;

    /// \brief The element with these limbs.
    /// \pre Each limb is below 2^52.
    /// \param l The limbs.
    constexpr explicit field_element(const limbs_type& l) noexcept : v_(l) {}

    /// \brief A small value.
    /// \param v The value, below 2^51.
    /// \return The element.
    [[nodiscard]] static constexpr field_element from_u64(std::uint64_t v) noexcept
    {
        return field_element(limbs_type{v & detail::mask51, v >> 51, 0, 0, 0});
    }

    /// \brief The low 255 bits of 32 little-endian bytes; bit 255 is ignored.
    /// \param b The bytes.
    /// \return The element (a value from p to 2^255 - 1 is accepted and behaves as its residue).
    [[nodiscard]] static constexpr field_element from_bytes(std::span<const std::uint8_t, 32> b) noexcept
    {
        auto load = [&](std::size_t i) {
            std::uint64_t x = 0;
            for (std::size_t j = 0; j < 8; ++j)
                x |= std::uint64_t{b[i + j]} << (8 * j);
            return x;
        };
        const std::uint64_t w0 = load(0), w1 = load(8), w2 = load(16), w3 = load(24);
        return field_element(limbs_type{w0 & detail::mask51, ((w0 >> 51) | (w1 << 13)) & detail::mask51,
                                        ((w1 >> 38) | (w2 << 26)) & detail::mask51, ((w2 >> 25) | (w3 << 39)) & detail::mask51,
                                        (w3 >> 12) & detail::mask51});
    }

    /// \brief Whether 32 bytes, bit 255 ignored, encode a value below p.
    /// \param b The bytes.
    /// \return `true` for a canonical encoding.
    [[nodiscard]] static constexpr bool is_canonical(std::span<const std::uint8_t, 32> b) noexcept
    {
        std::array<std::uint8_t, 32> c = from_bytes(b).to_bytes();
        c[31] = static_cast<std::uint8_t>(c[31] | (b[31] & 0x80));
        return ct::equal(c, b);
    }

    /// \brief The canonical 32-byte little-endian encoding, bit 255 clear.
    /// \return The bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 32> to_bytes() const noexcept
    {
        limbs_type h = carried().carried().v_;
        // q = 1 exactly when h >= p: whether h + 19 carries out of bit 255
        std::uint64_t q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        for (std::size_t i = 0; i < 4; ++i) {
            h[i + 1] += h[i] >> 51;
            h[i] &= detail::mask51;
        }
        h[4] &= detail::mask51;   // drops 2^255, completing the subtraction of p
        std::array<std::uint8_t, 32> out{};
        const std::uint64_t w[4] = {h[0] | (h[1] << 51), (h[1] >> 13) | (h[2] << 38), (h[2] >> 26) | (h[3] << 25),
                                    (h[3] >> 39) | (h[4] << 12)};
        for (std::size_t i = 0; i < 4; ++i)
            for (std::size_t j = 0; j < 8; ++j)
                out[8 * i + j] = static_cast<std::uint8_t>(w[i] >> (8 * j));
        return out;
    }

    /// \brief The limbs.
    /// \return The limbs, least significant first.
    [[nodiscard]] constexpr const limbs_type& limbs() const noexcept { return v_; }

    /// \brief Sum.
    /// \param a An element.
    /// \param b Another.
    /// \return a + b.
    [[nodiscard]] friend constexpr field_element operator+(const field_element& a, const field_element& b) noexcept
    {
        limbs_type r{};
        for (std::size_t i = 0; i < 5; ++i)
            r[i] = a.v_[i] + b.v_[i];
        return field_element(r).carried();
    }

    /// \brief Difference.
    /// \param a An element.
    /// \param b Another.
    /// \return a - b.
    [[nodiscard]] friend constexpr field_element operator-(const field_element& a, const field_element& b) noexcept
    {
        // a + 4p - b keeps every limb positive for weakly reduced inputs
        constexpr limbs_type four_p{0x1FFFFFFFFFFFB4ull, 0x1FFFFFFFFFFFFCull, 0x1FFFFFFFFFFFFCull, 0x1FFFFFFFFFFFFCull,
                                    0x1FFFFFFFFFFFFCull};
        limbs_type r{};
        for (std::size_t i = 0; i < 5; ++i)
            r[i] = a.v_[i] + four_p[i] - b.v_[i];
        return field_element(r).carried();
    }

    /// \brief Negation.
    /// \param a An element.
    /// \return -a.
    [[nodiscard]] friend constexpr field_element operator-(const field_element& a) noexcept { return field_element{} - a; }

    /// \brief Product.
    /// \param a An element.
    /// \param b Another.
    /// \return a b.
    [[nodiscard]] friend constexpr field_element operator*(const field_element& a, const field_element& b) noexcept
    {
        using detail::add128;
        using detail::mul64;
        const auto& x = a.v_;
        const auto& y = b.v_;
        const std::uint64_t y1 = 19 * y[1], y2 = 19 * y[2], y3 = 19 * y[3], y4 = 19 * y[4];
        detail::u128 t[5] = {
            add128(add128(add128(add128(mul64(x[0], y[0]), mul64(x[1], y4)), mul64(x[2], y3)), mul64(x[3], y2)), mul64(x[4], y1)),
            add128(add128(add128(add128(mul64(x[0], y[1]), mul64(x[1], y[0])), mul64(x[2], y4)), mul64(x[3], y3)), mul64(x[4], y2)),
            add128(add128(add128(add128(mul64(x[0], y[2]), mul64(x[1], y[1])), mul64(x[2], y[0])), mul64(x[3], y4)), mul64(x[4], y3)),
            add128(add128(add128(add128(mul64(x[0], y[3]), mul64(x[1], y[2])), mul64(x[2], y[1])), mul64(x[3], y[0])), mul64(x[4], y4)),
            add128(add128(add128(add128(mul64(x[0], y[4]), mul64(x[1], y[3])), mul64(x[2], y[2])), mul64(x[3], y[1])), mul64(x[4], y[0])),
        };
        limbs_type r{};
        std::uint64_t c = 0;
        for (std::size_t i = 0; i < 5; ++i) {
            const auto s = add128(t[i], {c, 0});
            r[i] = s.lo & detail::mask51;
            c = detail::shr51(s);
        }
        r[0] += 19 * c;
        r[1] += r[0] >> 51;
        r[0] &= detail::mask51;
        return field_element(r);
    }

    /// \brief The square.
    /// \return this^2.
    [[nodiscard]] constexpr field_element square() const noexcept { return *this * *this; }

    /// \brief this^(2^n), n squarings.
    /// \param n How many squarings; public.
    /// \return The power.
    [[nodiscard]] constexpr field_element square_times(int n) const noexcept
    {
        field_element r = *this;
        for (int i = 0; i < n; ++i)
            r = r.square();
        return r;
    }

    /// \brief The inverse, this^(p-2) by a fixed addition chain (254 squarings, 11 multiplications). Zero maps to zero.
    /// \return 1 / this.
    [[nodiscard]] constexpr field_element invert() const noexcept
    {
        field_element z11{}, z250_0{};
        chain(z11, z250_0);
        return z250_0.square_times(5) * z11;
    }

    /// \brief this^((p-5)/8) = this^(2^252 - 3), the exponent of every square root here.
    /// \return The power.
    [[nodiscard]] constexpr field_element pow22523() const noexcept
    {
        field_element z11{}, z250_0{};
        chain(z11, z250_0);
        return z250_0.square_times(2) * *this;
    }

    /// \brief sqrt(-1) = 2^((p-1)/4).
    /// \return The constant.
    [[nodiscard]] static constexpr field_element sqrt_m1() noexcept
    {
        return field_element(limbs_type{1718705420411056ull, 234908883556509ull, 2233514472574048ull, 2117202627021982ull,
                                        765476049583133ull});
    }

    /// \brief A square root of u / v, in constant time (RFC 8032, section 5.1.3).
    /// \param u The numerator.
    /// \param v The denominator.
    /// \param[out] was_square All ones if u / v is a square (u = 0 included), zero if not (or v = 0 with u != 0).
    /// \return x with v x^2 = u when `was_square`; meaningless otherwise.
    [[nodiscard]] static constexpr field_element sqrt_ratio(const field_element& u, const field_element& v,
                                                            std::uint64_t& was_square) noexcept
    {
        const field_element v3 = v.square() * v;
        const field_element v7 = v3.square() * v;
        field_element x = u * v3 * (u * v7).pow22523();
        const field_element check = v * x.square();
        const std::uint64_t direct = check.equal_mask(u);
        const std::uint64_t flipped = check.equal_mask(-u);
        x = select(flipped, x * sqrt_m1(), x);
        was_square = direct | flipped;
        return x;
    }

    /// \brief All ones if this is zero (as a residue).
    /// \return The mask.
    [[nodiscard]] constexpr std::uint64_t is_zero_mask() const noexcept
    {
        const auto b = to_bytes();
        std::uint64_t acc = 0;
        for (const std::uint8_t x : b)
            acc |= x;
        return ct::mask_is_zero(acc);
    }

    /// \brief Whether this is zero.
    /// \return `true` for zero.
    [[nodiscard]] constexpr bool is_zero() const noexcept { return is_zero_mask() != 0; }

    /// \brief The low bit of the canonical value (RFC 8032's "negative").
    /// \return 1 or 0.
    [[nodiscard]] constexpr std::uint64_t is_negative() const noexcept { return to_bytes()[0] & 1; }

    /// \brief All ones if this equals `other` as a residue.
    /// \param other Another element.
    /// \return The mask.
    [[nodiscard]] constexpr std::uint64_t equal_mask(const field_element& other) const noexcept
    {
        return (*this - other).is_zero_mask();
    }

    /// \brief `a` where `mask` is all ones, `b` where it is zero, in constant time.
    /// \param mask All ones or zero.
    /// \param a The element chosen by all ones.
    /// \param b The element chosen by zero.
    /// \return The selection.
    [[nodiscard]] static constexpr field_element select(std::uint64_t mask, const field_element& a, const field_element& b) noexcept
    {
        limbs_type r{};
        for (std::size_t i = 0; i < 5; ++i)
            r[i] = ct::select(mask, a.v_[i], b.v_[i]);
        return field_element(r);
    }

    /// \brief Swaps `a` and `b` where `mask` is all ones, in constant time.
    /// \param mask All ones or zero.
    /// \param a An element.
    /// \param b Another.
    static constexpr void conditional_swap(std::uint64_t mask, field_element& a, field_element& b) noexcept
    {
        for (std::size_t i = 0; i < 5; ++i)
            ct::conditional_swap(mask, a.v_[i], b.v_[i]);
    }

    /// \brief Equality of residues, in constant time.
    /// \param a An element.
    /// \param b Another.
    /// \return Whether they are equal modulo p.
    [[nodiscard]] friend constexpr bool operator==(const field_element& a, const field_element& b) noexcept
    {
        return a.equal_mask(b) != 0;
    }

private:
    // One carry pass: every limb below 2^51 except limb 1, which may exceed it by a few bits
    [[nodiscard]] constexpr field_element carried() const noexcept
    {
        limbs_type r = v_;
        for (std::size_t i = 0; i < 4; ++i) {
            r[i + 1] += r[i] >> 51;
            r[i] &= detail::mask51;
        }
        r[0] += 19 * (r[4] >> 51);
        r[4] &= detail::mask51;
        r[1] += r[0] >> 51;
        r[0] &= detail::mask51;
        return field_element(r);
    }

    // The shared start of invert and pow22523: z^11 and z^(2^250 - 1)
    constexpr void chain(field_element& z11, field_element& z250_0) const noexcept
    {
        const field_element z2 = square();
        const field_element z9 = z2.square_times(2) * *this;
        z11 = z9 * z2;
        const field_element z5_0 = z11.square() * z9;
        const field_element z10_0 = z5_0.square_times(5) * z5_0;
        const field_element z20_0 = z10_0.square_times(10) * z10_0;
        const field_element z40_0 = z20_0.square_times(20) * z20_0;
        const field_element z50_0 = z40_0.square_times(10) * z10_0;
        const field_element z100_0 = z50_0.square_times(50) * z50_0;
        const field_element z200_0 = z100_0.square_times(100) * z100_0;
        z250_0 = z200_0.square_times(50) * z50_0;
    }

    limbs_type v_{};
};

} // namespace snicholls::crypto::curve25519

#endif /* snicholls_crypto_curve25519_field_hpp */

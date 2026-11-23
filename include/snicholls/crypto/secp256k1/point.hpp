//
//  point.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `secp256k1::point`: the curve y^2 = x^3 + 7, complete addition, and constant-time scalar multiplication.
/// \ingroup secp256k1
///
/// \overview
/// Points in homogeneous projective coordinates (X : Y : Z), with the complete addition and doubling formulas of
/// Renes, Costello and Batina (2016, algorithms 7 and 9 for a = 0): one formula for every pair of inputs, the
/// identity and equal points included, so the arithmetic has no special case to branch on. On top of it:
///
/// - `mul(k, p)` and `mul_base(k)`: k p in constant time, a 4-bit fixed window whose table entry is read by
///   scanning all sixteen entries with masks (no secret index).
/// - `mul_add_public(a, b, q)`: a G + b q for verification and recovery, variable time (it only ever sees public
///   values), Shamir's trick over two 4-bit windows.
/// - `affine_point`, `decompress`, `is_on_curve`: the coordinates public keys are made of.
///
/// \relations
/// - `secp256k1/field.hpp`, `secp256k1/scalar.hpp`: the arithmetic underneath.
/// - `secp256k1/keys.hpp`, `secp256k1/ecdsa.hpp`, `secp256k1/schnorr.hpp`: the users.
/// - Group: \ref secp256k1.
///
/// \impls
/// One. libsecp256k1 is faster (5 x 52 limbs, an endomorphism, precomputed comb tables for G, safegcd inversion);
/// this is the short form whose every secret path is the same instruction sequence for every key.
///
/// \contracts
/// - Value types, trivially copyable, no allocation; every member `constexpr` and `noexcept`.
/// - `mul`, `mul_base`, `to_affine_ct`, `add`, `dbl`: constant time in every argument.
/// - `mul_add_public`, `to_affine`, `decompress`: variable time; they are only for public data.
///
/// \errors
/// None: the identity has no affine form (`to_affine` gives `std::nullopt`), a non-residue x has no point
/// (`decompress` gives `std::nullopt`).
///
/// \examples
/// \snippet secp256k1/point_demo.cpp point
///
/// \perf
/// See `benchmarks/secp256k1/ecdsa_benchmark.cpp` (public key from private key is `mul_base` plus one inversion).
///
/// \testing
/// `tests/secp256k1/point_test.cpp` (G, 2G and kG against published values, the group law at compile time, the
/// identity in every position), `demos/secp256k1/point_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`.
///
/// \gotchas
/// Projective equality compares cross products; two different (X : Y : Z) can be the same point.
///
/// A point multiplication evaluated in a constant expression needs a raised step limit: see the gotchas of `field.hpp`.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secp256k1_point_hpp
#define snicholls_crypto_secp256k1_point_hpp

#include <snicholls/crypto/secp256k1/field.hpp>
#include <snicholls/crypto/secp256k1/scalar.hpp>

#include <array>
#include <cstdint>
#include <optional>

namespace snicholls::crypto::secp256k1 {

/// \brief A point other than the identity, as (x, y). Public data.
/// \ingroup secp256k1
struct affine_point {
    field_element x;   ///< The x coordinate.
    field_element y;   ///< The y coordinate.

    /// \brief Whether it satisfies y^2 = x^3 + 7.
    /// \return `true` on the curve.
    [[nodiscard]] constexpr bool is_on_curve() const noexcept
    {
        return y.square() == x.square() * x + field_element::from_u64(7);
    }

    /// \brief Equality of coordinates.
    /// \param a A point.
    /// \param b Another.
    /// \return Whether x and y agree.
    [[nodiscard]] friend constexpr bool operator==(const affine_point& a, const affine_point& b) noexcept = default;
};

/// \brief The point with this x and the y of this parity, if x is on the curve (public data).
/// \param x The x coordinate.
/// \param odd 1 for the odd y, 0 for the even.
/// \return The point, or `std::nullopt` when x^3 + 7 is not a square.
[[nodiscard]] constexpr std::optional<affine_point> decompress(const field_element& x, std::uint64_t odd) noexcept
{
    const auto y = (x.square() * x + field_element::from_u64(7)).sqrt();
    if (!y)
        return std::nullopt;
    return affine_point{x, y->is_odd() == (odd & 1) ? *y : -*y};
}

/// \brief The generator G.
/// \return G.
[[nodiscard]] constexpr affine_point generator() noexcept
{
    return {field_element::from_limbs({0x59F2815B16F81798ull, 0x029BFCDB2DCE28D9ull, 0x55A06295CE870B07ull, 0x79BE667EF9DCBBACull}),
            field_element::from_limbs({0x9C47D08FFB10D4B8ull, 0xFD17B448A6855419ull, 0x5DA4FBFC0E1108A8ull, 0x483ADA7726A3C465ull})};
}

/// \brief A point in homogeneous projective coordinates (X : Y : Z), the identity being (0 : 1 : 0).
/// \ingroup secp256k1
class point {
public:
    /// \brief The identity.
    constexpr point() noexcept = default;

    /// \brief The point (x, y).
    /// \param a The affine point.
    constexpr explicit point(const affine_point& a) noexcept : x_(a.x), y_(a.y), z_(field_element::from_u64(1)) {}

    /// \brief The identity (the point at infinity).
    /// \return The identity.
    [[nodiscard]] static constexpr point identity() noexcept { return point{}; }

    /// \brief The generator G.
    /// \return G.
    [[nodiscard]] static constexpr point base() noexcept { return point(generator()); }

    /// \brief The sum, by the complete formula (any two points, constant time).
    /// \param p A point.
    /// \param q Another.
    /// \return p + q.
    [[nodiscard]] friend constexpr point operator+(const point& p, const point& q) noexcept
    {
        const field_element b3 = field_element::from_u64(21);
        field_element t0 = p.x_ * q.x_, t1 = p.y_ * q.y_, t2 = p.z_ * q.z_;
        field_element t3 = p.x_ + p.y_, t4 = q.x_ + q.y_;
        t3 = t3 * t4;
        t4 = t0 + t1;
        t3 = t3 - t4;
        t4 = p.y_ + p.z_;
        field_element x3 = q.y_ + q.z_;
        t4 = t4 * x3;
        x3 = t1 + t2;
        t4 = t4 - x3;
        x3 = p.x_ + p.z_;
        field_element y3 = q.x_ + q.z_;
        x3 = x3 * y3;
        y3 = t0 + t2;
        y3 = x3 - y3;
        x3 = t0 + t0;
        t0 = x3 + t0;
        t2 = b3 * t2;
        field_element z3 = t1 + t2;
        t1 = t1 - t2;
        y3 = b3 * y3;
        x3 = t4 * y3;
        t2 = t3 * t1;
        x3 = t2 - x3;
        y3 = y3 * t0;
        t1 = t1 * z3;
        y3 = t1 + y3;
        t0 = t0 * t3;
        z3 = z3 * t4;
        z3 = z3 + t0;
        return point(x3, y3, z3);
    }

    /// \brief Twice this point, by the complete formula.
    /// \return 2 p.
    [[nodiscard]] constexpr point dbl() const noexcept
    {
        const field_element b3 = field_element::from_u64(21);
        field_element t0 = y_.square();
        field_element z3 = t0 + t0;
        z3 = z3 + z3;
        z3 = z3 + z3;
        field_element t1 = y_ * z_;
        field_element t2 = z_.square();
        t2 = b3 * t2;
        field_element x3 = t2 * z3;
        field_element y3 = t0 + t2;
        z3 = t1 * z3;
        t1 = t2 + t2;
        t2 = t1 + t2;
        t0 = t0 - t2;
        y3 = t0 * y3;
        y3 = x3 + y3;
        t1 = x_ * y_;
        x3 = t0 * t1;
        x3 = x3 + x3;
        return point(x3, y3, z3);
    }

    /// \brief The negation.
    /// \param p A point.
    /// \return -p.
    [[nodiscard]] friend constexpr point operator-(const point& p) noexcept { return point(p.x_, -p.y_, p.z_); }

    /// \brief All ones if this is the identity.
    /// \return The mask.
    [[nodiscard]] constexpr std::uint64_t is_identity_mask() const noexcept { return z_.is_zero_mask(); }
    /// \brief Whether this is the identity.
    /// \return `true` for the identity.
    [[nodiscard]] constexpr bool is_identity() const noexcept { return z_.is_zero(); }

    /// \brief The affine coordinates, in constant time; meaningless (zero) for the identity.
    /// \param[out] finite All ones unless this is the identity.
    /// \return (x, y).
    [[nodiscard]] constexpr affine_point to_affine_ct(std::uint64_t& finite) const noexcept
    {
        finite = ~z_.is_zero_mask();
        const field_element zi = z_.inverse();
        return {x_ * zi, y_ * zi};
    }

    /// \brief The affine coordinates (public data).
    /// \return (x, y), or `std::nullopt` for the identity.
    [[nodiscard]] constexpr std::optional<affine_point> to_affine() const noexcept
    {
        std::uint64_t finite = 0;
        const affine_point a = to_affine_ct(finite);
        if (!finite)
            return std::nullopt;
        return a;
    }

    /// \brief `a` where `mask` is all ones, `b` where it is zero, in constant time.
    /// \param mask All ones or zero.
    /// \param a The point chosen by all ones.
    /// \param b The point chosen by zero.
    /// \return The selection.
    [[nodiscard]] static constexpr point select(std::uint64_t mask, const point& a, const point& b) noexcept
    {
        return point(field_element::select(mask, a.x_, b.x_), field_element::select(mask, a.y_, b.y_),
                     field_element::select(mask, a.z_, b.z_));
    }

    /// \brief Whether two points are the same point (cross-multiplied coordinates).
    /// \param p A point.
    /// \param q Another.
    /// \return Equality as points.
    [[nodiscard]] friend constexpr bool operator==(const point& p, const point& q) noexcept
    {
        return p.x_ * q.z_ == q.x_ * p.z_ && p.y_ * q.z_ == q.y_ * p.z_;
    }

    /// \brief k p, in constant time: 4-bit fixed window, table read by masked scan.
    /// \param k The scalar (may be secret).
    /// \param p The point.
    /// \return k p.
    [[nodiscard]] static constexpr point mul(const scalar& k, const point& p) noexcept
    {
        std::array<point, 16> table{};
        table[1] = p;
        for (std::size_t j = 2; j < 16; ++j)
            table[j] = (j % 2 == 0) ? table[j / 2].dbl() : table[j - 1] + p;
        point r;
        for (std::size_t i = 64; i-- > 0;) {
            r = r.dbl().dbl().dbl().dbl();
            const std::uint64_t nib = k.nibble(i);
            point t;
            for (std::size_t j = 0; j < 16; ++j)
                t = select(ct::mask_equal(j, nib), table[j], t);
            r = r + t;
        }
        return r;
    }

    /// \brief k G, in constant time.
    /// \param k The scalar (may be secret).
    /// \return k G.
    [[nodiscard]] static constexpr point mul_base(const scalar& k) noexcept { return mul(k, base()); }

    /// \brief a G + b q, variable time: only for public values (verification, recovery).
    /// \param a The multiple of G.
    /// \param b The multiple of q.
    /// \param q The point.
    /// \return a G + b q.
    [[nodiscard]] static constexpr point mul_add_public(const scalar& a, const scalar& b, const point& q) noexcept
    {
        std::array<point, 16> tg{}, tq{};
        tg[1] = base();
        tq[1] = q;
        for (std::size_t j = 2; j < 16; ++j) {
            tg[j] = tg[j - 1] + tg[1];
            tq[j] = tq[j - 1] + tq[1];
        }
        point r;
        for (std::size_t i = 64; i-- > 0;) {
            r = r.dbl().dbl().dbl().dbl();
            if (const auto na = a.nibble(i))
                r = r + tg[na];
            if (const auto nb = b.nibble(i))
                r = r + tq[nb];
        }
        return r;
    }

private:
    constexpr point(const field_element& x, const field_element& y, const field_element& z) noexcept : x_(x), y_(y), z_(z) {}

    field_element x_{};
    field_element y_ = field_element::from_u64(1);
    field_element z_{};
};

} // namespace snicholls::crypto::secp256k1

#endif /* snicholls_crypto_secp256k1_point_hpp */

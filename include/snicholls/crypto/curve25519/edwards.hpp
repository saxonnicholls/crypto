//
//  edwards.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `curve25519::point`: edwards25519, -x^2 + y^2 = 1 + d x^2 y^2, with complete addition, constant-time
/// scalar multiplication, and RFC 8032 point encoding.
/// \ingroup curve25519
///
/// \overview
/// The group Ed25519 signs in. Points in extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, xy = T/Z, with the
/// addition and doubling formulas of Hisil, Wong, Carter and Dawson (2008) for a = -1, which are complete on this
/// curve (d is not a square): one formula for every pair of points, the identity included. On top of it:
///
/// - `mul(k, p)` and `mul_base(k)`: k p in constant time, a 4-bit fixed window whose table entry is read by scanning
///   all sixteen entries with masks. The sixteen multiples of B are built by the compiler.
/// - `mul_add_public(a, b, q)`: a B + b q for verification, variable time (public data only).
/// - `encode` / `decode`: RFC 8032's 32-byte form, y with the sign of x in bit 255.
/// - `is_small_order`, `mul_by_cofactor`, `is_torsion_free`: the cofactor-8 helpers.
///
/// \relations
/// - `curve25519/field.hpp`, `curve25519/scalar.hpp`: the arithmetic underneath.
/// - `curve25519/ed25519.hpp`: the signature scheme.
/// - Group: \ref curve25519.
///
/// \impls
/// One. Faster libraries use precomputed tables for B in Niels form and signed windows; this is the short form whose
/// secret paths are one instruction sequence for every scalar.
///
/// \contracts
/// - Value type, trivially copyable, no allocation; every member `constexpr` and `noexcept`.
/// - `operator+`, `dbl`, `mul`, `mul_base`, `encode`, `select`: constant time in every argument.
/// - `decode`, `mul_add_public`, `mul_public`, `is_small_order`, `is_torsion_free`, `is_identity`, `operator==`:
///   variable time; public data only.
/// - Decoding is strict (RFC 8032, section 5.1.3): y must be below p (a non-canonical y is rejected), x must exist,
///   and x = 0 with the sign bit set is rejected. Small-order and mixed-order points decode (the caller decides).
///
/// \errors
/// None: an invalid encoding is `std::nullopt`.
///
/// \examples
/// \snippet curve25519/edwards_demo.cpp edwards
///
/// \perf
/// See `benchmarks/curve25519/ed25519_benchmark.cpp` (key generation is one `mul_base` and one encoding).
///
/// \testing
/// `tests/curve25519/edwards_test.cpp` (B encodes to RFC 8032's bytes, the group law at compile time, [L]B is the
/// identity, the eight small-order points, non-canonical encodings), `demos/curve25519/edwards_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`.
///
/// \gotchas
/// Equality is projective (cross products): the same point has many (X : Y : Z : T).
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_curve25519_edwards_hpp
#define snicholls_crypto_curve25519_edwards_hpp

#include <snicholls/crypto/curve25519/field.hpp>
#include <snicholls/crypto/curve25519/scalar.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace snicholls::crypto::curve25519 {

/// \brief A point of edwards25519 in extended coordinates; the identity is (0 : 1 : 1 : 0).
/// \ingroup curve25519
class point {
public:
    /// \brief The identity.
    constexpr point() noexcept = default;

    /// \brief The curve constant d = -121665 / 121666.
    /// \return d.
    [[nodiscard]] static constexpr field_element d() noexcept
    {
        return field_element(field_element::limbs_type{929955233495203ull, 466365720129213ull, 1662059464998953ull,
                                                       2033849074728123ull, 1442794654840575ull});
    }

    /// \brief The identity.
    /// \return The identity.
    [[nodiscard]] static constexpr point identity() noexcept { return point{}; }

    /// \brief The base point B (y = 4/5, x even), of prime order L.
    /// \return B.
    [[nodiscard]] static constexpr point base() noexcept
    {
        return point(field_element(field_element::limbs_type{1738742601995546ull, 1146398526822698ull, 2070867633025821ull,
                                                             562264141797630ull, 587772402128613ull}),
                     field_element(field_element::limbs_type{1801439850948184ull, 1351079888211148ull, 450359962737049ull,
                                                             900719925474099ull, 1801439850948198ull}),
                     field_element::from_u64(1),
                     field_element(field_element::limbs_type{1841354044333475ull, 16398895984059ull, 755974180946558ull,
                                                             900171276175154ull, 1821297809914039ull}));
    }

    /// \brief The point with these affine coordinates; no check that it is on the curve.
    /// \param x The x coordinate.
    /// \param y The y coordinate.
    /// \return (x, y).
    [[nodiscard]] static constexpr point from_affine(const field_element& x, const field_element& y) noexcept
    {
        return point(x, y, field_element::from_u64(1), x * y);
    }

    /// \brief The sum, by the complete formula (constant time).
    /// \param p A point.
    /// \param q Another.
    /// \return p + q.
    [[nodiscard]] friend constexpr point operator+(const point& p, const point& q) noexcept
    {
        const field_element d2 = field_element(field_element::limbs_type{1859910466990425ull, 932731440258426ull, 1072319116312658ull,
                                                                         1815898335770999ull, 633789495995903ull});
        const field_element a = (p.y_ - p.x_) * (q.y_ - q.x_);
        const field_element b = (p.y_ + p.x_) * (q.y_ + q.x_);
        const field_element c = p.t_ * d2 * q.t_;
        const field_element zz = p.z_ * q.z_;
        const field_element dd = zz + zz;
        const field_element e = b - a, f = dd - c, g = dd + c, h = b + a;
        return point(e * f, g * h, f * g, e * h);
    }

    /// \brief The difference.
    /// \param p A point.
    /// \param q Another.
    /// \return p - q.
    [[nodiscard]] friend constexpr point operator-(const point& p, const point& q) noexcept { return p + -q; }

    /// \brief Twice this point (constant time).
    /// \return 2 p.
    [[nodiscard]] constexpr point dbl() const noexcept
    {
        const field_element a = x_.square(), b = y_.square();
        const field_element zz = z_.square();
        const field_element c = zz + zz;
        const field_element h = a + b;
        const field_element e = h - (x_ + y_).square();
        const field_element g = a - b;
        const field_element f = c + g;
        return point(e * f, g * h, f * g, e * h);
    }

    /// \brief The negation.
    /// \param p A point.
    /// \return -p.
    [[nodiscard]] friend constexpr point operator-(const point& p) noexcept { return point(-p.x_, p.y_, p.z_, -p.t_); }

    /// \brief 8 p.
    /// \return The point times the cofactor.
    [[nodiscard]] constexpr point mul_by_cofactor() const noexcept { return dbl().dbl().dbl(); }

    /// \brief Whether this is the identity (public data).
    /// \return `true` for the identity.
    [[nodiscard]] constexpr bool is_identity() const noexcept { return x_.is_zero() && y_ == z_; }

    /// \brief Whether this point has order 1, 2, 4 or 8 (public data).
    /// \return `true` for the eight small-order points.
    [[nodiscard]] constexpr bool is_small_order() const noexcept { return mul_by_cofactor().is_identity(); }

    /// \brief Whether this point is in the prime-order subgroup, [L] p = identity (public data, variable time).
    /// \return `true` when there is no small-order component.
    [[nodiscard]] constexpr bool is_torsion_free() const noexcept
    {
        constexpr std::array<std::uint8_t, 32> order{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                                     0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
        return mul_public(order, *this).is_identity();
    }

    /// \brief `a` where `mask` is all ones, `b` where it is zero, in constant time.
    /// \param mask All ones or zero.
    /// \param a The point chosen by all ones.
    /// \param b The point chosen by zero.
    /// \return The selection.
    [[nodiscard]] static constexpr point select(std::uint64_t mask, const point& a, const point& b) noexcept
    {
        return point(field_element::select(mask, a.x_, b.x_), field_element::select(mask, a.y_, b.y_),
                     field_element::select(mask, a.z_, b.z_), field_element::select(mask, a.t_, b.t_));
    }

    /// \brief The RFC 8032 encoding: y little-endian, bit 255 the low bit of x (constant time).
    /// \return 32 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 32> encode() const noexcept
    {
        const field_element zi = z_.invert();
        const field_element x = x_ * zi, y = y_ * zi;
        auto out = y.to_bytes();
        out[31] = static_cast<std::uint8_t>(out[31] | (x.is_negative() << 7));
        return out;
    }

    /// \brief The point an RFC 8032 encoding names, strictly (public data, variable time).
    /// \param b The 32 bytes.
    /// \return The point, or `std::nullopt` when y is not below p, no x exists, or x = 0 with the sign bit set.
    [[nodiscard]] static constexpr std::optional<point> decode(std::span<const std::uint8_t, 32> b) noexcept
    {
        if (!field_element::is_canonical(b))
            return std::nullopt;
        const field_element y = field_element::from_bytes(b);
        const field_element one = field_element::from_u64(1);
        const field_element yy = y.square();
        std::uint64_t ok = 0;
        field_element x = field_element::sqrt_ratio(yy - one, d() * yy + one, ok);
        if (!ok)
            return std::nullopt;
        const std::uint64_t sign = b[31] >> 7;
        if (x.is_zero() && sign == 1)
            return std::nullopt;
        if (x.is_negative() != sign)
            x = -x;
        return from_affine(x, y);
    }

    /// \brief Whether two points are the same point (public data).
    /// \param p A point.
    /// \param q Another.
    /// \return Equality as points.
    [[nodiscard]] friend constexpr bool operator==(const point& p, const point& q) noexcept
    {
        return p.x_ * q.z_ == q.x_ * p.z_ && p.y_ * q.z_ == q.y_ * p.z_;
    }

    /// \brief k p, in constant time: a 4-bit fixed window, the table read by masked scan.
    /// \param k The scalar (may be secret).
    /// \param p The point.
    /// \return k p.
    [[nodiscard]] static constexpr point mul(const scalar& k, const point& p) noexcept { return mul_window(k, table(p)); }

    /// \brief k B, in constant time.
    /// \param k The scalar (may be secret).
    /// \return k B.
    [[nodiscard]] static constexpr point mul_base(const scalar& k) noexcept;

    /// \brief a B + b q, variable time: public data only (verification).
    /// \param a The multiple of B.
    /// \param b The multiple of q.
    /// \param q The point.
    /// \return a B + b q.
    [[nodiscard]] static constexpr point mul_add_public(const scalar& a, const scalar& b, const point& q) noexcept;

    /// \brief k p for any 256-bit little-endian k, variable time: public data only.
    /// \param k The multiplier's bytes (not reduced modulo L, so L itself can be used).
    /// \param p The point.
    /// \return k p.
    [[nodiscard]] static constexpr point mul_public(std::span<const std::uint8_t, 32> k, const point& p) noexcept
    {
        const auto t = table(p);
        point r;
        for (std::size_t i = 64; i-- > 0;) {
            r = r.dbl().dbl().dbl().dbl();
            const std::uint64_t nib = (k[i / 2] >> (4 * (i % 2))) & 0xf;
            if (nib != 0)
                r = r + t[nib];
        }
        return r;
    }

    /// \brief 0 p to 15 p.
    /// \param p The point.
    /// \return The sixteen multiples.
    [[nodiscard]] static constexpr std::array<point, 16> table(const point& p) noexcept
    {
        std::array<point, 16> t{};
        t[1] = p;
        for (std::size_t j = 2; j < 16; ++j)
            t[j] = (j % 2 == 0) ? t[j / 2].dbl() : t[j - 1] + p;
        return t;
    }

private:
    constexpr point(const field_element& x, const field_element& y, const field_element& z, const field_element& t) noexcept
        : x_(x), y_(y), z_(z), t_(t)
    {
    }

    [[nodiscard]] static constexpr point mul_window(const scalar& k, const std::array<point, 16>& t) noexcept
    {
        point r;
        for (std::size_t i = 64; i-- > 0;) {
            r = r.dbl().dbl().dbl().dbl();
            const std::uint64_t nib = k.nibble(i);
            point e;
            for (std::size_t j = 0; j < 16; ++j)
                e = select(ct::mask_equal(j, nib), t[j], e);
            r = r + e;
        }
        return r;
    }

    field_element x_{};
    field_element y_ = field_element::from_u64(1);
    field_element z_ = field_element::from_u64(1);
    field_element t_{};
};

/// \brief 0 B to 15 B, built by the compiler.
inline constexpr std::array<point, 16> base_multiples = point::table(point::base());

constexpr point point::mul_base(const scalar& k) noexcept { return mul_window(k, base_multiples); }

constexpr point point::mul_add_public(const scalar& a, const scalar& b, const point& q) noexcept
{
    const auto tq = table(q);
    point r;
    for (std::size_t i = 64; i-- > 0;) {
        r = r.dbl().dbl().dbl().dbl();
        if (const auto na = a.nibble(i))
            r = r + base_multiples[na];
        if (const auto nb = b.nibble(i))
            r = r + tq[nb];
    }
    return r;
}

} // namespace snicholls::crypto::curve25519

#endif /* snicholls_crypto_curve25519_edwards_hpp */

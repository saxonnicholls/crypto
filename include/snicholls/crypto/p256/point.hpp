//
//  point.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Points of P-256 (y^2 = x^3 - 3x + b): complete projective addition and scalar multiplication.
/// \ingroup p256
///
/// \overview
/// `point` is a point of P-256 in homogeneous projective coordinates (X : Y : Z), the identity being (0 : 1 : 0).
/// Addition uses complete formulas, correct for every pair of inputs including the identity and doubling, so no
/// input decides a branch. `mul` is the constant-time multiplication used with secrets (keys and nonces);
/// `mul_add_public` computes a G + b Q in variable time for verification. `affine_point` is the decoded form, with
/// SEC1 encoding and the curve equation.
///
/// \relations
/// - `p256/field.hpp`, `p256/scalar.hpp`; `p256/ecdsa.hpp` uses it.
/// - Group: \ref p256.
///
/// \impls
/// One: Renes, Costello and Batina's complete addition for a = -3 (Eurocrypt 2016, Algorithm 4), doubling as an
/// addition of a point to itself, and a 4-bit fixed window whose table entry is read by a masked scan of all 16.
///
/// \contracts
/// - `operator+`, `dbl`, `mul`, `mul_base`, `select`, `to_affine_ct`: constant time (fixed operation sequences;
///   the window's table is scanned whole); the scalar of `mul` may be secret.
/// - `mul_add_public`, `to_affine`, `operator==`, `affine_point::decode` and its checks: variable time; public data
///   only.
/// - `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `affine_point::decode` returns std::nullopt for an encoding that is not SEC1 compressed or uncompressed, a
/// coordinate at or above p, or a point not on the curve; `to_affine` returns std::nullopt for the identity.
///
/// \examples
/// \snippet p256/point_demo.cpp point
///
/// \perf
/// `mul`: 256 doublings and 64 additions, each a complete addition (12 multiplications). See BENCHMARKS.md.
///
/// \testing
/// `tests/p256/point_test.cpp`: the generator on the curve, n G = identity, the group law at compile time, known
/// multiples, and the SEC1 edge cases. `demos/p256/point_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`; `p256/field.hpp`, `p256/scalar.hpp`.
///
/// \gotchas
/// The identity has no affine form and no SEC1 encoding: check `to_affine` before encoding.
///
/// \status
/// Experimental (0.3).

#ifndef snicholls_crypto_p256_point_hpp
#define snicholls_crypto_p256_point_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/p256/field.hpp>
#include <snicholls/crypto/p256/scalar.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace snicholls::crypto::p256 {

namespace detail {
constexpr std::array<std::uint8_t, 32> curve_b{0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd,
                                               0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53,
                                               0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b};
constexpr std::array<std::uint8_t, 32> base_x{0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
                                              0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
                                              0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
constexpr std::array<std::uint8_t, 32> base_y{0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                                              0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
                                              0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
constexpr field_element b() noexcept { return field_element::from_bytes(curve_b).value(); }
} // namespace detail

/// \brief A point of P-256 in affine coordinates (never the identity).
/// \ingroup p256
struct affine_point {
    field_element x;   ///< x.
    field_element y;   ///< y.

    /// \brief Whether y^2 = x^3 - 3x + b (variable time; public data only).
    /// \return True on the curve.
    [[nodiscard]] constexpr bool is_on_curve() const noexcept
    {
        const field_element three = field_element::from_u64(3);
        return y.square() == x.square() * x - three * x + detail::b();
    }

    /// \brief The SEC1 encoding: 0x02 or 0x03 then x (33 bytes).
    /// \return The compressed encoding.
    [[nodiscard]] constexpr std::array<std::uint8_t, 33> compressed() const noexcept
    {
        std::array<std::uint8_t, 33> out{};
        out[0] = static_cast<std::uint8_t>(0x02 | y.is_odd());
        const auto xb = x.to_bytes();
        for (std::size_t i = 0; i < 32; ++i)
            out[1 + i] = xb[i];
        return out;
    }

    /// \brief The SEC1 encoding: 0x04 then x and y (65 bytes).
    /// \return The uncompressed encoding.
    [[nodiscard]] constexpr std::array<std::uint8_t, 65> uncompressed() const noexcept
    {
        std::array<std::uint8_t, 65> out{};
        out[0] = 0x04;
        const auto xb = x.to_bytes(), yb = y.to_bytes();
        for (std::size_t i = 0; i < 32; ++i) {
            out[1 + i] = xb[i];
            out[33 + i] = yb[i];
        }
        return out;
    }

    /// \brief A SEC1 encoding, compressed (33 bytes) or uncompressed (65), checked: coordinates below p, on the curve.
    /// Variable time; public data only. The hybrid form (0x06, 0x07) and the identity (0x00) are refused.
    /// \param b The encoding.
    /// \return The point, or std::nullopt.
    [[nodiscard]] static constexpr std::optional<affine_point> decode(std::span<const std::uint8_t> b) noexcept
    {
        if (b.size() == 65 && b[0] == 0x04) {
            const auto x = field_element::from_bytes(b.subspan<1, 32>());
            const auto y = field_element::from_bytes(b.subspan<33, 32>());
            if (!x || !y)
                return std::nullopt;
            const affine_point p{*x, *y};
            if (!p.is_on_curve())
                return std::nullopt;
            return p;
        }
        if (b.size() == 33 && (b[0] == 0x02 || b[0] == 0x03)) {
            const auto x = field_element::from_bytes(b.subspan<1, 32>());
            if (!x)
                return std::nullopt;
            const field_element rhs = x->square() * *x - field_element::from_u64(3) * *x + detail::b();
            std::uint64_t square = 0;
            field_element y = rhs.sqrt_ct(square);
            if (!square)
                return std::nullopt;
            if (y.is_odd() != (b[0] & 1u))
                y = -y;
            return affine_point{*x, y};
        }
        return std::nullopt;
    }

    /// \brief Equality (variable time).
    /// \param a A point.
    /// \param c Another.
    /// \return Whether they are equal.
    [[nodiscard]] friend constexpr bool operator==(const affine_point& a, const affine_point& c) noexcept = default;
};

/// \brief A point of P-256 in homogeneous projective coordinates, the identity included.
/// \ingroup p256
class point {
public:
    /// \brief The identity, (0 : 1 : 0).
    constexpr point() noexcept = default;

    /// \brief An affine point, with Z = 1.
    /// \param a The point.
    constexpr explicit point(const affine_point& a) noexcept : x_(a.x), y_(a.y), z_(field_element::from_u64(1)) {}

    /// \brief The identity.
    /// \return (0 : 1 : 0).
    [[nodiscard]] static constexpr point identity() noexcept { return point{}; }

    /// \brief The generator G of FIPS 186-5.
    /// \return G.
    [[nodiscard]] static constexpr point base() noexcept
    {
        return point(affine_point{field_element::from_bytes(detail::base_x).value(), field_element::from_bytes(detail::base_y).value()});
    }

    /// \brief Complete addition for a = -3 (Renes, Costello and Batina, Algorithm 4): any two points, constant time.
    /// \param p A point.
    /// \param q Another (p itself included).
    /// \return p + q.
    [[nodiscard]] friend constexpr point operator+(const point& p, const point& q) noexcept
    {
        const field_element b = detail::b();
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
        field_element z3 = b * t2;
        x3 = y3 - z3;
        z3 = x3 + x3;
        x3 = x3 + z3;
        z3 = t1 - x3;
        x3 = t1 + x3;
        y3 = b * y3;
        t1 = t2 + t2;
        t2 = t1 + t2;
        y3 = y3 - t2;
        y3 = y3 - t0;
        t1 = y3 + y3;
        y3 = t1 + y3;
        t1 = t0 + t0;
        t0 = t1 + t0;
        t0 = t0 - t2;
        t1 = t4 * y3;
        t2 = t0 * y3;
        y3 = x3 * z3;
        y3 = y3 + t2;
        x3 = t3 * x3;
        x3 = x3 - t1;
        z3 = t4 * z3;
        t1 = t3 * t0;
        z3 = z3 + t1;
        return point(x3, y3, z3);
    }

    /// \brief Doubling, as the complete addition of the point to itself (constant time).
    /// \return 2 p.
    [[nodiscard]] constexpr point dbl() const noexcept { return *this + *this; }

    /// \brief Negation.
    /// \param p A point.
    /// \return -p.
    [[nodiscard]] friend constexpr point operator-(const point& p) noexcept { return point(p.x_, -p.y_, p.z_); }

    /// \brief Whether the point is the identity, as a mask (constant time).
    /// \return All ones for the identity.
    [[nodiscard]] constexpr std::uint64_t is_identity_mask() const noexcept { return z_.is_zero_mask(); }

    /// \brief Whether the point is the identity (public data only).
    /// \return True for the identity.
    [[nodiscard]] constexpr bool is_identity() const noexcept { return z_.is_zero(); }

    /// \brief The affine form in constant time, with whether the point was finite as a mask (the identity gives (0, 0)).
    /// \param finite Set to all ones unless the point is the identity.
    /// \return The affine coordinates.
    [[nodiscard]] constexpr affine_point to_affine_ct(std::uint64_t& finite) const noexcept
    {
        finite = ~z_.is_zero_mask();
        const field_element zi = z_.inverse();
        return {x_ * zi, y_ * zi};
    }

    /// \brief The affine form, or std::nullopt for the identity (variable time; public data only).
    /// \return The affine coordinates.
    [[nodiscard]] constexpr std::optional<affine_point> to_affine() const noexcept
    {
        std::uint64_t finite = 0;
        const affine_point a = to_affine_ct(finite);
        if (!finite)
            return std::nullopt;
        return a;
    }

    /// \brief a if mask is all ones, b if it is zero, in constant time.
    /// \param mask All ones or zero.
    /// \param a One point.
    /// \param b Another.
    /// \return The selected point.
    [[nodiscard]] static constexpr point select(std::uint64_t mask, const point& a, const point& b) noexcept
    {
        return point(field_element::select(mask, a.x_, b.x_), field_element::select(mask, a.y_, b.y_),
                     field_element::select(mask, a.z_, b.z_));
    }

    /// \brief Equality as points (variable time; public data only).
    /// \param p A point.
    /// \param q Another.
    /// \return Whether they are the same point.
    [[nodiscard]] friend constexpr bool operator==(const point& p, const point& q) noexcept
    {
        return p.x_ * q.z_ == q.x_ * p.z_ && p.y_ * q.z_ == q.y_ * p.z_;
    }

    /// \brief k p in constant time: a 4-bit fixed window, each table entry read by a masked scan of all 16.
    /// \param k The scalar (may be secret).
    /// \param p The point.
    /// \return k p.
    [[nodiscard]] static constexpr point mul(const scalar& k, const point& p) noexcept
    {
        const auto limbs = k.canonical();
        std::array<point, 16> table{};
        table[1] = p;
        for (std::size_t j = 2; j < 16; ++j)
            table[j] = table[j - 1] + p;
        point r;
        for (std::size_t i = 64; i-- > 0;) {
            r = r.dbl().dbl().dbl().dbl();
            const std::uint64_t nib = (limbs[i / 16] >> (4 * (i % 16))) & 0xf;
            point t;
            for (std::size_t j = 0; j < 16; ++j)
                t = select(ct::mask_equal(j, nib), table[j], t);
            r = r + t;
        }
        return r;
    }

    /// \brief k G in constant time.
    /// \param k The scalar (may be secret).
    /// \return k G.
    [[nodiscard]] static constexpr point mul_base(const scalar& k) noexcept { return mul(k, base()); }

    /// \brief a G + b Q in variable time, for verification (public data only).
    /// \param a The scalar of G.
    /// \param b The scalar of Q.
    /// \param q Q.
    /// \return a G + b Q.
    [[nodiscard]] static constexpr point mul_add_public(const scalar& a, const scalar& b, const point& q) noexcept
    {
        const auto la = a.canonical(), lb = b.canonical();
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
            if (const auto na = (la[i / 16] >> (4 * (i % 16))) & 0xf)
                r = r + tg[na];
            if (const auto nb = (lb[i / 16] >> (4 * (i % 16))) & 0xf)
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

} // namespace snicholls::crypto::p256

#endif /* snicholls_crypto_p256_point_hpp */

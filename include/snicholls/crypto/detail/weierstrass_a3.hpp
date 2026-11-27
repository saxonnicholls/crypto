//
//  weierstrass_a3.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Points of a short Weierstrass curve y^2 = x^3 - 3x + b of prime order: the one implementation behind P-256's and
//  P-384's points (p256::affine_point and p256::point, p384::affine_point and p384::point are its instances).
//
//  Curve is a type with `using field` and `using scalar` (detail::mont_residue instances) and static constexpr
//  `b()`, `gx()`, `gy()` returning field elements.
//
//  - `affine_point_t`: SEC1 encode and decode (compressed and uncompressed, coordinates below p, on the curve; the
//    hybrid form and the identity refused), the curve equation.
//  - `point_t`: homogeneous projective coordinates with the complete addition of Renes, Costello and Batina for
//    a = -3 (Algorithm 4), correct for every pair of inputs, the identity and doubling included, so no input decides
//    a branch; `mul` (constant time: a 4-bit fixed window, each table entry read by a masked scan of all 16), and
//    `mul_add_public` (variable time, for verification).
//
//  Constant time: operator+, dbl, mul, mul_base, select, to_affine_ct. Variable time, public data only: decode,
//  is_on_curve, to_affine, operator==, mul_add_public. constexpr, noexcept, no allocation.
//

#ifndef snicholls_crypto_detail_weierstrass_a3_hpp
#define snicholls_crypto_detail_weierstrass_a3_hpp

#include <snicholls/crypto/constant_time.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace snicholls::crypto::detail {

template <class Curve>
struct affine_point_t {
    using field = typename Curve::field;
    static constexpr std::size_t coordinate_bytes = field::size_bytes;

    field x;
    field y;

    // Whether y^2 = x^3 - 3x + b (variable time; public data only)
    [[nodiscard]] constexpr bool is_on_curve() const noexcept { return y.square() == rhs(x); }

    // SEC1: 0x02 or 0x03 then x
    [[nodiscard]] constexpr std::array<std::uint8_t, 1 + coordinate_bytes> compressed() const noexcept
    {
        std::array<std::uint8_t, 1 + coordinate_bytes> out{};
        out[0] = static_cast<std::uint8_t>(0x02 | y.is_odd());
        const auto xb = x.to_bytes();
        for (std::size_t i = 0; i < coordinate_bytes; ++i)
            out[1 + i] = xb[i];
        return out;
    }

    // SEC1: 0x04 then x and y
    [[nodiscard]] constexpr std::array<std::uint8_t, 1 + 2 * coordinate_bytes> uncompressed() const noexcept
    {
        std::array<std::uint8_t, 1 + 2 * coordinate_bytes> out{};
        out[0] = 0x04;
        const auto xb = x.to_bytes(), yb = y.to_bytes();
        for (std::size_t i = 0; i < coordinate_bytes; ++i) {
            out[1 + i] = xb[i];
            out[1 + coordinate_bytes + i] = yb[i];
        }
        return out;
    }

    // A SEC1 encoding, compressed or uncompressed, checked: coordinates below p, on the curve. Variable time
    [[nodiscard]] static constexpr std::optional<affine_point_t> decode(std::span<const std::uint8_t> b) noexcept
    {
        constexpr std::size_t n = coordinate_bytes;
        if (b.size() == 1 + 2 * n && b[0] == 0x04) {
            const auto x = field::from_bytes(b.template subspan<1, n>());
            const auto y = field::from_bytes(b.template subspan<1 + n, n>());
            if (!x || !y)
                return std::nullopt;
            const affine_point_t p{*x, *y};
            if (!p.is_on_curve())
                return std::nullopt;
            return p;
        }
        if (b.size() == 1 + n && (b[0] == 0x02 || b[0] == 0x03)) {
            const auto x = field::from_bytes(b.template subspan<1, n>());
            if (!x)
                return std::nullopt;
            std::uint64_t square = 0;
            field y = rhs(*x).sqrt_ct(square);
            if (!square)
                return std::nullopt;
            if (y.is_odd() != (b[0] & 1u))
                y = -y;
            return affine_point_t{*x, y};
        }
        return std::nullopt;
    }

    [[nodiscard]] friend constexpr bool operator==(const affine_point_t& a, const affine_point_t& c) noexcept = default;

private:
    static constexpr field rhs(const field& x) noexcept { return x.square() * x - field::from_u64(3) * x + Curve::b(); }
};

template <class Curve>
class point_t {
public:
    using field = typename Curve::field;
    using scalar = typename Curve::scalar;
    using affine = affine_point_t<Curve>;

    // The identity, (0 : 1 : 0)
    constexpr point_t() noexcept = default;

    // An affine point, with Z = 1
    constexpr explicit point_t(const affine& a) noexcept : x_(a.x), y_(a.y), z_(field::from_u64(1)) {}

    [[nodiscard]] static constexpr point_t identity() noexcept { return point_t{}; }

    [[nodiscard]] static constexpr point_t base() noexcept { return point_t(affine{Curve::gx(), Curve::gy()}); }

    // Complete addition for a = -3 (Renes, Costello and Batina, Algorithm 4): any two points, constant time
    [[nodiscard]] friend constexpr point_t operator+(const point_t& p, const point_t& q) noexcept
    {
        const field b = Curve::b();
        field t0 = p.x_ * q.x_, t1 = p.y_ * q.y_, t2 = p.z_ * q.z_;
        field t3 = p.x_ + p.y_, t4 = q.x_ + q.y_;
        t3 = t3 * t4;
        t4 = t0 + t1;
        t3 = t3 - t4;
        t4 = p.y_ + p.z_;
        field x3 = q.y_ + q.z_;
        t4 = t4 * x3;
        x3 = t1 + t2;
        t4 = t4 - x3;
        x3 = p.x_ + p.z_;
        field y3 = q.x_ + q.z_;
        x3 = x3 * y3;
        y3 = t0 + t2;
        y3 = x3 - y3;
        field z3 = b * t2;
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
        return point_t(x3, y3, z3);
    }

    [[nodiscard]] constexpr point_t dbl() const noexcept { return *this + *this; }

    [[nodiscard]] friend constexpr point_t operator-(const point_t& p) noexcept { return point_t(p.x_, -p.y_, p.z_); }

    [[nodiscard]] constexpr std::uint64_t is_identity_mask() const noexcept { return z_.is_zero_mask(); }
    [[nodiscard]] constexpr bool is_identity() const noexcept { return z_.is_zero(); }

    // The affine form in constant time, with whether the point was finite as a mask (the identity gives (0, 0))
    [[nodiscard]] constexpr affine to_affine_ct(std::uint64_t& finite) const noexcept
    {
        finite = ~z_.is_zero_mask();
        const field zi = z_.inverse();
        return {x_ * zi, y_ * zi};
    }

    // The affine form, or std::nullopt for the identity (variable time; public data only)
    [[nodiscard]] constexpr std::optional<affine> to_affine() const noexcept
    {
        std::uint64_t finite = 0;
        const affine a = to_affine_ct(finite);
        if (!finite)
            return std::nullopt;
        return a;
    }

    [[nodiscard]] static constexpr point_t select(std::uint64_t mask, const point_t& a, const point_t& b) noexcept
    {
        return point_t(field::select(mask, a.x_, b.x_), field::select(mask, a.y_, b.y_), field::select(mask, a.z_, b.z_));
    }

    // Equality as points (variable time; public data only)
    [[nodiscard]] friend constexpr bool operator==(const point_t& p, const point_t& q) noexcept
    {
        return p.x_ * q.z_ == q.x_ * p.z_ && p.y_ * q.z_ == q.y_ * p.z_;
    }

    // k p in constant time: a 4-bit fixed window, each table entry read by a masked scan of all 16
    [[nodiscard]] static constexpr point_t mul(const scalar& k, const point_t& p) noexcept
    {
        constexpr std::size_t nibbles = 16 * scalar::limbs;
        const auto limbs = k.canonical();
        std::array<point_t, 16> table{};
        table[1] = p;
        for (std::size_t j = 2; j < 16; ++j)
            table[j] = table[j - 1] + p;
        point_t r;
        for (std::size_t i = nibbles; i-- > 0;) {
            r = r.dbl().dbl().dbl().dbl();
            const std::uint64_t nib = (limbs[i / 16] >> (4 * (i % 16))) & 0xf;
            point_t t;
            for (std::size_t j = 0; j < 16; ++j)
                t = select(ct::mask_equal(j, nib), table[j], t);
            r = r + t;
        }
        return r;
    }

    [[nodiscard]] static constexpr point_t mul_base(const scalar& k) noexcept { return mul(k, base()); }

    // a G + b Q in variable time, for verification (public data only)
    [[nodiscard]] static constexpr point_t mul_add_public(const scalar& a, const scalar& b, const point_t& q) noexcept
    {
        constexpr std::size_t nibbles = 16 * scalar::limbs;
        const auto la = a.canonical(), lb = b.canonical();
        std::array<point_t, 16> tg{}, tq{};
        tg[1] = base();
        tq[1] = q;
        for (std::size_t j = 2; j < 16; ++j) {
            tg[j] = tg[j - 1] + tg[1];
            tq[j] = tq[j - 1] + tq[1];
        }
        point_t r;
        for (std::size_t i = nibbles; i-- > 0;) {
            r = r.dbl().dbl().dbl().dbl();
            if (const auto na = (la[i / 16] >> (4 * (i % 16))) & 0xf)
                r = r + tg[na];
            if (const auto nb = (lb[i / 16] >> (4 * (i % 16))) & 0xf)
                r = r + tq[nb];
        }
        return r;
    }

private:
    constexpr point_t(const field& x, const field& y, const field& z) noexcept : x_(x), y_(y), z_(z) {}

    field x_{};
    field y_ = field::from_u64(1);
    field z_{};
};

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_weierstrass_a3_hpp */

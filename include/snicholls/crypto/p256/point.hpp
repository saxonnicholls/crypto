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
#include <snicholls/crypto/detail/weierstrass_a3.hpp>
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

// The curve, for detail::weierstrass_a3
struct curve {
    using field = field_element;
    using scalar = p256::scalar;
    static constexpr field_element b() noexcept { return detail::b(); }
    static constexpr field_element gx() noexcept { return field_element::from_bytes(base_x).value(); }
    static constexpr field_element gy() noexcept { return field_element::from_bytes(base_y).value(); }
};
} // namespace detail

/// \brief A point of P-256 in affine coordinates (never the identity): `x`, `y`, `is_on_curve`, `compressed` (33
/// bytes), `uncompressed` (65), `decode` (SEC1, checked; variable time, public data only), `==`. The class is
/// `detail::affine_point_t`, shared with P-384.
/// \ingroup p256
using affine_point = crypto::detail::affine_point_t<detail::curve>;

/// \brief A point of P-256 in homogeneous projective coordinates, the identity included: complete addition for
/// a = -3 (`+`, `dbl`, `-`), `mul` and `mul_base` in constant time (a 4-bit fixed window, masked table scans),
/// `mul_add_public` for verification (variable time), `to_affine_ct`, `to_affine`, `select`, `==`. The class is
/// `detail::point_t`, shared with P-384.
/// \ingroup p256
using point = crypto::detail::point_t<detail::curve>;

} // namespace snicholls::crypto::p256

#endif /* snicholls_crypto_p256_point_hpp */

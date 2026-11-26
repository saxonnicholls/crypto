//
//  point.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Points of P-384 (y^2 = x^3 - 3x + b): complete projective addition and scalar multiplication.
/// \ingroup p384
///
/// \overview
/// `point` is a point of P-384 in homogeneous projective coordinates (X : Y : Z), the identity being (0 : 1 : 0).
/// Addition uses complete formulas, correct for every pair of inputs including the identity and doubling, so no
/// input decides a branch. `mul` is the constant-time multiplication used with secrets (keys, ECDH);
/// `mul_add_public` computes a G + b Q in variable time for verification. `affine_point` is the decoded form, with
/// SEC1 encoding (49 or 97 bytes) and the curve equation.
///
/// \relations
/// - `detail/weierstrass_a3.hpp`: the one implementation, shared with P-256's points; `p384/field.hpp`,
///   `p384/scalar.hpp`; `p384/ecdsa.hpp` and `p384/ecdh.hpp` use it.
/// - Group: \ref p384.
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
/// \snippet p384/point_demo.cpp point384
///
/// \perf
/// `mul`: 384 doublings and 96 additions, each a complete addition (12 multiplications of six limbs). See
/// BENCHMARKS.md.
///
/// \testing
/// `tests/p384/point_test.cpp`: the generator on the curve, n G = identity, the group law, known multiples, and the
/// SEC1 edge cases. `demos/p384/point_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`; `p384/field.hpp`, `p384/scalar.hpp`, `detail/weierstrass_a3.hpp`.
///
/// \gotchas
/// The identity has no affine form and no SEC1 encoding: check `to_affine` before encoding.
///
/// \status
/// Experimental (0.6).

#ifndef snicholls_crypto_p384_point_hpp
#define snicholls_crypto_p384_point_hpp

#include <snicholls/crypto/detail/weierstrass_a3.hpp>
#include <snicholls/crypto/p384/field.hpp>
#include <snicholls/crypto/p384/scalar.hpp>

#include <array>
#include <cstdint>

namespace snicholls::crypto::p384 {

namespace detail {
constexpr std::array<std::uint8_t, 48> curve_b{0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b,
                                               0xe3, 0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
                                               0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d,
                                               0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef};
constexpr std::array<std::uint8_t, 48> base_x{0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e,
                                              0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
                                              0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d,
                                              0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7};
constexpr std::array<std::uint8_t, 48> base_y{0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
                                              0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
                                              0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
                                              0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f};

// The curve, for detail::weierstrass_a3
struct curve {
    using field = field_element;
    using scalar = p384::scalar;
    static constexpr field_element b() noexcept { return field_element::from_bytes(curve_b).value(); }
    static constexpr field_element gx() noexcept { return field_element::from_bytes(base_x).value(); }
    static constexpr field_element gy() noexcept { return field_element::from_bytes(base_y).value(); }
};
} // namespace detail

/// \brief A point of P-384 in affine coordinates (never the identity): `x`, `y`, `is_on_curve`, `compressed` (49
/// bytes), `uncompressed` (97), `decode` (SEC1, checked; variable time, public data only), `==`. The class is
/// `detail::affine_point_t`, shared with P-256.
/// \ingroup p384
using affine_point = crypto::detail::affine_point_t<detail::curve>;

/// \brief A point of P-384 in homogeneous projective coordinates, the identity included: complete addition for
/// a = -3 (`+`, `dbl`, `-`), `mul` and `mul_base` in constant time (a 4-bit fixed window, masked table scans),
/// `mul_add_public` for verification (variable time), `to_affine_ct`, `to_affine`, `select`, `==`. The class is
/// `detail::point_t`, shared with P-256.
/// \ingroup p384
using point = crypto::detail::point_t<detail::curve>;

} // namespace snicholls::crypto::p384

#endif /* snicholls_crypto_p384_point_hpp */

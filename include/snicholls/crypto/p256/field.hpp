//
//  field.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief The field of P-256: integers modulo p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
/// \ingroup p256
///
/// \overview
/// `field_element` holds an integer modulo P-256's prime in Montgomery form; addition, subtraction, multiplication,
/// Fermat's inverse and the square root (p = 3 mod 4). Used by `p256/point.hpp`.
///
/// \relations
/// `detail/mont.hpp` and `detail/mont_residue.hpp` (the arithmetic and the class, shared with `p256/scalar.hpp` and
/// P-384); `p256/point.hpp`. Group: \ref p256.
///
/// \impls
/// One: Montgomery multiplication (CIOS, four 64-bit limbs) with a masked final subtraction.
///
/// \contracts
/// Constant time throughout, for secret or public values alike (no branch or index on a value); `from_bytes`
/// declassifies only whether the bytes were canonical. `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `from_bytes` returns std::nullopt for a value at or above p.
///
/// \examples
/// \snippet p256/field_demo.cpp field
///
/// \perf
/// One multiplication: 16 64-bit products and a reduction of the same size. See BENCHMARKS.md (`p256/ecdsa`).
///
/// \testing
/// `tests/p256/field_test.cpp`: identities at compile time (inverse, square root, distributivity), boundary values.
/// `demos/p256/field_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<optional>`, `<span>`; core's `result.hpp` and SHA-256; `detail/mont256.hpp`.
///
/// \gotchas
/// Values are in Montgomery form: compare them with `==` only against other `field_element`s, and read them with
/// `to_bytes` or `canonical`.
///
/// \status
/// Experimental (0.3).

#ifndef snicholls_crypto_p256_field_hpp
#define snicholls_crypto_p256_field_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/limbs.hpp>
#include <snicholls/crypto/detail/mont256.hpp>
#include <snicholls/crypto/detail/mont_residue.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

/// \brief P-256 (secp256r1, NIST FIPS 186-5, SEC 2): its field, scalars, points and ECDSA.
namespace snicholls::crypto::p256 {

namespace detail {
inline constexpr crypto::detail::mont256_params field_params = crypto::detail::make_mont256(crypto::detail::from_be(
    std::array<std::uint8_t, 32>{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
} // namespace detail

namespace detail {
struct field_modulus {
    static constexpr const crypto::detail::mont256_params& params() noexcept { return field_params; }
};
} // namespace detail

/// \brief An integer modulo p, kept in Montgomery form, fully reduced: `from_u64`, `from_bytes` (strict: refused at
/// or above p), `from_bytes_ct`, `to_bytes`, `+`, `-`, `*`, `square`, `inverse` (Fermat), `sqrt_ct` (p = 3 mod 4),
/// `is_odd`, `is_zero_mask`, `select`, `==`. The class is `detail::mont_residue<4, ...>`, shared with P-384.
/// \ingroup p256
using field_element = crypto::detail::mont_residue<4, detail::field_modulus>;

} // namespace snicholls::crypto::p256

#endif /* snicholls_crypto_p256_field_hpp */

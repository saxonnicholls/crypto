//
//  field.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief The field of P-384: integers modulo p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
/// \ingroup p384
///
/// \overview
/// `field_element` holds an integer modulo P-384's prime in Montgomery form, on six 64-bit limbs: addition,
/// subtraction, multiplication, Fermat's inverse and the square root (p = 3 mod 4). Used by `p384/point.hpp`.
///
/// \relations
/// `detail/mont.hpp` and `detail/mont_residue.hpp`: the arithmetic and the class, the same code as P-256's field
/// and scalars at six limbs instead of four; `p384/point.hpp`. Group: \ref p384.
///
/// \impls
/// One: Montgomery multiplication (CIOS, six 64-bit limbs) with a masked final subtraction.
///
/// \contracts
/// Constant time throughout, for secret or public values alike (no branch or index on a value); `from_bytes`
/// declassifies only whether the bytes were canonical. `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `from_bytes` returns std::nullopt for a value at or above p.
///
/// \examples
/// \snippet p384/field_demo.cpp field384
///
/// \perf
/// One multiplication: 36 64-bit products and a reduction of the same size. See BENCHMARKS.md (`p384/ecdsa`).
///
/// \testing
/// `tests/p384/field_test.cpp`: identities at compile time (inverse, square root, distributivity), boundary values.
/// `demos/p384/field_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`; `detail/mont.hpp`, `detail/mont_residue.hpp`.
///
/// \gotchas
/// Values are in Montgomery form: compare them with `==` only against other `field_element`s, and read them with
/// `to_bytes` or `canonical`.
///
/// \status
/// Experimental (0.5).

#ifndef snicholls_crypto_p384_field_hpp
#define snicholls_crypto_p384_field_hpp

#include <snicholls/crypto/detail/mont.hpp>
#include <snicholls/crypto/detail/mont_residue.hpp>

#include <array>
#include <cstdint>

/// \brief P-384 (secp384r1, NIST FIPS 186-5, SEC 2): its field, scalars, points, ECDSA verification and ECDH.
namespace snicholls::crypto::p384 {

namespace detail {
inline constexpr crypto::detail::mont_params<6> field_params = crypto::detail::make_mont<6>(crypto::detail::from_be_n<6>(std::array<std::uint8_t, 48>{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}));
struct field_modulus {
    static constexpr const crypto::detail::mont_params<6>& params() noexcept { return field_params; }
};
} // namespace detail

/// \brief An integer modulo p, kept in Montgomery form, fully reduced: `from_u64`, `from_bytes` (48 bytes, strict:
/// refused at or above p), `from_bytes_ct`, `to_bytes`, `+`, `-`, `*`, `square`, `inverse` (Fermat), `sqrt_ct`
/// (p = 3 mod 4), `is_odd`, `is_zero_mask`, `select`, `==`. The class is `detail::mont_residue<6, ...>`, the same
/// as P-256's at six limbs.
/// \ingroup p384
using field_element = crypto::detail::mont_residue<6, detail::field_modulus>;

} // namespace snicholls::crypto::p384

#endif /* snicholls_crypto_p384_field_hpp */

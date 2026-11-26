//
//  scalar.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Scalars of P-384: integers modulo the group order n.
/// \ingroup p384
///
/// \overview
/// `scalar` holds an integer modulo P-384's group order n in Montgomery form: private keys and the ECDSA arithmetic
/// of `p384/ecdsa.hpp`.
///
/// \relations
/// `detail/mont.hpp`, `detail/mont_residue.hpp` (shared with P-256); `p384/ecdsa.hpp`. Group: \ref p384.
///
/// \impls
/// One: Montgomery multiplication (CIOS, six 64-bit limbs) with a masked final subtraction; Fermat's inverse.
///
/// \contracts
/// Constant time throughout: a private key never decides a branch or an index; `from_bytes` declassifies only
/// whether the bytes were below n. `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `from_bytes` returns std::nullopt for a value at or above n.
///
/// \examples
/// \snippet p384/scalar_demo.cpp scalar384
///
/// \perf
/// See BENCHMARKS.md (`p384/ecdsa`).
///
/// \testing
/// `tests/p384/scalar_test.cpp`: identities at compile time, n - 1, reduction of values at and above n.
/// `demos/p384/scalar_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`; `detail/mont.hpp`, `detail/mont_residue.hpp`.
///
/// \gotchas
/// A scalar of zero is a valid element but not a valid private key: `p384/ecdsa.hpp`'s `private_key` refuses it.
/// A 48-byte hash is reduced modulo n with `from_bytes_reduced` (SHA-384's length is the order's).
///
/// \status
/// Experimental (0.6).

#ifndef snicholls_crypto_p384_scalar_hpp
#define snicholls_crypto_p384_scalar_hpp

#include <snicholls/crypto/detail/mont.hpp>
#include <snicholls/crypto/detail/mont_residue.hpp>

#include <array>
#include <cstdint>

namespace snicholls::crypto::p384 {

namespace detail {
inline constexpr crypto::detail::mont_params<6> order_params = crypto::detail::make_mont<6>(crypto::detail::from_be_n<6>(std::array<std::uint8_t, 48>{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73}));
struct order_modulus {
    static constexpr const crypto::detail::mont_params<6>& params() noexcept { return order_params; }
};
} // namespace detail

/// \brief An integer modulo the group order n, kept in Montgomery form, fully reduced: `from_u64`, `from_bytes`
/// (48 bytes, strict: refused at or above n), `from_bytes_ct`, `from_bytes_reduced` (a hash, reduced once),
/// `order_bytes`, `to_bytes`, `+`, `-`, `*`, `inverse` (Fermat), `is_zero_mask`, `select`, `==`. The class is
/// `detail::mont_residue<6, ...>`, the same as P-256's at six limbs.
/// \ingroup p384
using scalar = crypto::detail::mont_residue<6, detail::order_modulus>;

} // namespace snicholls::crypto::p384

#endif /* snicholls_crypto_p384_scalar_hpp */

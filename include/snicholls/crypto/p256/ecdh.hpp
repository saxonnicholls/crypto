//
//  ecdh.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief ECDH on P-256 (SEC 1 3.3.1, NIST SP 800-56A's primitive): the shared secret, the x-coordinate of d Q.
/// \ingroup p256
///
/// \overview
/// `shared_secret(own private key, peer's public key)` returns the 32 bytes both sides compute: the big-endian
/// x-coordinate of d Q. It is the `Z` of JOSE's ECDH-ES (RFC 7518 4.6) and of every other P-256 key agreement, and
/// like X25519's it is input to a KDF (`jose/ecdh_es.hpp`), never a key itself.
///
/// \relations
/// - `p256/ecdsa.hpp`: the key types; `p256/point.hpp`: `point::mul`.
/// - `curve25519/x25519.hpp`: the same agreement on Curve25519; `jose/ecdh_es.hpp`: the KDF JOSE puts on top.
/// - Group: \ref p256.
///
/// \impls
/// One: `point::mul` (a 4-bit fixed window over complete addition) and the constant-time conversion to affine.
///
/// \contracts
/// - Constant time in the private key; the peer's key is public. Revealed on purpose (`ct::declassify`): whether
///   d Q is the identity, which cannot happen for a key that `public_key::parse` accepted (P-256 has prime order).
/// - The peer's point is checked to be on the curve again before it is multiplied (an invalid-curve attack would
///   otherwise learn d modulo the small factors of another curve's order: the complete formulas compute on any
///   curve with a = -3), so a `public_key` built from an unchecked `affine_point` is refused, not used.
/// - The result is in `secret_bytes<32>`; intermediates are wiped. `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `errc::invalid_public_key` when the peer's point is not on the curve, or d Q is the identity.
///
/// \examples
/// \snippet p256/ecdh_demo.cpp p256_ecdh
///
/// \perf
/// One `point::mul` and one inversion. See BENCHMARKS.md, `benchmarks/p256/ecdh_benchmark.cpp`.
///
/// \testing
/// `tests/p256/ecdh_test.cpp`: RFC 7518 appendix C's keys (the KDF output is checked in `tests/jose/`), every
/// Wycheproof `ecdh_secp256r1_ecpoint_test` case (`tests/fixtures/wycheproof/ecdh_p256.txt`), both orders of the
/// agreement, an off-curve point. The secret path is in the Valgrind check (`tests/ct/secret_marking.cpp`).
/// `demos/p256/ecdh_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`.
///
/// \gotchas
/// The shared secret is not uniformly random: put it through a KDF (Concat KDF for JOSE, HKDF elsewhere). An
/// ephemeral key must be fresh for every message: the caller makes it from a system random source.
///
/// \status
/// Experimental (0.5).

#ifndef snicholls_crypto_p256_ecdh_hpp
#define snicholls_crypto_p256_ecdh_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/p256/ecdsa.hpp>
#include <snicholls/crypto/p256/point.hpp>
#include <snicholls/crypto/p256/scalar.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <utility>

namespace snicholls::crypto::p256 {

/// \brief The ECDH shared secret with a peer: the 32-byte big-endian x-coordinate of d Q.
/// \ingroup p256
/// \param key Our private key d (secret).
/// \param peer The peer's public key Q (public; checked to be on the curve).
/// \return The shared secret, or `errc::invalid_public_key`.
[[nodiscard]] constexpr result<secret_bytes<32>, errc> shared_secret(const private_key& key, const public_key& peer) noexcept
{
    if (!peer.point().is_on_curve())   // public data
        return err(errc::invalid_public_key);
    scalar d = key.to_scalar();
    std::uint64_t finite = 0;
    affine_point s = point::mul(d, point(peer.point())).to_affine_ct(finite);
    secure_wipe(d);
    std::array<std::uint8_t, 32> x = s.x.to_bytes();
    secure_wipe(s);
    if (!ct::declassify(finite != 0)) {
        secure_wipe(x);
        return err(errc::invalid_public_key);
    }
    return ok(secret_bytes<32>(std::move(x)));
}

} // namespace snicholls::crypto::p256

#endif /* snicholls_crypto_p256_ecdh_hpp */

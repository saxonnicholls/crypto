//
//  x25519.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief X25519 (RFC 7748): Diffie-Hellman on Curve25519 with the Montgomery ladder.
/// \ingroup curve25519
///
/// \overview
/// Key agreement: each side has a 32-byte secret, publishes `public_key_from_secret(secret)`, and computes
/// `shared_secret(own secret, peer's public key)`; both get the same 32 bytes, which are input to a KDF, never a key
/// themselves. `scalar_mult` is RFC 7748's X25519 function itself, for the test vectors and for protocols that
/// define their own checks.
///
/// RFC 7748's rules, as implemented:
///
/// - The secret is clamped (`clamp`: bits 0, 1, 2 and 255 cleared, bit 254 set) inside every call: callers pass
///   32 uniformly random bytes or KDF output as they are.
/// - The peer's u-coordinate is decoded with bit 255 masked, and values from p to 2^255 - 1 are accepted and reduced
///   (section 5: "implementations MUST accept non-canonical values").
/// - `shared_secret` refuses the all-zero output with `errc::small_order` (the check section 6.1 describes): the
///   peer's key had small order, so the result is independent of the secret. `scalar_mult` makes no such check.
/// - Public keys on the twist are not rejected (X25519 is twist-secure); Wycheproof marks those "acceptable".
///
/// \relations
/// - `curve25519/field.hpp`: the arithmetic; `curve25519/ed25519.hpp`: signatures on the same curve.
/// - Group: \ref curve25519.
///
/// \impls
/// One: the Montgomery ladder of RFC 7748, section 5, with a constant-time conditional swap per bit and one
/// inversion at the end.
///
/// \contracts
/// - `scalar_mult`, `public_key_from_secret`, `shared_secret`, `clamp`: constant time in the secret (255 ladder steps
///   whatever its value; swaps are masked); the u-coordinate is public. The all-zero check reveals only that the
///   output is zero, which the error reports anyway.
/// - The shared secret is returned in `secret_bytes<32>`; intermediates are wiped.
/// - Everything is `constexpr` and `noexcept`; no allocation.
///
/// \errors
/// `shared_secret` returns `errc::small_order` for the all-zero shared secret.
///
/// \examples
/// \snippet curve25519/x25519_demo.cpp x25519
///
/// \perf
/// See BENCHMARKS.md, `benchmarks/curve25519/x25519_benchmark.cpp`.
///
/// \testing
/// `tests/curve25519/x25519_test.cpp`: RFC 7748 section 5.2 (both vectors, 1 and 1,000 iterations; 1,000,000 as a
/// disabled test), section 6.1 (Alice and Bob), and all 518 Wycheproof `x25519_test.json` cases
/// (`tests/fixtures/wycheproof/x25519.txt`). `demos/curve25519/x25519_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`.
///
/// \gotchas
/// The shared secret is not uniformly random: hash it (HKDF) before using it as a key, and bind both public keys
/// into that derivation if the protocol needs it.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_curve25519_x25519_hpp
#define snicholls_crypto_curve25519_x25519_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/curve25519/field.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

/// \brief X25519 key agreement (RFC 7748).
namespace snicholls::crypto::x25519 {

/// \brief An X25519 public key: a u-coordinate, 32 bytes little-endian.
/// \ingroup curve25519
struct public_key {
    std::array<std::uint8_t, 32> bytes{};   ///< The u-coordinate.

    /// \brief Equality of the bytes.
    /// \param a A key.
    /// \param b Another.
    /// \return Whether the bytes agree.
    [[nodiscard]] friend constexpr bool operator==(const public_key& a, const public_key& b) noexcept = default;
};

/// \brief RFC 7748's clamping: bits 0, 1, 2 and 255 cleared, bit 254 set.
/// \param k The 32 bytes.
/// \return The clamped scalar.
[[nodiscard]] constexpr std::array<std::uint8_t, 32> clamp(std::span<const std::uint8_t, 32> k) noexcept
{
    std::array<std::uint8_t, 32> c{};
    for (std::size_t i = 0; i < 32; ++i)
        c[i] = k[i];
    c[0] = static_cast<std::uint8_t>(c[0] & 248);
    c[31] = static_cast<std::uint8_t>((c[31] & 127) | 64);
    return c;
}

/// \brief The X25519 function of RFC 7748, section 5: clamp k, decode u, run the ladder, encode.
/// \param k The scalar's 32 bytes (secret; clamped here).
/// \param u The u-coordinate's 32 bytes (public; bit 255 masked, non-canonical values accepted).
/// \return The 32-byte result, all zero for a small-order u (no check here; the caller wipes it).
[[nodiscard]] constexpr std::array<std::uint8_t, 32> scalar_mult(std::span<const std::uint8_t, 32> k,
                                                                  std::span<const std::uint8_t, 32> u) noexcept
{
    using curve25519::field_element;
    auto e = clamp(k);
    const field_element x1 = field_element::from_bytes(u);
    const field_element a24 = field_element::from_u64(121665);
    field_element x2 = field_element::from_u64(1), z2{}, x3 = x1, z3 = field_element::from_u64(1);
    std::uint64_t swap = 0;
    for (int t = 254; t >= 0; --t) {
        const std::uint64_t bit = (e[static_cast<std::size_t>(t) / 8] >> (t % 8)) & 1;
        swap ^= bit;
        const std::uint64_t mask = ct::mask_from_bit(swap);
        field_element::conditional_swap(mask, x2, x3);
        field_element::conditional_swap(mask, z2, z3);
        swap = bit;
        const field_element a = x2 + z2, aa = a.square(), b = x2 - z2, bb = b.square(), ee = aa - bb;
        const field_element c = x3 + z3, d = x3 - z3, da = d * a, cb = c * b;
        x3 = (da + cb).square();
        z3 = x1 * (da - cb).square();
        x2 = aa * bb;
        z2 = ee * (aa + a24 * ee);
    }
    const std::uint64_t mask = ct::mask_from_bit(swap);
    field_element::conditional_swap(mask, x2, x3);
    field_element::conditional_swap(mask, z2, z3);
    const auto out = (x2 * z2.invert()).to_bytes();
    secure_wipe(e);
    secure_wipe(x2);
    secure_wipe(z2);
    secure_wipe(x3);
    secure_wipe(z3);
    return out;
}

/// \brief The public key of a secret: X25519(secret, 9).
/// \param secret The 32-byte secret (clamped inside).
/// \return The public key.
[[nodiscard]] constexpr public_key public_key_from_secret(const secret_bytes<32>& secret) noexcept
{
    constexpr std::array<std::uint8_t, 32> nine{9};
    return {scalar_mult(secret.reveal(), nine)};
}

/// \brief The shared secret with a peer, refusing a small-order peer key.
/// \param secret Our 32-byte secret (clamped inside).
/// \param peer The peer's public key.
/// \return The 32-byte shared secret, or `errc::small_order` when it is all zero.
[[nodiscard]] constexpr snicholls::result<secret_bytes<32>, errc> shared_secret(const secret_bytes<32>& secret,
                                                                                const public_key& peer) noexcept
{
    auto out = scalar_mult(secret.reveal(), peer.bytes);
    if (ct::declassify(ct::is_zero(out)))
        return snicholls::err(errc::small_order);
    return snicholls::ok(secret_bytes<32>(std::move(out)));
}

} // namespace snicholls::crypto::x25519

#endif /* snicholls_crypto_curve25519_x25519_hpp */

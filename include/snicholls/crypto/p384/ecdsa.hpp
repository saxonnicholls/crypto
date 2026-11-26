//
//  ecdsa.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief ECDSA on P-384 with SHA-384 (JOSE's ES384, TLS 1.3's ecdsa_secp384r1_sha384, X.509's ecdsa-with-SHA384):
/// keys, verification, JOSE and DER forms.
/// \ingroup p384
///
/// \overview
/// - `private_key` (48 bytes, 1 to n - 1) and its `public_key` (SEC1 compressed, 49 bytes, or uncompressed, 97),
///   computed in constant time.
/// - `verify(key, hash, signature)`: FIPS 186-5 / SEC 1 verification over a 48-byte SHA-384 hash, either s
///   accepted; `verify_message` hashes the message with SHA-384 first.
/// - `signature::from_jose` / `jose()`: JWS's 96-byte r || s (TLS and X.509 use DER); `from_der` / `der()`: strict
///   DER.
///
/// Verification only: there is no P-384 signing here (P-256 and Ed25519 sign). With P-384's 384-bit order the
/// SHA-384 hash is used whole, reduced modulo n.
///
/// \relations
/// - `p384/point.hpp`, `p384/scalar.hpp`; `detail/ecdsa_der.hpp` (the DER shared with P-256 and secp256k1);
///   `p384/ecdh.hpp` (key agreement with the same keys).
/// - Group: \ref p384.
///
/// \impls
/// One: d G in constant time (`point::mul`); verification with `point::mul_add_public` in variable time.
///
/// \contracts
/// - `private_key` and `public_key()`: constant time in the private key. Revealed on purpose (`ct::declassify`):
///   whether a key's bytes are in range. The key is held in `secret_bytes<48>`; intermediates are wiped.
/// - `verify`, `verify_message`, `public_key::parse`, `signature::from_der`: variable time; public data only.
/// - `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `errc::invalid_private_key` for a key of 0 or at least n; `errc::invalid_public_key` for an encoding that is not
/// SEC1 compressed or uncompressed of a point on the curve; `errc::invalid_signature` for r or s outside 1 to n - 1,
/// DER that is not DER, or a signature that does not verify.
///
/// \examples
/// \snippet p384/ecdsa_demo.cpp p384
///
/// \perf
/// See BENCHMARKS.md, `benchmarks/p384/ecdsa_benchmark.cpp`.
///
/// \testing
/// `tests/p384/ecdsa_test.cpp`: every Wycheproof `ecdsa_secp384r1_sha384` case in DER and P1363 form
/// (`tests/fixtures/wycheproof/`), keys and encodings at their edges. `tests/p384/ecdsa_oracles_test.cpp`: OpenSSL,
/// `@noble/curves` and Node's crypto. `demos/p384/ecdsa_demo.cpp`. The secret paths are in the Valgrind check
/// (`tests/ct/secret_marking.cpp`).
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp` and SHA-384.
///
/// \gotchas
/// Hash the message first for `verify` (48 bytes of SHA-384), or call `verify_message`. JOSE's signature is r || s,
/// never DER; TLS's and X.509's are DER.
///
/// \status
/// Experimental (0.6).

#ifndef snicholls_crypto_p384_ecdsa_hpp
#define snicholls_crypto_p384_ecdsa_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/ecdsa_der.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/p384/point.hpp>
#include <snicholls/crypto/p384/scalar.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace snicholls::crypto::p384 {

/// \brief A P-384 public key: a point on the curve, not the identity.
/// \ingroup p384
class public_key {
public:
    /// \brief A key from a point (which must be on the curve; `parse` checks).
    /// \param p The point.
    constexpr explicit public_key(const affine_point& p) noexcept : p_(p) {}

    /// \brief A SEC1 encoding, compressed (49 bytes) or uncompressed (97), checked. Variable time; public data only.
    /// \param bytes The encoding.
    /// \return The key, or `errc::invalid_public_key`.
    [[nodiscard]] static constexpr result<public_key, errc> parse(std::span<const std::uint8_t> bytes) noexcept
    {
        const auto p = affine_point::decode(bytes);
        if (!p)
            return err(errc::invalid_public_key);
        return ok(public_key(*p));
    }

    /// \brief The compressed SEC1 encoding.
    /// \return 49 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 49> compressed() const noexcept { return p_.compressed(); }

    /// \brief The uncompressed SEC1 encoding (as in a JWK, x and y after the 0x04; TLS's key_share).
    /// \return 97 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 97> uncompressed() const noexcept { return p_.uncompressed(); }

    /// \brief The point.
    /// \return The affine point.
    [[nodiscard]] constexpr const affine_point& point() const noexcept { return p_; }

    /// \brief Equality.
    /// \param a A key.
    /// \param b Another.
    /// \return Whether they are the same key.
    [[nodiscard]] friend constexpr bool operator==(const public_key& a, const public_key& b) noexcept = default;

private:
    affine_point p_;
};

/// \brief A P-384 private key: 48 bytes, 1 to n - 1, held in `secret_bytes<48>`.
/// \ingroup p384
class private_key {
public:
    /// \brief A key from 48 big-endian bytes (copied into wiped storage). Constant time in the bytes.
    /// \param bytes The key.
    /// \return The key, or `errc::invalid_private_key` for 0 or at least n.
    [[nodiscard]] static constexpr result<private_key, errc> from_bytes(std::span<const std::uint8_t, 48> bytes) noexcept
    {
        return from_secret(secret_bytes<48>(bytes));
    }

    /// \brief A key from secret bytes, taken over. Constant time in the bytes.
    /// \param bytes The key.
    /// \return The key, or `errc::invalid_private_key` for 0 or at least n.
    [[nodiscard]] static constexpr result<private_key, errc> from_secret(secret_bytes<48>&& bytes) noexcept
    {
        std::uint64_t below = 0;
        scalar d = scalar::from_bytes_ct(bytes.reveal(), below);
        const std::uint64_t valid = below & ~d.is_zero_mask();
        secure_wipe(d);
        if (!ct::declassify(valid))   // a key's validity is revealed on purpose
            return err(errc::invalid_private_key);
        return ok(private_key(std::move(bytes)));
    }

    /// \brief The public key, d G, in constant time.
    /// \return The key.
    [[nodiscard]] constexpr p384::public_key public_key() const noexcept
    {
        scalar d = to_scalar();
        std::uint64_t finite = 0;
        const affine_point p = point::mul_base(d).to_affine_ct(finite);
        secure_wipe(d);
        return p384::public_key(p);
    }

    /// \brief The key as a scalar (wipe it after use).
    /// \return d.
    [[nodiscard]] constexpr scalar to_scalar() const noexcept { return scalar::from_bytes_reduced(d_.reveal()); }

    /// \brief The key's bytes.
    /// \return 48 bytes.
    [[nodiscard]] constexpr std::span<const std::uint8_t, 48> reveal() const noexcept { return d_.reveal(); }

    /// \brief An explicit copy.
    /// \return The same key.
    [[nodiscard]] constexpr private_key clone() const noexcept { return private_key(d_.clone()); }

private:
    constexpr explicit private_key(secret_bytes<48>&& d) noexcept : d_(std::move(d)) {}

    secret_bytes<48> d_;
};

/// \brief An ECDSA signature: r and s, 48 bytes each, big-endian.
/// \ingroup p384
struct signature {
    std::array<std::uint8_t, 48> r{};   ///< r.
    std::array<std::uint8_t, 48> s{};   ///< s.

    /// \brief JOSE's form (RFC 7518 section 3.4): r || s, 96 bytes.
    /// \param rs The 96 bytes.
    /// \return The signature (range checks happen in `verify`).
    [[nodiscard]] static constexpr signature from_jose(std::span<const std::uint8_t, 96> rs) noexcept
    {
        signature sig;
        for (std::size_t i = 0; i < 48; ++i) {
            sig.r[i] = rs[i];
            sig.s[i] = rs[48 + i];
        }
        return sig;
    }

    /// \brief JOSE's form: r || s.
    /// \return 96 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 96> jose() const noexcept
    {
        std::array<std::uint8_t, 96> out{};
        for (std::size_t i = 0; i < 48; ++i) {
            out[i] = r[i];
            out[48 + i] = s[i];
        }
        return out;
    }

    /// \brief The DER form, SEQUENCE { r INTEGER, s INTEGER }.
    /// \return 8 to 104 bytes.
    [[nodiscard]] constexpr crypto::detail::der_signature_n<48> der() const noexcept { return crypto::detail::ecdsa_der_encode_n<48>(r, s); }

    /// \brief Strict DER (minimal, non-negative, at most 384 bits each, nothing trailing). Variable time; public data.
    /// \param der The DER.
    /// \return The signature, or `errc::invalid_signature`.
    [[nodiscard]] static constexpr result<signature, errc> from_der(std::span<const std::uint8_t> der) noexcept
    {
        const auto rs = crypto::detail::ecdsa_der_decode_n<48>(der);
        if (!rs)
            return err(errc::invalid_signature);
        return ok(signature{rs->first, rs->second});
    }

    /// \brief Equality.
    /// \param a A signature.
    /// \param b Another.
    /// \return Whether r and s are equal.
    [[nodiscard]] friend constexpr bool operator==(const signature& a, const signature& b) noexcept = default;
};

/// \brief Verifies a signature over a SHA-384 hash (FIPS 186-5 section 6.4.2; either s). Variable time; public data
/// only.
/// \ingroup p384
/// \param key The signer's public key.
/// \param hash The SHA-384 of the message.
/// \param sig The signature.
/// \return Success, or `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> verify(const public_key& key, std::span<const std::uint8_t, 48> hash,
                                                  const signature& sig) noexcept
{
    const auto r = scalar::from_bytes(sig.r);
    const auto s = scalar::from_bytes(sig.s);
    if (!r || !s || r->is_zero() || s->is_zero())
        return err(errc::invalid_signature);
    const scalar w = s->inverse();
    const scalar z = scalar::from_bytes_reduced(hash);
    const point big_r = point::mul_add_public(z * w, *r * w, point(key.point()));
    const auto a = big_r.to_affine();
    if (!a)
        return err(errc::invalid_signature);
    std::uint64_t below = 0;
    if (!(scalar::from_bytes_ct(a->x.to_bytes(), below) == *r))
        return err(errc::invalid_signature);
    return ok();
}

/// \brief Verifies a signature over a message, hashed with SHA-384 (ES384). Variable time; public data only.
/// \ingroup p384
/// \param key The signer's public key.
/// \param message The signed bytes (for a JWS, the ASCII of `header.payload`).
/// \param sig The signature.
/// \return Success, or `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> verify_message(const public_key& key, std::span<const std::uint8_t> message,
                                                          const signature& sig) noexcept
{
    const auto h = crypto::detail::sha384::hash(message);
    return verify(key, h, sig);
}

} // namespace snicholls::crypto::p384

#endif /* snicholls_crypto_p384_ecdsa_hpp */

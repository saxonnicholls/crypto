//
//  ecdsa.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief ECDSA on P-256 with SHA-256 (JOSE's ES256): keys, RFC 6979 signing, verification, JOSE and DER forms.
/// \ingroup p256
///
/// \overview
/// - `private_key` (32 bytes, 1 to n - 1) and its `public_key` (SEC1 compressed or uncompressed).
/// - `sign(key, hash)`: RFC 6979 deterministic nonces (HMAC-SHA256), the signature (r, s) as computed; s is not
///   reduced to the lower half, as ES256 and FIPS 186-5 do not require it.
/// - `verify(key, hash, signature)`: FIPS 186-5 / SEC 1 verification, either s accepted.
/// - `signature::from_jose` / `jose()`: JWS's 64-byte r || s; `from_der` / `der()`: strict DER.
///
/// The hash is the SHA-256 of the message, 32 bytes (for a JWS, of the ASCII `header.payload`); with P-256's 256-bit
/// order it is used whole, reduced modulo n.
///
/// \relations
/// - `p256/point.hpp`, `p256/scalar.hpp`; `secp256k1/rfc6979.hpp` (the nonce generator, for any 256-bit order);
///   `detail/ecdsa_der.hpp`.
/// - Group: \ref p256.
///
/// \impls
/// One: k G and the private-key arithmetic in constant time (`point::mul`, Fermat's inverse); verification with
/// `point::mul_add_public` in variable time.
///
/// \contracts
/// - `private_key`, `public_key()` and `sign`: constant time in the private key and the nonce. Revealed on purpose
///   (`ct::declassify`): whether a key's bytes are in range, and the RFC 6979 retry on r or s of zero (probability
///   about 2^-256). The key is held in `secret_bytes<32>`; intermediates are wiped.
/// - `verify`, `public_key::parse`, `signature::from_der`: variable time; public data only.
/// - `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `errc::invalid_private_key` for a key of 0 or at least n; `errc::invalid_public_key` for an encoding that is not
/// SEC1 compressed or uncompressed of a point on the curve; `errc::invalid_signature` for r or s outside 1 to n - 1,
/// DER that is not DER, or a signature that does not verify.
///
/// \examples
/// \snippet p256/ecdsa_demo.cpp p256
///
/// \perf
/// See BENCHMARKS.md, `benchmarks/p256/ecdsa_benchmark.cpp`.
///
/// \testing
/// `tests/p256/ecdsa_test.cpp`: RFC 6979 appendix A.2.5 (P-256, SHA-256, "sample" and "test", signatures byte for
/// byte), every Wycheproof `ecdsa_secp256r1_sha256` case in DER and P1363 form (`tests/fixtures/wycheproof/`), keys
/// and encodings at their edges. `tests/p256/ecdsa_oracles_test.cpp`: OpenSSL, Node's crypto and RustCrypto's p256.
/// `demos/p256/ecdsa_demo.cpp`. The secret paths are in the Valgrind check (`tests/ct/secret_marking.cpp`).
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp` and SHA-256.
///
/// \gotchas
/// Hash the message first: `sign` and `verify` take the 32-byte SHA-256. JOSE's signature is r || s, never DER.
///
/// \status
/// Experimental (0.3).

#ifndef snicholls_crypto_p256_ecdsa_hpp
#define snicholls_crypto_p256_ecdsa_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/ecdsa_der.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/p256/point.hpp>
#include <snicholls/crypto/p256/scalar.hpp>
#include <snicholls/crypto/secp256k1/rfc6979.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace snicholls::crypto::p256 {

/// \brief A P-256 public key: a point on the curve, not the identity.
/// \ingroup p256
class public_key {
public:
    /// \brief A key from a point (which must be on the curve; `parse` checks).
    /// \param p The point.
    constexpr explicit public_key(const affine_point& p) noexcept : p_(p) {}

    /// \brief A SEC1 encoding, compressed (33 bytes) or uncompressed (65), checked. Variable time; public data only.
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
    /// \return 33 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 33> compressed() const noexcept { return p_.compressed(); }

    /// \brief The uncompressed SEC1 encoding (as in a JWK, x and y after the 0x04).
    /// \return 65 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 65> uncompressed() const noexcept { return p_.uncompressed(); }

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

/// \brief A P-256 private key: 32 bytes, 1 to n - 1, held in `secret_bytes<32>`.
/// \ingroup p256
class private_key {
public:
    /// \brief A key from 32 big-endian bytes (copied into wiped storage). Constant time in the bytes.
    /// \param bytes The key.
    /// \return The key, or `errc::invalid_private_key` for 0 or at least n.
    [[nodiscard]] static constexpr result<private_key, errc> from_bytes(std::span<const std::uint8_t, 32> bytes) noexcept
    {
        return from_secret(secret_bytes<32>(bytes));
    }

    /// \brief A key from secret bytes, taken over. Constant time in the bytes.
    /// \param bytes The key.
    /// \return The key, or `errc::invalid_private_key` for 0 or at least n.
    [[nodiscard]] static constexpr result<private_key, errc> from_secret(secret_bytes<32>&& bytes) noexcept
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
    [[nodiscard]] constexpr p256::public_key public_key() const noexcept
    {
        scalar d = to_scalar();
        std::uint64_t finite = 0;
        const affine_point p = point::mul_base(d).to_affine_ct(finite);
        secure_wipe(d);
        return p256::public_key(p);
    }

    /// \brief The key as a scalar (wipe it after use).
    /// \return d.
    [[nodiscard]] constexpr scalar to_scalar() const noexcept { return scalar::from_bytes_reduced(d_.reveal()); }

    /// \brief The key's bytes.
    /// \return 32 bytes.
    [[nodiscard]] constexpr std::span<const std::uint8_t, 32> reveal() const noexcept { return d_.reveal(); }

    /// \brief An explicit copy.
    /// \return The same key.
    [[nodiscard]] constexpr private_key clone() const noexcept { return private_key(d_.clone()); }

private:
    constexpr explicit private_key(secret_bytes<32>&& d) noexcept : d_(std::move(d)) {}

    secret_bytes<32> d_;
};

/// \brief An ECDSA signature: r and s, 32 bytes each, big-endian.
/// \ingroup p256
struct signature {
    std::array<std::uint8_t, 32> r{};   ///< r.
    std::array<std::uint8_t, 32> s{};   ///< s.

    /// \brief JOSE's form (RFC 7518 section 3.4): r || s, 64 bytes.
    /// \param rs The 64 bytes.
    /// \return The signature (range checks happen in `verify`).
    [[nodiscard]] static constexpr signature from_jose(std::span<const std::uint8_t, 64> rs) noexcept
    {
        signature sig;
        for (std::size_t i = 0; i < 32; ++i) {
            sig.r[i] = rs[i];
            sig.s[i] = rs[32 + i];
        }
        return sig;
    }

    /// \brief JOSE's form: r || s.
    /// \return 64 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 64> jose() const noexcept
    {
        std::array<std::uint8_t, 64> out{};
        for (std::size_t i = 0; i < 32; ++i) {
            out[i] = r[i];
            out[32 + i] = s[i];
        }
        return out;
    }

    /// \brief The DER form, SEQUENCE { r INTEGER, s INTEGER }.
    /// \return 8 to 72 bytes.
    [[nodiscard]] constexpr crypto::detail::der_signature der() const noexcept { return crypto::detail::ecdsa_der_encode(r, s); }

    /// \brief Strict DER (minimal, non-negative, at most 256 bits each, nothing trailing). Variable time; public data.
    /// \param der The DER.
    /// \return The signature, or `errc::invalid_signature`.
    [[nodiscard]] static constexpr result<signature, errc> from_der(std::span<const std::uint8_t> der) noexcept
    {
        const auto rs = crypto::detail::ecdsa_der_decode(der);
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

/// \brief Signs a SHA-256 hash with RFC 6979 nonces, in constant time in the key and the nonce.
/// \ingroup p256
/// \param key The private key.
/// \param hash The SHA-256 of the message.
/// \return The signature, s as computed (not normalised).
[[nodiscard]] constexpr signature sign(const private_key& key, std::span<const std::uint8_t, 32> hash) noexcept
{
    const auto order = scalar::order_bytes();
    scalar d = key.to_scalar();
    scalar z = scalar::from_bytes_reduced(hash);
    secp256k1::rfc6979 nonces(key.reveal(), hash, order, {});
    for (;;) {
        const secret_bytes<32> kb = nonces.next();
        std::uint64_t below = 0;
        scalar k = scalar::from_bytes_ct(kb.reveal(), below);   // RFC 6979 gives 1 to n - 1: below is set
        std::uint64_t finite = 0;
        const affine_point big_r = point::mul_base(k).to_affine_ct(finite);
        std::uint64_t r_below = 0;
        const scalar r = scalar::from_bytes_ct(big_r.x.to_bytes(), r_below);   // r = x mod n
        scalar k_inverse = k.inverse();
        const scalar s = k_inverse * (z + r * d);
        secure_wipe(k);
        secure_wipe(k_inverse);
        // r or s of zero, with probability about 2^-256: the next RFC 6979 nonce. No `continue` (MSVC's C3615)
        if (!ct::declassify(r.is_zero_mask() | s.is_zero_mask())) {
            secure_wipe(d);
            secure_wipe(z);
            return {r.to_bytes(), s.to_bytes()};
        }
    }
}

/// \brief Verifies a signature over a SHA-256 hash (FIPS 186-5 section 6.4.2; either s). Variable time; public data
/// only.
/// \ingroup p256
/// \param key The signer's public key.
/// \param hash The SHA-256 of the message.
/// \param sig The signature.
/// \return Success, or `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> verify(const public_key& key, std::span<const std::uint8_t, 32> hash,
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

} // namespace snicholls::crypto::p256

#endif /* snicholls_crypto_p256_ecdsa_hpp */

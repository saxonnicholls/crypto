//
//  ed25519.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Ed25519 (RFC 8032): key pairs from a 32-byte seed, deterministic signatures, and verification.
/// \ingroup curve25519
///
/// \overview
/// Pure Ed25519 as RFC 8032 defines it (not Ed25519ph or Ed25519ctx). A `key_pair` is made from a 32-byte seed (the
/// RFC's private key): SHA-512 of the seed gives the clamped secret scalar and the nonce prefix. `sign` is
/// deterministic (no randomness, so no nonce reuse); `verify` checks a signature against a public key.
///
/// Verification rule, stated exactly (the "cofactorless" equation, as Go's crypto/ed25519 and libsodium's default
/// verifier use):
///
/// 1. The public key A must decode strictly (`curve25519::point::decode`): y below p, x defined, no "negative zero".
///    Otherwise `errc::invalid_public_key`.
/// 2. S must be canonical, S < L. Otherwise `errc::invalid_signature` (this is what stops S + L malleability).
/// 3. k = SHA-512(R || A || M) mod L, and the signature is valid exactly when the encoding of [S]B - [k]A equals the
///    32 bytes R, byte for byte. R is not decoded on its own, so a non-canonical R can never match.
///
/// Accepted: small-order and mixed-order public keys and R values whenever the equation holds (Wycheproof marks
/// these "acceptable"; libsodium's strict mode rejects small-order A and R, which a caller can add with
/// `point::is_small_order`). Rejected: S >= L, a public key that does not decode, every non-canonical R, and the
/// signatures that only a cofactored equation ([8][S]B = [8]R + [8][k]A) would accept. Different verifiers disagree on
/// those edge cases (see "Taming the many EdDSAs", Chalkias, Garillot and Nikolaenko, 2020); this one matches Go.
///
/// \relations
/// - `curve25519/edwards.hpp`: the group; `curve25519/scalar.hpp`: the scalars.
/// - `hd/slip10.hpp`: derives Ed25519 seeds from a wallet seed.
/// - `curve25519/x25519.hpp`: key agreement on the same curve, in its Montgomery form.
/// - Group: \ref curve25519.
///
/// \impls
/// One.
///
/// \contracts
/// - `key_pair::from_seed`, `key_pair::sign`, `public_key_from_seed`: constant time in the seed and the secret
///   scalar; the message's length and content are public. The seed, the secret scalar and the prefix live in
///   `secret_bytes` and are wiped with the key pair; the nonce, the expanded hash and other intermediates are wiped
///   before returning.
/// - `verify`: variable time; its inputs are public.
/// - Everything is `constexpr` and `noexcept`; no allocation (the message is hashed as a stream, twice when signing).
///
/// \errors
/// `verify` returns `errc::invalid_public_key` when A does not decode and `errc::invalid_signature` for every other
/// failure, without saying which check failed.
///
/// \examples
/// \snippet curve25519/ed25519_demo.cpp ed25519
///
/// \perf
/// See BENCHMARKS.md, `benchmarks/curve25519/ed25519_benchmark.cpp` (key pair, sign, verify).
///
/// \testing
/// `tests/curve25519/ed25519_test.cpp`: RFC 8032 section 7.1 (tests 1, 2, 3, 1024 and SHA(abc)), all 210 Wycheproof
/// `ed25519_test.json` cases (`tests/fixtures/wycheproof/ed25519.txt`), and the malleability, small-order and
/// non-canonical cases above. `demos/curve25519/ed25519_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`; the SHA-512 in `detail/hashes.hpp` (interim, until core's).
///
/// \gotchas
/// A seed is not a scalar: never pass SHA-512 output or a clamped scalar as a seed. Ed25519ph and Ed25519ctx are not
/// implemented.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_curve25519_ed25519_hpp
#define snicholls_crypto_curve25519_ed25519_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/curve25519/edwards.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

/// \brief Ed25519 signatures (RFC 8032).
namespace snicholls::crypto::ed25519 {

/// \brief An Ed25519 public key: the 32-byte encoding of A.
/// \ingroup curve25519
struct public_key {
    std::array<std::uint8_t, 32> bytes{};   ///< The encoding.

    /// \brief Equality of the bytes.
    /// \param a A key.
    /// \param b Another.
    /// \return Whether the encodings agree.
    [[nodiscard]] friend constexpr bool operator==(const public_key& a, const public_key& b) noexcept = default;
};

/// \brief An Ed25519 signature: R (32 bytes) then S (32 bytes, little-endian).
/// \ingroup curve25519
struct signature {
    std::array<std::uint8_t, 64> bytes{};   ///< R || S.

    /// \brief Equality of the bytes.
    /// \param a A signature.
    /// \param b Another.
    /// \return Whether the bytes agree.
    [[nodiscard]] friend constexpr bool operator==(const signature& a, const signature& b) noexcept = default;
};

/// \brief A signing key: the seed, its expansion, and the public key.
/// \ingroup curve25519
///
/// \contracts
/// Move-only; the seed, the secret scalar and the prefix are wiped when it dies. `noexcept` and `constexpr`.
class key_pair {
public:
    /// \brief The key pair of a seed, taking the seed.
    /// \param seed The 32-byte seed (RFC 8032's private key); it is moved in and wiped with the key pair.
    /// \return The key pair.
    [[nodiscard]] static constexpr key_pair from_seed(secret_bytes<32>&& seed) noexcept { return key_pair(std::move(seed)); }

    /// \brief The key pair of a seed, copying it.
    /// \param seed The 32 bytes; the caller still owns and should wipe them.
    /// \return The key pair.
    [[nodiscard]] static constexpr key_pair from_seed(std::span<const std::uint8_t, 32> seed) noexcept
    {
        return key_pair(secret_bytes<32>(seed));
    }

    /// \brief The public key.
    /// \return A's encoding.
    [[nodiscard]] constexpr const ed25519::public_key& public_key() const noexcept { return public_; }

    /// \brief The seed, for backing the key up; handle with care.
    /// \return The seed.
    [[nodiscard]] constexpr const secret_bytes<32>& seed() const noexcept { return seed_; }

    /// \brief The deterministic signature of a message (RFC 8032, section 5.1.6).
    /// \param message The message, any length.
    /// \return R || S.
    [[nodiscard]] constexpr signature sign(std::span<const std::uint8_t> message) const noexcept
    {
        crypto::detail::sha512 h;
        h.update(prefix_.reveal());
        h.update(message);
        auto rh = h.finish();
        curve25519::scalar r = curve25519::scalar::reduce(rh);
        secure_wipe(rh);
        const auto big_r = curve25519::point::mul_base(r).encode();

        crypto::detail::sha512 hk;
        hk.update(big_r);
        hk.update(public_.bytes);
        hk.update(message);
        const auto kh = hk.finish();
        const curve25519::scalar k = curve25519::scalar::reduce(kh);

        const curve25519::scalar a = curve25519::scalar::from_bytes_reduced(scalar_.reveal());
        curve25519::scalar s = curve25519::scalar::mul_add(k, a, r);
        signature sig;
        for (std::size_t i = 0; i < 32; ++i) {
            sig.bytes[i] = big_r[i];
            sig.bytes[32 + i] = s.to_bytes()[i];
        }
        secure_wipe(r);
        secure_wipe(s);
        auto a_copy = a;
        secure_wipe(a_copy);
        return sig;
    }

private:
    constexpr explicit key_pair(secret_bytes<32>&& seed) noexcept : seed_(std::move(seed))
    {
        auto d = crypto::detail::sha512::hash(seed_.reveal());
        std::array<std::uint8_t, 32> a{};
        std::array<std::uint8_t, 32> prefix{};
        for (std::size_t i = 0; i < 32; ++i) {
            a[i] = d[i];
            prefix[i] = d[32 + i];
        }
        secure_wipe(d);
        a[0] = static_cast<std::uint8_t>(a[0] & 248);
        a[31] = static_cast<std::uint8_t>((a[31] & 127) | 64);
        // The clamped value is below 2^255; B has order L, so the scalar can be held reduced modulo L
        curve25519::scalar s = curve25519::scalar::from_bytes_reduced(a);
        secure_wipe(a);
        public_.bytes = curve25519::point::mul_base(s).encode();
        auto sb = s.to_bytes();
        scalar_ = secret_bytes<32>(std::move(sb));
        prefix_ = secret_bytes<32>(std::move(prefix));
        secure_wipe(s);
    }

    secret_bytes<32> seed_;
    secret_bytes<32> scalar_;
    secret_bytes<32> prefix_;
    ed25519::public_key public_;
};

/// \brief The public key of a seed, without keeping a key pair.
/// \param seed The 32-byte seed.
/// \return The public key.
[[nodiscard]] constexpr public_key public_key_from_seed(std::span<const std::uint8_t, 32> seed) noexcept
{
    return key_pair::from_seed(seed).public_key();
}

/// \brief Verifies a signature by the cofactorless rule in the file description (variable time; public data).
/// \param key The signer's public key.
/// \param message The message.
/// \param sig The signature.
/// \return Success, `errc::invalid_public_key`, or `errc::invalid_signature`.
[[nodiscard]] constexpr snicholls::result<void, errc> verify(const public_key& key, std::span<const std::uint8_t> message,
                                                             const signature& sig) noexcept
{
    const auto a = curve25519::point::decode(key.bytes);
    if (!a)
        return snicholls::err(errc::invalid_public_key);
    const auto sig_span = std::span<const std::uint8_t, 64>(sig.bytes);
    const auto s = curve25519::scalar::from_canonical(sig_span.subspan<32, 32>());
    if (!s)
        return snicholls::err(errc::invalid_signature);
    crypto::detail::sha512 hk;
    hk.update(sig_span.first<32>());
    hk.update(key.bytes);
    hk.update(message);
    const curve25519::scalar k = curve25519::scalar::reduce(hk.finish());
    const auto check = curve25519::point::mul_add_public(*s, k, -*a).encode();
    for (std::size_t i = 0; i < 32; ++i)
        if (check[i] != sig.bytes[i])
            return snicholls::err(errc::invalid_signature);
    return snicholls::ok();
}

} // namespace snicholls::crypto::ed25519

#endif /* snicholls_crypto_curve25519_ed25519_hpp */

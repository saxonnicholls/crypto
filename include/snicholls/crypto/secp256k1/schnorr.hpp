//
//  schnorr.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief BIP-340 Schnorr signatures over secp256k1: x-only public keys, signing with auxiliary randomness,
/// verification.
/// \ingroup secp256k1
///
/// \overview
/// The signatures of Bitcoin's taproot (BIP-341). Public keys are 32 bytes, the x of a point whose y is even; a
/// signature is 64 bytes, R's x and s. Signing takes 32 bytes of auxiliary randomness (BIP-340 recommends fresh
/// random bytes; zeros give a deterministic signature that is still safe), and messages of any length.
///
/// \relations
/// - `secp256k1/keys.hpp`: the same private keys as ECDSA.
/// - `secp256k1/ecdsa.hpp`: the other signature scheme on this curve.
/// - Group: \ref secp256k1.
///
/// \impls
/// One, following BIP-340's reference algorithm step by step, with SHA-256 tagged hashes.
///
/// \contracts
/// - `sign` and `xonly_public_key_of` are constant time in the key, the nonce and the auxiliary data: the negations
///   that make y even are masked selections, the multiplications are the fixed-window `mul_base`. The only branch is
///   on a nonce of zero (probability about 2^-256). Secret intermediates are wiped.
/// - `verify` is variable time; its inputs are public.
/// - `constexpr`, `noexcept`, no allocation; the message is hashed in a stream.
///
/// \errors
/// `verify`: `errc::invalid_public_key` when the key is not the x of a curve point; `errc::invalid_signature` for r
/// at or above p, s at or above n, or a signature that does not verify.
///
/// \examples
/// \snippet secp256k1/schnorr_demo.cpp schnorr
///
/// \perf
/// `benchmarks/secp256k1/schnorr_benchmark.cpp`.
///
/// \testing
/// `tests/secp256k1/schnorr_test.cpp`: all of BIP-340's `test-vectors.csv` (signing and verification, including
/// the messages of length 0, 1, 17 and 100); `demos/secp256k1/schnorr_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; the library's SHA-256.
///
/// \gotchas
/// BIP-340 suggests verifying a signature before releasing it, against faults; this library does not (call `verify`
/// if the hardware warrants it).
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secp256k1_schnorr_hpp
#define snicholls_crypto_secp256k1_schnorr_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secp256k1/keys.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace snicholls::crypto::secp256k1 {

/// \brief A BIP-340 public key: the 32-byte x of a point with even y. Public data.
/// \ingroup secp256k1
struct xonly_public_key {
    std::array<std::uint8_t, 32> bytes{};   ///< x, big-endian.

    /// \brief Equality.
    /// \param a A key.
    /// \param b Another.
    /// \return Whether the bytes agree.
    [[nodiscard]] friend constexpr bool operator==(const xonly_public_key& a, const xonly_public_key& b) noexcept = default;
};

/// \brief A BIP-340 signature: R's x, then s.
/// \ingroup secp256k1
struct schnorr_signature {
    std::array<std::uint8_t, 64> bytes{};   ///< r || s.

    /// \brief Equality.
    /// \param a A signature.
    /// \param b Another.
    /// \return Whether the bytes agree.
    [[nodiscard]] friend constexpr bool operator==(const schnorr_signature& a, const schnorr_signature& b) noexcept = default;
};

namespace detail {
// BIP-340's tagged hash, SHA-256(SHA-256(tag) || SHA-256(tag) || ...): the state after the two tag blocks
constexpr crypto::detail::sha256 tagged(std::string_view tag) noexcept
{
    crypto::detail::sha256 t;
    t.update(tag);
    const auto h = t.finish();
    crypto::detail::sha256 out;
    out.update(h);
    out.update(h);
    return out;
}

// d and P = d G with d negated (in constant time) when P's y is odd
constexpr scalar even_y_key(const private_key& key, affine_point& p) noexcept
{
    scalar d = key.to_scalar();
    std::uint64_t finite = 0;
    p = point::mul_base(d).to_affine_ct(finite);
    const std::uint64_t odd = ct::mask_from_bit(p.y.is_odd());
    d = scalar::select(odd, -d, d);
    p.y = field_element::select(odd, -p.y, p.y);
    return d;
}
} // namespace detail

/// \brief The x-only public key of a private key, in constant time.
/// \ingroup secp256k1
/// \param key The private key.
/// \return x(d G).
[[nodiscard]] constexpr xonly_public_key xonly_public_key_of(const private_key& key) noexcept
{
    affine_point p;
    scalar d = detail::even_y_key(key, p);
    secure_wipe(d);
    return {p.x.to_bytes()};
}

/// \brief Signs a message (BIP-340). Constant time in the key, the nonce and `aux`.
/// \ingroup secp256k1
/// \param key The private key.
/// \param message The message, any length (BIP-340 signs it directly; it is usually a 32-byte hash).
/// \param aux 32 bytes of auxiliary randomness (fresh random bytes recommended; zeros are safe but deterministic).
/// \return The signature.
[[nodiscard]] constexpr schnorr_signature schnorr_sign(const private_key& key, std::span<const std::uint8_t> message,
                                                       std::span<const std::uint8_t, 32> aux) noexcept
{
    affine_point p;
    scalar d = detail::even_y_key(key, p);
    const auto px = p.x.to_bytes();
    // t = bytes(d) xor hash_aux(a)
    auto ha = detail::tagged("BIP0340/aux");
    ha.update(aux);
    auto t = ha.finish();
    auto db = d.to_bytes();
    for (std::size_t i = 0; i < 32; ++i)
        t[i] ^= db[i];
    for (;;) {
        auto hn = detail::tagged("BIP0340/nonce");
        hn.update(t);
        hn.update(px);
        hn.update(message);
        auto rand = hn.finish();
        scalar k = scalar::from_bytes_reduced(rand);
        secure_wipe(rand);
        if (k.is_zero()) {   // probability about 2^-256; BIP-340 fails here, this library tries once more with aux'
            t[0] ^= 1;
            continue;
        }
        std::uint64_t finite = 0;
        const affine_point big_r = point::mul_base(k).to_affine_ct(finite);
        k = scalar::select(ct::mask_from_bit(big_r.y.is_odd()), -k, k);
        const auto rx = big_r.x.to_bytes();
        auto he = detail::tagged("BIP0340/challenge");
        he.update(rx);
        he.update(px);
        he.update(message);
        const scalar e = scalar::from_bytes_reduced(he.finish());
        const auto s = (k + e * d).to_bytes();
        schnorr_signature sig;
        for (std::size_t i = 0; i < 32; ++i) {
            sig.bytes[i] = rx[i];
            sig.bytes[32 + i] = s[i];
        }
        secure_wipe(k);
        secure_wipe(d);
        secure_wipe(t);
        secure_wipe(db);
        return sig;
    }
}

/// \brief Verifies a BIP-340 signature. Variable time; public data only.
/// \ingroup secp256k1
/// \param key The x-only public key.
/// \param message The message.
/// \param sig The signature.
/// \return Success, or `errc::invalid_public_key` / `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> schnorr_verify(const xonly_public_key& key, std::span<const std::uint8_t> message,
                                                          const schnorr_signature& sig) noexcept
{
    const auto px = field_element::from_bytes(key.bytes);
    if (!px)
        return err(errc::invalid_public_key);
    const auto p = decompress(*px, 0);
    if (!p)
        return err(errc::invalid_public_key);
    const std::span<const std::uint8_t, 64> b(sig.bytes);
    const auto r = field_element::from_bytes(b.first<32>());
    const auto s = scalar::from_bytes(b.last<32>());
    if (!r || !s)
        return err(errc::invalid_signature);
    auto he = detail::tagged("BIP0340/challenge");
    he.update(b.first<32>());
    he.update(key.bytes);
    he.update(message);
    const scalar e = scalar::from_bytes_reduced(he.finish());
    const auto big_r = point::mul_add_public(*s, -e, point(*p)).to_affine();
    if (!big_r || big_r->y.is_odd() || !(big_r->x == *r))
        return err(errc::invalid_signature);
    return ok();
}

} // namespace snicholls::crypto::secp256k1

#endif /* snicholls_crypto_secp256k1_schnorr_hpp */

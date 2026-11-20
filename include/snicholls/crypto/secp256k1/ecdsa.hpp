//
//  ecdsa.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief ECDSA over secp256k1: RFC 6979 signing with low-S and a recovery id, verification, public-key recovery
/// (Ethereum's `ecrecover`), and strict DER.
/// \ingroup secp256k1
///
/// \overview
/// - `sign(key, hash)`: a deterministic signature (RFC 6979 nonce, optional extra entropy) of a 32-byte message hash,
///   always low-S (s <= n / 2, BIP-62 / EIP-2), with the recovery id that lets a verifier recover the public key.
/// - `verify(key, hash, sig, policy)`: standard ECDSA verification. `high_s::accept` is the textbook rule (and
///   Wycheproof's); `high_s::reject` is Bitcoin's and Ethereum transactions' (EIP-2).
/// - `recover(hash, sig, recovery_id, policy)`: the public key that produced a signature, from (r, s, id);
///   `recover_ethereum(hash, rsv)` reads Ethereum's 65-byte r || s || v with v = 27 or 28, as the `ecrecover`
///   precompile does.
/// - `signature::der()` / `signature::from_der`: the DER form Bitcoin and X.509 use, parsed strictly (BIP-66's
///   rules: minimal lengths, no padding beyond a sign byte, no negative integers, nothing after the sequence).
///
/// The hash is the caller's: SHA-256 (or double SHA-256) for Bitcoin, Keccak-256 for Ethereum. Hashes are reduced
/// modulo n, as ECDSA specifies.
///
/// \relations
/// - `secp256k1/keys.hpp`: the keys; `secp256k1/rfc6979.hpp`: the nonces; `secp256k1/point.hpp`: the arithmetic.
/// - `secp256k1/schnorr.hpp`: BIP-340 signatures with the same keys.
/// - Group: \ref secp256k1.
///
/// \impls
/// One.
///
/// \contracts
/// - `sign` is constant time in the key, the nonce and the hash: the nonce's multiplication is the fixed-window
///   `mul_base`, the inversion is Fermat, low-S is a masked selection. Its only branches are on r = 0 or s = 0,
///   which happen with probability about 2^-256 and then retry with the next RFC 6979 nonce. Every secret
///   intermediate is wiped.
/// - `verify`, `recover`, `recover_ethereum`, `from_der`: variable time; their inputs are public.
/// - `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `verify`: `errc::invalid_signature` for r or s outside [1, n - 1] or a signature that does not verify (one value for
/// every reason), `errc::high_s` for a high s under `high_s::reject`. `recover`: those, plus
/// `errc::invalid_recovery_id` and `errc::recovery_failed` (r + j n is not the x of a curve point, or the result is
/// the identity). `from_der`: `errc::invalid_signature` for anything that is not strict DER.
///
/// \examples
/// \snippet secp256k1/ecdsa_demo.cpp ecdsa
///
/// \perf
/// `benchmarks/secp256k1/ecdsa_benchmark.cpp`; numbers in README.md and BENCHMARKS.md.
///
/// \testing
/// `tests/secp256k1/ecdsa_test.cpp`: RFC 6979 secp256k1 signatures, Wycheproof (`ecdsa_secp256k1_sha256` in DER and
/// P1363 form, and the Bitcoin variant with low-S), recovery against every signature's own key, Ethereum's v,
/// and the edge cases (r = 0, s = 0, r or s = n, high-S, recovery ids 2 and 3, x not on the curve, the identity).
/// `demos/secp256k1/ecdsa_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp` and `containers/inplace_vector.hpp`.
///
/// \gotchas
/// A recovery id of 2 or 3 means r overflowed n (x = r + n); it occurs with probability about 2^-128 and is
/// supported, but Ethereum's v cannot express it.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secp256k1_ecdsa_hpp
#define snicholls_crypto_secp256k1_ecdsa_hpp

#include <snicholls/core/containers/inplace_vector.hpp>
#include <snicholls/core/result.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secp256k1/keys.hpp>
#include <snicholls/crypto/secp256k1/rfc6979.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace snicholls::crypto::secp256k1 {

/// \brief Whether verification accepts an s above n / 2.
/// \ingroup secp256k1
enum class high_s : unsigned char {
    accept,   ///< Textbook ECDSA (and Wycheproof's expectations): both s and n - s verify.
    reject,   ///< Bitcoin (BIP-62 / BIP-146) and Ethereum transactions (EIP-2): only s <= n / 2.
};

/// \brief An ECDSA signature: r and s, 32 bytes each, big-endian. Public data; not validated until verified.
/// \ingroup secp256k1
struct signature {
    std::array<std::uint8_t, 32> r{};   ///< r.
    std::array<std::uint8_t, 32> s{};   ///< s.

    /// \brief The 64-byte r || s form (IEEE P1363, "compact").
    /// \param rs The bytes.
    /// \return The signature.
    [[nodiscard]] static constexpr signature from_compact(std::span<const std::uint8_t, 64> rs) noexcept
    {
        signature sig;
        for (std::size_t i = 0; i < 32; ++i) {
            sig.r[i] = rs[i];
            sig.s[i] = rs[32 + i];
        }
        return sig;
    }

    /// \brief r || s.
    /// \return 64 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 64> compact() const noexcept
    {
        std::array<std::uint8_t, 64> out{};
        for (std::size_t i = 0; i < 32; ++i) {
            out[i] = r[i];
            out[32 + i] = s[i];
        }
        return out;
    }

    /// \brief The DER encoding: SEQUENCE { INTEGER r, INTEGER s }, minimal, at most 72 bytes.
    /// \return The bytes.
    [[nodiscard]] constexpr containers::inplace_vector<std::uint8_t, 72> der() const noexcept
    {
        containers::inplace_vector<std::uint8_t, 72> out;
        auto integer = [](const std::array<std::uint8_t, 32>& v, containers::inplace_vector<std::uint8_t, 33>& w) {
            std::size_t i = 0;
            while (i < 31 && v[i] == 0)
                ++i;
            if (v[i] & 0x80)
                w.push_back(0);
            for (; i < 32; ++i)
                w.push_back(v[i]);
        };
        containers::inplace_vector<std::uint8_t, 33> ri, si;
        integer(r, ri);
        integer(s, si);
        out.push_back(0x30);
        out.push_back(static_cast<std::uint8_t>(4 + ri.size() + si.size()));
        out.push_back(0x02);
        out.push_back(static_cast<std::uint8_t>(ri.size()));
        for (const auto b : ri)
            out.push_back(b);
        out.push_back(0x02);
        out.push_back(static_cast<std::uint8_t>(si.size()));
        for (const auto b : si)
            out.push_back(b);
        return out;
    }

    /// \brief A strict DER signature (BIP-66's rules). Variable time; public data only.
    /// \param der The encoding, nothing after it.
    /// \return The signature (r and s not yet range-checked), or `errc::invalid_signature`.
    [[nodiscard]] static constexpr result<signature, errc> from_der(std::span<const std::uint8_t> der) noexcept
    {
        const std::size_t n = der.size();
        if (n < 8 || n > 72 || der[0] != 0x30 || der[1] != n - 2 || der[2] != 0x02)
            return err(errc::invalid_signature);
        const std::size_t len_r = der[3];
        if (len_r == 0 || 5 + len_r >= n || der[4 + len_r] != 0x02)
            return err(errc::invalid_signature);
        const std::size_t len_s = der[5 + len_r];
        if (len_s == 0 || len_r + len_s + 6 != n)
            return err(errc::invalid_signature);
        signature sig;
        auto integer = [](std::span<const std::uint8_t> v, std::array<std::uint8_t, 32>& out) {
            if (v[0] & 0x80)
                return false;   // negative
            if (v.size() > 1 && v[0] == 0 && !(v[1] & 0x80))
                return false;   // padding beyond the sign byte
            if (v.size() > 33 || (v.size() == 33 && v[0] != 0))
                return false;   // more than 256 bits
            const std::size_t skip = v.size() == 33 ? 1 : 0;
            const std::size_t pad = 32 - (v.size() - skip);
            for (std::size_t i = 0; i < v.size() - skip; ++i)
                out[pad + i] = v[skip + i];
            return true;
        };
        if (!integer(der.subspan(4, len_r), sig.r) || !integer(der.subspan(6 + len_r, len_s), sig.s))
            return err(errc::invalid_signature);
        return ok(sig);
    }

    /// \brief Equality of bytes.
    /// \param a A signature.
    /// \param b Another.
    /// \return Whether r and s agree.
    [[nodiscard]] friend constexpr bool operator==(const signature& a, const signature& b) noexcept = default;
};

/// \brief A signature with its recovery id (0 to 3): bit 0 is the parity of R's y, bit 1 says R's x overflowed n.
/// \ingroup secp256k1
struct recoverable_signature {
    secp256k1::signature sig;     ///< r and s.
    std::uint8_t recovery_id = 0; ///< 0 to 3.

    /// \brief Ethereum's 65-byte form, r || s || v with v = 27 + recovery id.
    /// \pre `recovery_id < 2` (an id of 2 or 3 has no Ethereum form; it occurs with probability about 2^-128).
    /// \return 65 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 65> ethereum() const noexcept
    {
        std::array<std::uint8_t, 65> out{};
        const auto rs = sig.compact();
        for (std::size_t i = 0; i < 64; ++i)
            out[i] = rs[i];
        out[64] = static_cast<std::uint8_t>(27 + recovery_id);
        return out;
    }

    /// \brief Equality.
    /// \param a A signature.
    /// \param b Another.
    /// \return Whether every field agrees.
    [[nodiscard]] friend constexpr bool operator==(const recoverable_signature& a, const recoverable_signature& b) noexcept = default;
};

/// \brief Signs a 32-byte message hash: RFC 6979 nonce, low-S, recovery id. Constant time in the key and the nonce.
/// \ingroup secp256k1
/// \param key The private key.
/// \param hash The message hash (SHA-256, Keccak-256, ...), 32 bytes.
/// \param extra Optional extra data for the nonce (RFC 6979 3.6): empty, or 32 bytes.
/// \return The signature and its recovery id.
[[nodiscard]] constexpr recoverable_signature sign(const private_key& key, std::span<const std::uint8_t, 32> hash,
                                                   std::span<const std::uint8_t> extra = {}) noexcept
{
    const auto order = scalar::order_bytes();
    scalar d = key.to_scalar();
    scalar z = scalar::from_bytes_reduced(hash);
    rfc6979 nonces(key.reveal(), hash, order, extra);
    for (;;) {
        const secret_bytes<32> kb = nonces.next();
        scalar k = scalar::from_bytes_reduced(kb.reveal());
        std::uint64_t finite = 0;
        const affine_point big_r = point::mul_base(k).to_affine_ct(finite);
        std::uint64_t below = 0;
        const scalar r = scalar::from_bytes_ct(big_r.x.to_bytes(), below);   // r = x mod n; overflow when x >= n
        scalar k_inverse = k.inverse();
        scalar s = k_inverse * (z + r * d);
        const std::uint64_t high = s.is_high_mask();
        s = scalar::select(high, -s, s);
        const auto id = static_cast<std::uint8_t>((big_r.y.is_odd() ^ (high & 1)) | ((~below & 1) << 1));
        secure_wipe(k);
        secure_wipe(k_inverse);
        if (r.is_zero() || s.is_zero())   // probability about 2^-256: the next RFC 6979 nonce
            continue;
        secure_wipe(d);
        secure_wipe(z);
        return {{r.to_bytes(), s.to_bytes()}, id};
    }
}

namespace detail {
// r and s in [1, n - 1], and s's policy; public data
constexpr result<std::array<scalar, 2>, errc> signature_scalars(const signature& sig, high_s policy) noexcept
{
    const auto r = scalar::from_bytes(sig.r);
    const auto s = scalar::from_bytes(sig.s);
    if (!r || !s || r->is_zero() || s->is_zero())
        return err(errc::invalid_signature);
    if (policy == high_s::reject && s->is_high())
        return err(errc::high_s);
    return ok(std::array<scalar, 2>{*r, *s});
}
} // namespace detail

/// \brief Verifies a signature of a 32-byte hash. Variable time; public data only.
/// \ingroup secp256k1
/// \param key The public key.
/// \param hash The message hash.
/// \param sig The signature.
/// \param policy Whether an s above n / 2 is accepted.
/// \return Success, or `errc::invalid_signature` / `errc::high_s`.
[[nodiscard]] constexpr result<void, errc> verify(const public_key& key, std::span<const std::uint8_t, 32> hash,
                                                  const signature& sig, high_s policy = high_s::accept) noexcept
{
    const auto rs = detail::signature_scalars(sig, policy);
    if (!rs)
        return err(rs.unwrap_err());
    const scalar r = (*rs)[0], s = (*rs)[1];
    const scalar z = scalar::from_bytes_reduced(hash);
    const scalar w = s.inverse();
    const auto x = point::mul_add_public(z * w, r * w, point(key.point())).to_affine();
    if (!x || !(scalar::from_bytes_reduced(x->x.to_bytes()) == r))
        return err(errc::invalid_signature);
    return ok();
}

/// \brief Recovers the public key from a signature, its recovery id and the hash. Variable time; public data only.
/// \ingroup secp256k1
/// \param hash The message hash.
/// \param sig The signature.
/// \param recovery_id 0 to 3.
/// \param policy Whether an s above n / 2 is accepted.
/// \return The key, or `errc::invalid_signature`, `errc::high_s`, `errc::invalid_recovery_id`, `errc::recovery_failed`.
[[nodiscard]] constexpr result<public_key, errc> recover(std::span<const std::uint8_t, 32> hash, const signature& sig,
                                                         std::uint8_t recovery_id, high_s policy = high_s::accept) noexcept
{
    if (recovery_id > 3)
        return err(errc::invalid_recovery_id);
    const auto rs = detail::signature_scalars(sig, policy);
    if (!rs)
        return err(rs.unwrap_err());
    const scalar r = (*rs)[0], s = (*rs)[1];
    // x = r + (id / 2) n, which must be a field element
    auto x_limbs = crypto::detail::from_be(sig.r);
    if (recovery_id & 2) {
        crypto::detail::limbs4 t{};
        if (crypto::detail::add4(t, x_limbs, secp256k1::detail::order_modulus.m))
            return err(errc::recovery_failed);
        x_limbs = t;
    }
    const auto x = field_element::from_bytes(crypto::detail::to_be(x_limbs));
    if (!x)
        return err(errc::recovery_failed);
    const auto big_r = decompress(*x, recovery_id & 1);
    if (!big_r)
        return err(errc::recovery_failed);
    const scalar z = scalar::from_bytes_reduced(hash);
    const scalar r_inverse = r.inverse();
    const auto q = point::mul_add_public(-(z * r_inverse), s * r_inverse, point(*big_r)).to_affine();
    if (!q)
        return err(errc::recovery_failed);
    return ok(public_key(*q));
}

/// \brief Ethereum's `ecrecover`: the key behind a 65-byte r || s || v signature, v = 27 or 28. Variable time.
/// \ingroup secp256k1
/// \param hash The message hash (Keccak-256 of the message, or of EIP-191's prefixed message).
/// \param rsv r, s and v.
/// \param policy `high_s::accept` as the precompile does; `high_s::reject` for transactions (EIP-2).
/// \return The key (its `xy()` hashed with Keccak-256 gives the address), or the errors of `recover`;
/// `errc::invalid_recovery_id` for any other v.
[[nodiscard]] constexpr result<public_key, errc> recover_ethereum(std::span<const std::uint8_t, 32> hash,
                                                                  std::span<const std::uint8_t, 65> rsv,
                                                                  high_s policy = high_s::accept) noexcept
{
    if (rsv[64] != 27 && rsv[64] != 28)
        return err(errc::invalid_recovery_id);
    return recover(hash, signature::from_compact(rsv.first<64>()), static_cast<std::uint8_t>(rsv[64] - 27), policy);
}

} // namespace snicholls::crypto::secp256k1

#endif /* snicholls_crypto_secp256k1_ecdsa_hpp */

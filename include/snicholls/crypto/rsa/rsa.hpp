//
//  rsa.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief RSA signature verification (RFC 8017): RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256 (RS256, PS256).
/// \ingroup rsa
///
/// \overview
/// Verification only: checking signatures made by others with public keys they publish (JWKS `n` and `e`, an X.509
/// SubjectPublicKeyInfo, a PKCS#1 RSAPublicKey). There is no RSA signing or decryption here, so no RSA private key
/// ever enters this library.
///
/// - Keys: `public_key::from_components(n, e)` (big-endian bytes, as a JWK's `n` and `e` are after base64url
///   decoding), `public_key::from_spki_der` (a SubjectPublicKeyInfo with the rsaEncryption identifier, or a bare
///   RSAPublicKey) and `public_key::from_pkcs1_der` (a bare RSAPublicKey only). Moduli of 2048 to 4096 bits; odd
///   exponents from 3 to 2^64 - 1.
/// - `verify_pkcs1v15_sha256`: RFC 8017 section 8.2.2 with EMSA-PKCS1-v1_5 and SHA-256 (JOSE's RS256). The encoded
///   message is rebuilt from the hash and compared whole, so no parser of the padding or the DigestInfo exists to be
///   lenient (the class of forgery behind Bleichenbacher's 2006 low-exponent attack is impossible by construction).
///   The DigestInfo is DER with its NULL parameters; the form without them, which RFC 8017 does not define for
///   SHA-256 and Wycheproof marks "acceptable", is refused.
/// - `verify_pss_sha256`: RFC 8017 section 8.1.2 with EMSA-PSS, SHA-256 and MGF1-SHA-256 (JOSE's PS256), for a
///   given salt length (32 by default, as PS256 uses; 0 to the maximum the modulus allows).
/// - Each has a prehashed form taking the 32-byte SHA-256 of the message.
///
/// Strict input (CLAUDE.md rule 8): a signature must be exactly as long as the modulus, and below it; `n` and `e`
/// given as components must have no leading zero byte (JWK's rule, RFC 7518 section 6.3.1); DER must be DER (minimal
/// lengths and integers, nothing trailing), with the rsaEncryption algorithm's NULL parameters present.
///
/// \relations
/// - `detail/montgomery.hpp`: the modular arithmetic; `detail/hashes.hpp`: SHA-256 (core's).
/// - Group: \ref rsa.
///
/// \impls
/// One: s^e mod n by left-to-right square-and-multiply in Montgomery form (CIOS multiplication, 64-bit limbs), the
/// modulus's Montgomery constants computed when the key is made.
///
/// \contracts
/// - Variable time; public data only. Every input is public (a public key, a message, a signature), so the
///   arithmetic runs over the modulus's length and the exponent's bits, and comparisons stop at the first
///   difference. There is no secret on any path in this header.
/// - Everything is `constexpr` and `noexcept`; no allocation (a key holds fixed arrays for 4096 bits, about 1 KB).
/// - Thread safety: a `public_key` is a value; concurrent verifications with one key are safe.
///
/// \errors
/// `errc::invalid_public_key` for a key outside the limits or badly encoded, `errc::non_canonical` for a component
/// with a leading zero byte, `errc::invalid_signature` for a signature of the wrong length, at or above the modulus,
/// or that does not verify, `errc::invalid_length` for a PSS salt length the modulus cannot hold.
///
/// \examples
/// \snippet rsa/rsa_demo.cpp rsa
///
/// \perf
/// One modular exponentiation with the public exponent: 17 Montgomery multiplications for e = 65537. See
/// BENCHMARKS.md, `benchmarks/rsa/rsa_benchmark.cpp`.
///
/// \testing
/// `tests/rsa/rsa_test.cpp`: every Wycheproof `rsa_signature_{2048,3072,4096}_sha256` and
/// `rsa_pss_{2048,3072,4096}_sha256_mgf1_32`, `rsa_pss_2048_sha256_mgf1_0` case (`tests/fixtures/wycheproof/`),
/// each key read from its SubjectPublicKeyInfo, its RSAPublicKey and its components; key and DER edge cases.
/// `tests/rsa/rsa_oracles_test.cpp`: signatures from OpenSSL, Node and RustCrypto (`tests/fixtures/oracles/`).
/// `demos/rsa/rsa_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp` and SHA-256.
///
/// \gotchas
/// A JWK's `n` and `e` are base64url text: decode them first (this library takes bytes). PEM is base64 text around
/// DER: strip the armour and decode it first. Pick the scheme from the token or the protocol, never by trying both.
///
/// \status
/// Experimental (0.2).

#ifndef snicholls_crypto_rsa_rsa_hpp
#define snicholls_crypto_rsa_rsa_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/detail/montgomery.hpp>
#include <snicholls/crypto/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

/// \brief RSA signature verification (RFC 8017).
namespace snicholls::crypto::rsa {

inline constexpr std::size_t min_modulus_bits = 2048;   ///< The smallest modulus accepted.
inline constexpr std::size_t max_modulus_bits = 4096;   ///< The largest modulus accepted.
inline constexpr std::size_t max_modulus_bytes = max_modulus_bits / 8;   ///< The longest signature, in bytes.

namespace detail {

// A strict DER reader over one buffer: a tag, a minimal definite length, then that many bytes
class der_reader {
public:
    constexpr explicit der_reader(std::span<const std::uint8_t> b) noexcept : b_(b) {}

    [[nodiscard]] constexpr bool done() const noexcept { return i_ == b_.size(); }

    // The contents of the next element if it has the tag; std::nullopt otherwise
    constexpr std::optional<std::span<const std::uint8_t>> next(std::uint8_t tag) noexcept
    {
        if (b_.size() - i_ < 2 || b_[i_] != tag)
            return std::nullopt;
        std::size_t j = i_ + 1;
        std::size_t len = b_[j++];
        if (len & 0x80) {
            const std::size_t n = len & 0x7f;
            if (n == 0 || n > 2 || b_.size() - j < n || b_[j] == 0)
                return std::nullopt;   // indefinite, too long for a key, or not minimal
            len = 0;
            for (std::size_t k = 0; k < n; ++k)
                len = len << 8 | b_[j++];
            if (len < 0x80)
                return std::nullopt;   // the long form where the short one fits
        }
        if (b_.size() - j < len)
            return std::nullopt;
        i_ = j + len;
        return b_.subspan(j, len);
    }

private:
    std::span<const std::uint8_t> b_;
    std::size_t i_ = 0;
};

// A DER INTEGER's contents as an unsigned big-endian magnitude: non-negative and minimal
constexpr std::optional<std::span<const std::uint8_t>> der_unsigned(std::span<const std::uint8_t> v) noexcept
{
    if (v.empty() || (v[0] & 0x80))
        return std::nullopt;
    if (v.size() > 1 && v[0] == 0 && !(v[1] & 0x80))
        return std::nullopt;
    return v[0] == 0 && v.size() > 1 ? v.subspan(1) : v;
}

inline constexpr std::array<std::uint8_t, 9> rsa_encryption_oid{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};

// DER of DigestInfo for SHA-256, before the hash (RFC 8017 section 9.2, note 1)
inline constexpr std::array<std::uint8_t, 19> sha256_digest_info{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                                 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

} // namespace detail

/// \brief An RSA public key for verification: a modulus of 2048 to 4096 bits and an odd public exponent.
/// \ingroup rsa
///
/// Made only by the three factory functions, which check the limits; a key holds its Montgomery constants.
class public_key {
public:
    /// \brief A key from its components, big-endian with no leading zero byte (a JWK's `n` and `e`, decoded).
    /// \param n The modulus.
    /// \param e The public exponent.
    /// \return The key; `errc::non_canonical` for a leading zero byte, `errc::invalid_public_key` for a modulus outside
    /// 2048 to 4096 bits or even, or an exponent that is even, below 3, wider than 64 bits or not below the modulus.
    [[nodiscard]] static constexpr result<public_key, errc> from_components(std::span<const std::uint8_t> n,
                                                                            std::span<const std::uint8_t> e) noexcept
    {
        if ((!n.empty() && n[0] == 0) || (!e.empty() && e[0] == 0))
            return err(errc::non_canonical);
        return make(n, e);
    }

    /// \brief A key from a DER RSAPublicKey (PKCS#1: SEQUENCE { modulus INTEGER, publicExponent INTEGER }).
    /// \param der The DER.
    /// \return The key, or `errc::invalid_public_key` for anything but exactly that, in DER, within the limits.
    [[nodiscard]] static constexpr result<public_key, errc> from_pkcs1_der(std::span<const std::uint8_t> der) noexcept
    {
        detail::der_reader outer(der);
        const auto seq = outer.next(0x30);
        if (!seq || !outer.done())
            return err(errc::invalid_public_key);
        detail::der_reader in(*seq);
        const auto n = in.next(0x02);
        const auto e = n ? in.next(0x02) : std::nullopt;
        if (!e || !in.done())
            return err(errc::invalid_public_key);
        const auto nu = detail::der_unsigned(*n);
        const auto eu = detail::der_unsigned(*e);
        if (!nu || !eu)
            return err(errc::invalid_public_key);
        return make(*nu, *eu);
    }

    /// \brief A key from a DER SubjectPublicKeyInfo with the rsaEncryption algorithm (an X.509 or PEM "PUBLIC KEY"),
    /// or from a bare RSAPublicKey.
    /// \param der The DER.
    /// \return The key, or `errc::invalid_public_key` for any other structure or algorithm, or a key outside the limits.
    [[nodiscard]] static constexpr result<public_key, errc> from_spki_der(std::span<const std::uint8_t> der) noexcept
    {
        detail::der_reader outer(der);
        const auto seq = outer.next(0x30);
        if (!seq || !outer.done())
            return err(errc::invalid_public_key);
        if (!seq->empty() && (*seq)[0] == 0x02)
            return from_pkcs1_der(der);   // a bare RSAPublicKey: its first element is the modulus
        detail::der_reader in(*seq);
        const auto alg = in.next(0x30);
        const auto bits = alg ? in.next(0x03) : std::nullopt;
        if (!bits || !in.done())
            return err(errc::invalid_public_key);
        detail::der_reader a(*alg);
        const auto oid = a.next(0x06);
        const auto null = oid ? a.next(0x05) : std::nullopt;
        if (!null || !null->empty() || !a.done() || oid->size() != detail::rsa_encryption_oid.size())
            return err(errc::invalid_public_key);
        for (std::size_t i = 0; i < oid->size(); ++i)
            if ((*oid)[i] != detail::rsa_encryption_oid[i])
                return err(errc::invalid_public_key);
        if (bits->empty() || (*bits)[0] != 0)
            return err(errc::invalid_public_key);   // a whole number of bytes: no unused bits
        return from_pkcs1_der(bits->subspan(1));
    }

    /// \brief The modulus's length in bits.
    /// \return 2048 to 4096.
    [[nodiscard]] constexpr std::size_t modulus_bits() const noexcept { return bits_; }

    /// \brief The modulus's length in bytes, which is a signature's length.
    /// \return 256 to 512.
    [[nodiscard]] constexpr std::size_t modulus_bytes() const noexcept { return (bits_ + 7) / 8; }

    /// \brief The public exponent.
    /// \return e.
    [[nodiscard]] constexpr std::uint64_t exponent() const noexcept { return e_; }

    /// \brief s^e mod n as modulus_bytes() big-endian bytes, the first step of every verification. Variable time;
    /// public data only.
    /// \param sig The signature, exactly modulus_bytes() long.
    /// \param out modulus_bytes() bytes, or more (only the first modulus_bytes() are written).
    /// \return Success, or `errc::invalid_signature` for a signature of the wrong length or not below the modulus.
    [[nodiscard]] constexpr result<void, errc> open(std::span<const std::uint8_t> sig, std::span<std::uint8_t> out) const noexcept
    {
        const std::size_t k = modulus_bytes();
        if (sig.size() != k || out.size() < k)
            return err(errc::invalid_signature);
        const auto s = crypto::detail::wide_from_be(sig);
        if (!s || !crypto::detail::wide_less(*s, mont_.modulus(), crypto::detail::mont_max_limbs))
            return err(errc::invalid_signature);
        crypto::detail::wide_to_be(mont_.pow(*s, e_), out.first(k));
        return ok();
    }

private:
    constexpr public_key(const crypto::detail::montgomery& m, std::uint64_t e, std::size_t bits) noexcept
        : mont_(m), e_(e), bits_(bits)
    {
    }

    static constexpr result<public_key, errc> make(std::span<const std::uint8_t> n, std::span<const std::uint8_t> e) noexcept
    {
        if (n.size() > max_modulus_bytes || e.empty() || e.size() > 8)
            return err(errc::invalid_public_key);
        const auto nw = crypto::detail::wide_from_be(n);
        if (!nw)
            return err(errc::invalid_public_key);
        const std::size_t bits = crypto::detail::wide_bits(*nw);
        std::uint64_t ev = 0;
        for (const auto b : e)
            ev = ev << 8 | b;
        if (bits < min_modulus_bits || bits > max_modulus_bits || ev < 3 || (ev & 1) == 0)
            return err(errc::invalid_public_key);
        const auto m = crypto::detail::montgomery::make(*nw);   // refuses an even modulus
        if (!m)
            return err(errc::invalid_public_key);
        return ok(public_key(*m, ev, bits));
    }

    crypto::detail::montgomery mont_;
    std::uint64_t e_ = 0;
    std::size_t bits_ = 0;
};

namespace detail {

// MGF1 with SHA-256 (RFC 8017 appendix B.2.1), XORed into out
constexpr void mgf1_sha256_xor(std::span<const std::uint8_t, 32> seed, std::span<std::uint8_t> out) noexcept
{
    std::size_t done = 0;
    for (std::uint32_t counter = 0; done < out.size(); ++counter) {
        crypto::detail::sha256 h;
        h.update(seed);
        const std::array<std::uint8_t, 4> c{static_cast<std::uint8_t>(counter >> 24), static_cast<std::uint8_t>(counter >> 16),
                                            static_cast<std::uint8_t>(counter >> 8), static_cast<std::uint8_t>(counter)};
        h.update(c);
        const auto block = h.finish();
        for (std::size_t i = 0; i < block.size() && done < out.size(); ++i)
            out[done++] ^= block[i];
    }
}

} // namespace detail

/// \brief Verifies an RSASSA-PKCS1-v1_5 signature over a SHA-256 hash (RFC 8017 section 8.2.2). Variable time; public
/// data only.
/// \ingroup rsa
/// \param key The signer's public key.
/// \param hash The SHA-256 of the message.
/// \param sig The signature, exactly `key.modulus_bytes()` long.
/// \return Success, or `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> verify_pkcs1v15_sha256_prehashed(const public_key& key,
                                                                            std::span<const std::uint8_t, 32> hash,
                                                                            std::span<const std::uint8_t> sig) noexcept
{
    std::array<std::uint8_t, max_modulus_bytes> em{};
    if (const auto r = key.open(sig, em); !r)
        return r;
    // EM = 0x00 0x01 0xFF ... 0xFF 0x00 DigestInfo H, rebuilt and compared whole
    const std::size_t k = key.modulus_bytes();
    const std::size_t t = detail::sha256_digest_info.size() + hash.size();
    std::size_t i = 0;
    bool same = em[i++] == 0x00 && em[i++] == 0x01;
    for (; i < k - t - 1; ++i)
        same = same && em[i] == 0xff;
    same = same && em[i++] == 0x00;
    for (const auto b : detail::sha256_digest_info)
        same = same && em[i++] == b;
    for (const auto b : hash)
        same = same && em[i++] == b;
    if (!same)
        return err(errc::invalid_signature);
    return ok();
}

/// \brief Verifies an RSASSA-PKCS1-v1_5 signature with SHA-256 over a message: JOSE's RS256. Variable time; public data
/// only.
/// \ingroup rsa
/// \param key The signer's public key.
/// \param message The signed bytes (for a JWS, the ASCII of `header.payload`).
/// \param sig The signature, exactly `key.modulus_bytes()` long.
/// \return Success, or `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> verify_pkcs1v15_sha256(const public_key& key, std::span<const std::uint8_t> message,
                                                                  std::span<const std::uint8_t> sig) noexcept
{
    const auto h = crypto::detail::sha256::hash(message);
    return verify_pkcs1v15_sha256_prehashed(key, h, sig);
}

/// \brief Verifies an RSASSA-PSS signature over a SHA-256 hash, with MGF1-SHA-256 (RFC 8017 sections 8.1.2 and
/// 9.1.2). Variable time; public data only.
/// \ingroup rsa
/// \param key The signer's public key.
/// \param hash The SHA-256 of the message.
/// \param sig The signature, exactly `key.modulus_bytes()` long.
/// \param salt_length The salt length the signer used, in bytes (PS256: 32).
/// \return Success, `errc::invalid_length` for a salt length the modulus cannot hold, or `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> verify_pss_sha256_prehashed(const public_key& key, std::span<const std::uint8_t, 32> hash,
                                                                       std::span<const std::uint8_t> sig,
                                                                       std::size_t salt_length = 32) noexcept
{
    constexpr std::size_t h_len = 32;
    const std::size_t em_bits = key.modulus_bits() - 1;
    const std::size_t em_len = (em_bits + 7) / 8;
    if (em_len < h_len + salt_length + 2)
        return err(errc::invalid_length);
    std::array<std::uint8_t, max_modulus_bytes> m{};
    if (const auto r = key.open(sig, m); !r)
        return r;
    // EM is the last em_len bytes of m; when em_bits is a multiple of 8 the extra leading byte must be zero
    const std::size_t k = key.modulus_bytes();
    if (k != em_len && m[0] != 0)
        return err(errc::invalid_signature);
    const std::span<std::uint8_t> em(m.data() + (k - em_len), em_len);
    if (em[em_len - 1] != 0xbc)
        return err(errc::invalid_signature);
    const std::size_t db_len = em_len - h_len - 1;
    const std::span<std::uint8_t> db = em.first(db_len);
    const std::span<const std::uint8_t, h_len> h(em.data() + db_len, h_len);
    const std::size_t zero_bits = 8 * em_len - em_bits;
    const auto top_mask = static_cast<std::uint8_t>(0xff >> zero_bits);
    if (db[0] & ~top_mask)
        return err(errc::invalid_signature);
    std::array<std::uint8_t, h_len> h_copy{};
    for (std::size_t i = 0; i < h_len; ++i)
        h_copy[i] = h[i];
    detail::mgf1_sha256_xor(h_copy, db);
    db[0] &= top_mask;
    const std::size_t ps_len = db_len - salt_length - 1;
    for (std::size_t i = 0; i < ps_len; ++i)
        if (db[i] != 0)
            return err(errc::invalid_signature);
    if (db[ps_len] != 0x01)
        return err(errc::invalid_signature);
    // H' = SHA-256(0x00 x 8 || mHash || salt)
    crypto::detail::sha256 hp;
    const std::array<std::uint8_t, 8> zeros{};
    hp.update(zeros);
    hp.update(hash);
    hp.update(db.subspan(ps_len + 1, salt_length));
    const auto expected = hp.finish();
    for (std::size_t i = 0; i < h_len; ++i)
        if (expected[i] != h_copy[i])
            return err(errc::invalid_signature);
    return ok();
}

/// \brief Verifies an RSASSA-PSS signature with SHA-256 and MGF1-SHA-256 over a message: JOSE's PS256 (salt length
/// 32). Variable time; public data only.
/// \ingroup rsa
/// \param key The signer's public key.
/// \param message The signed bytes.
/// \param sig The signature, exactly `key.modulus_bytes()` long.
/// \param salt_length The salt length the signer used, in bytes (PS256: 32).
/// \return Success, `errc::invalid_length` for a salt length the modulus cannot hold, or `errc::invalid_signature`.
[[nodiscard]] constexpr result<void, errc> verify_pss_sha256(const public_key& key, std::span<const std::uint8_t> message,
                                                             std::span<const std::uint8_t> sig,
                                                             std::size_t salt_length = 32) noexcept
{
    const auto h = crypto::detail::sha256::hash(message);
    return verify_pss_sha256_prehashed(key, h, sig, salt_length);
}

} // namespace snicholls::crypto::rsa

#endif /* snicholls_crypto_rsa_rsa_hpp */

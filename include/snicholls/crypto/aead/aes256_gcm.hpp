//
//  aes256_gcm.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief AES-256-GCM (NIST SP 800-38D): authenticated encryption with associated data, 96-bit nonces.
/// \ingroup aead
///
/// \overview
/// The same shape as `aead/chacha20_poly1305.hpp`: `aes256_gcm_seal` writes the ciphertext and returns the
/// 16-byte tag; `aes256_gcm_open` checks the tag in constant time and only then writes the plaintext. JOSE's A256GCM
/// (JWE content encryption) and TLS's AES_256_GCM. The nonce is 96 bits, the length NIST recommends and JOSE uses;
/// other lengths are not offered.
///
/// \relations
/// - `detail/aes.hpp` (AES-256 without tables, GHASH); `aead/chacha20_poly1305.hpp` (the same interface);
///   `aead/aes_key_wrap.hpp` (A256KW).
/// - Group: \ref aead.
///
/// \impls
/// One: counter mode from J0 + 1 with J0 = nonce || 0^31 || 1, GHASH over the associated data and the ciphertext
/// with their lengths, the tag E(K, J0) XOR GHASH. AES computes its S-box (no tables) and GHASH multiplies bit by
/// bit with masks.
///
/// \contracts
/// - Constant time in the key, the plaintext and the tag: no memory index or branch depends on them; lengths and
///   the nonce are public. Revealed on purpose: whether the tag matched.
/// - `open` writes nothing it has not authenticated; on a mismatch the output is zeroed.
/// - In place allowed. `constexpr`, `noexcept`, no allocation.
/// - Slower than AES-NI or table implementations (each S-box value is computed): fine for cookies, tokens and JWE,
///   not for bulk data; use ChaCha20-Poly1305 for that.
///
/// \errors
/// `errc::invalid_length` for an output of another length, or a message over 2^36 - 32 bytes;
/// `errc::authentication_failed` from `open`.
///
/// \examples
/// \snippet aead/aes256_gcm_demo.cpp gcm
///
/// \perf
/// About 100 us for 64 bytes and 1 MB/s for longer messages (Release, Xeon W-3245): roughly 200 times slower than
/// ChaCha20-Poly1305 here, the price of computing AES's S-box without tables or AES-NI. Fine for JWE's keys and short
/// payloads; use XChaCha20-Poly1305 for cookies and bulk data. See `benchmarks/aead/aes256_gcm_benchmark.cpp`.
///
/// \testing
/// `tests/aead/aes256_gcm_test.cpp`: the GCM specification's test cases 13 to 16 (AES-256), every Wycheproof
/// `aes_gcm_test.json` case with a 256-bit key, a 96-bit nonce and a 128-bit tag, in-place use;
/// `tests/aead/aes256_gcm_oracles_test.cpp`: OpenSSL and Node's crypto. The secret paths are in the Valgrind check.
/// `demos/aead/aes256_gcm_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`.
///
/// \gotchas
/// A 96-bit nonce must never repeat under one key: a repeat reveals the authentication key. With random nonces keep
/// to well under 2^32 messages per key, or use XChaCha20-Poly1305.
///
/// \status
/// Experimental (0.4).

#ifndef snicholls_crypto_aead_aes256_gcm_hpp
#define snicholls_crypto_aead_aes256_gcm_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/aead/chacha20_poly1305.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/aes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace snicholls::crypto::aead {

namespace detail {

inline constexpr std::uint64_t gcm_max_message = (std::uint64_t{1} << 36) - 32;

constexpr void gcm_ctr(const crypto::detail::aes256& aes, std::array<std::uint8_t, 16> counter, std::span<const std::uint8_t> in,
                       std::span<std::uint8_t> out) noexcept
{
    for (std::size_t off = 0; off < in.size(); off += 16) {
        // inc32: the last four bytes, big-endian
        for (std::size_t i = 16; i-- > 12;)
            if (++counter[i] != 0)   // the counter is public
                break;
        auto ks = aes.encrypt(counter);
        const std::size_t n = in.size() - off < 16 ? in.size() - off : 16;
        for (std::size_t i = 0; i < n; ++i)
            out[off + i] = static_cast<std::uint8_t>(in[off + i] ^ ks[i]);
        secure_wipe(ks);
    }
}

constexpr void ghash_update(std::array<std::uint8_t, 16>& y, const std::array<std::uint8_t, 16>& h, std::span<const std::uint8_t> data) noexcept
{
    for (std::size_t off = 0; off < data.size(); off += 16) {
        const std::size_t n = data.size() - off < 16 ? data.size() - off : 16;
        for (std::size_t i = 0; i < n; ++i)
            y[i] ^= data[off + i];
        y = crypto::detail::ghash_mul(y, h);
    }
}

constexpr tag gcm_tag(const crypto::detail::aes256& aes, const std::array<std::uint8_t, 16>& j0, std::span<const std::uint8_t> aad,
                      std::span<const std::uint8_t> ciphertext) noexcept
{
    auto h = aes.encrypt({});
    std::array<std::uint8_t, 16> y{};
    ghash_update(y, h, aad);
    ghash_update(y, h, ciphertext);
    std::array<std::uint8_t, 16> lengths{};
    const std::uint64_t abits = static_cast<std::uint64_t>(aad.size()) * 8, cbits = static_cast<std::uint64_t>(ciphertext.size()) * 8;
    for (std::size_t i = 0; i < 8; ++i) {
        lengths[i] = static_cast<std::uint8_t>(abits >> (56 - 8 * i));
        lengths[8 + i] = static_cast<std::uint8_t>(cbits >> (56 - 8 * i));
    }
    ghash_update(y, h, lengths);
    auto ek = aes.encrypt(j0);
    tag t{};
    for (std::size_t i = 0; i < 16; ++i)
        t[i] = static_cast<std::uint8_t>(ek[i] ^ y[i]);
    secure_wipe(h);
    secure_wipe(ek);
    return t;
}

constexpr std::array<std::uint8_t, 16> gcm_j0(std::span<const std::uint8_t, 12> nonce) noexcept
{
    std::array<std::uint8_t, 16> j0{};
    for (std::size_t i = 0; i < 12; ++i)
        j0[i] = nonce[i];
    j0[15] = 1;
    return j0;
}

} // namespace detail

/// \brief Encrypts and authenticates with AES-256-GCM. Constant time in the key and the plaintext.
/// \ingroup aead
/// \param key The 32-byte key.
/// \param nonce The 12-byte nonce, never repeated under this key.
/// \param aad Associated data, authenticated but not encrypted.
/// \param plaintext The message.
/// \param ciphertext Where the ciphertext goes: exactly as long as the plaintext (may be the same span).
/// \return The tag, or `errc::invalid_length`.
[[nodiscard]] constexpr result<tag, errc> aes256_gcm_seal(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                                                          std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plaintext,
                                                          std::span<std::uint8_t> ciphertext) noexcept
{
    if (plaintext.size() != ciphertext.size() || plaintext.size() > detail::gcm_max_message)
        return err(errc::invalid_length);
    const crypto::detail::aes256 aes(key);
    const auto j0 = detail::gcm_j0(nonce);
    detail::gcm_ctr(aes, j0, plaintext, ciphertext);
    return ok(detail::gcm_tag(aes, j0, aad, ciphertext));
}

/// \brief Checks the tag and decrypts with AES-256-GCM. Constant time in the key, the plaintext and the tag.
/// \ingroup aead
/// \param key The 32-byte key.
/// \param nonce The 12-byte nonce used to seal.
/// \param aad The associated data used to seal.
/// \param ciphertext The ciphertext.
/// \param received The 16-byte tag.
/// \param plaintext Where the plaintext goes: exactly as long as the ciphertext (may be the same span). Zeroed when
/// the tag does not match.
/// \return Success, `errc::authentication_failed` or `errc::invalid_length`.
[[nodiscard]] constexpr result<void, errc> aes256_gcm_open(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                                                           std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext,
                                                           std::span<const std::uint8_t, 16> received,
                                                           std::span<std::uint8_t> plaintext) noexcept
{
    if (plaintext.size() != ciphertext.size() || ciphertext.size() > detail::gcm_max_message)
        return err(errc::invalid_length);
    const crypto::detail::aes256 aes(key);
    const auto j0 = detail::gcm_j0(nonce);
    if (!detail::tags_equal(detail::gcm_tag(aes, j0, aad, ciphertext), received)) {
        for (auto& b : plaintext)
            b = 0;
        return err(errc::authentication_failed);
    }
    detail::gcm_ctr(aes, j0, ciphertext, plaintext);
    return ok();
}

} // namespace snicholls::crypto::aead

#endif /* snicholls_crypto_aead_aes256_gcm_hpp */

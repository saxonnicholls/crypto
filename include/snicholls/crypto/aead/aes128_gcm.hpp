//
//  aes128_gcm.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief AES-128-GCM (NIST SP 800-38D): authenticated encryption with associated data, 96-bit nonces.
/// \ingroup aead
///
/// \overview
/// AES-256-GCM's interface (`aead/aes256_gcm.hpp`) with a 16-byte key: `aes128_gcm_seal` writes the ciphertext and
/// returns the 16-byte tag; `aes128_gcm_open` checks the tag in constant time and only then writes the plaintext.
/// TLS 1.3's mandatory cipher suite (TLS_AES_128_GCM_SHA256, RFC 8446 9.1, with RFC 8446 5.3's per-record nonce)
/// and JOSE's A128GCM. The nonce is 96 bits; other lengths are not offered.
///
/// \relations
/// - `detail/aes.hpp` (AES without tables, `aes_cipher<16>`, and GHASH); `aead/aes256_gcm.hpp` (the same mode and
///   code, a 32-byte key).
/// - Group: \ref aead.
///
/// \impls
/// One: AES-256-GCM's `detail::gcm_seal` and `detail::gcm_open` instantiated for AES-128 (10 rounds).
///
/// \contracts
/// - Constant time in the key, the plaintext and the tag: no memory index or branch depends on them; lengths and
///   the nonce are public. Revealed on purpose: whether the tag matched.
/// - `open` writes nothing it has not authenticated; on a mismatch the output is zeroed.
/// - In place allowed. `constexpr`, `noexcept`, no allocation.
/// - Slower than AES-NI or table implementations (each S-box value is computed): see `aead/aes256_gcm.hpp`.
///
/// \errors
/// `errc::invalid_length` for an output of another length, or a message over 2^36 - 32 bytes;
/// `errc::authentication_failed` from `open`.
///
/// \examples
/// \snippet aead/aes128_gcm_demo.cpp gcm128
///
/// \perf
/// About 70% of AES-256-GCM's time per block (10 rounds instead of 14). See
/// `benchmarks/aead/aes128_gcm_benchmark.cpp`.
///
/// \testing
/// `tests/aead/aes128_gcm_test.cpp`: FIPS 197 C.1 (AES-128), the GCM specification's test cases 1 to 4, every
/// Wycheproof `aes_gcm_test.json` case with a 128-bit key, a 96-bit nonce and a 128-bit tag, in-place use;
/// `tests/aead/aes128_gcm_oracles_test.cpp`: OpenSSL and Node's crypto. The secret paths are in the Valgrind check.
/// `demos/aead/aes128_gcm_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`.
///
/// \gotchas
/// A 96-bit nonce must never repeat under one key: a repeat reveals the authentication key. TLS derives each
/// record's nonce from a sequence number for this reason.
///
/// \status
/// Experimental (0.5).

#ifndef snicholls_crypto_aead_aes128_gcm_hpp
#define snicholls_crypto_aead_aes128_gcm_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/aead/aes256_gcm.hpp>
#include <snicholls/crypto/error.hpp>

#include <cstdint>
#include <span>

namespace snicholls::crypto::aead {

/// \brief Encrypts and authenticates with AES-128-GCM. Constant time in the key and the plaintext.
/// \ingroup aead
/// \param key The 16-byte key.
/// \param nonce The 12-byte nonce, never repeated under this key.
/// \param aad Associated data, authenticated but not encrypted.
/// \param plaintext The message.
/// \param ciphertext Where the ciphertext goes: exactly as long as the plaintext (may be the same span).
/// \return The tag, or `errc::invalid_length`.
[[nodiscard]] constexpr result<tag, errc> aes128_gcm_seal(std::span<const std::uint8_t, 16> key, std::span<const std::uint8_t, 12> nonce,
                                                          std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plaintext,
                                                          std::span<std::uint8_t> ciphertext) noexcept
{
    return detail::gcm_seal<16>(key, nonce, aad, plaintext, ciphertext);
}

/// \brief Checks the tag and decrypts with AES-128-GCM. Constant time in the key, the plaintext and the tag.
/// \ingroup aead
/// \param key The 16-byte key.
/// \param nonce The 12-byte nonce used to seal.
/// \param aad The associated data used to seal.
/// \param ciphertext The ciphertext.
/// \param received The 16-byte tag.
/// \param plaintext Where the plaintext goes: exactly as long as the ciphertext (may be the same span). Zeroed when
/// the tag does not match.
/// \return Success, `errc::authentication_failed` or `errc::invalid_length`.
[[nodiscard]] constexpr result<void, errc> aes128_gcm_open(std::span<const std::uint8_t, 16> key, std::span<const std::uint8_t, 12> nonce,
                                                           std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext,
                                                           std::span<const std::uint8_t, 16> received,
                                                           std::span<std::uint8_t> plaintext) noexcept
{
    return detail::gcm_open<16>(key, nonce, aad, ciphertext, received, plaintext);
}

} // namespace snicholls::crypto::aead

#endif /* snicholls_crypto_aead_aes128_gcm_hpp */

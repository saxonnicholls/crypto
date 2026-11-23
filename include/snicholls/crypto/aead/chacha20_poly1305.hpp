//
//  chacha20_poly1305.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305: authenticated encryption with associated data.
/// \ingroup aead
///
/// \overview
/// Encrypts and authenticates a message under a 32-byte key and a nonce, and authenticates associated data (a
/// header, a cookie's name, a record id) that is not encrypted. `seal` writes the ciphertext, as long as the
/// plaintext, and returns the 16-byte tag; `open` checks the tag in constant time and only then writes the
/// plaintext.
///
/// - `chacha20_poly1305_seal` / `_open`: RFC 8439, a 12-byte nonce. A nonce must never repeat under one key: use a
///   counter, or XChaCha20.
/// - `xchacha20_poly1305_seal` / `_open`: draft-irtf-cfrg-xchacha, a 24-byte nonce, long enough to choose at random
///   for every message (session cookies, tokens at rest). HChaCha20 derives a subkey from the key and the first 16
///   nonce bytes; the last 8 make the 12-byte nonce, after four zero bytes.
///
/// \relations
/// - `detail/chacha20.hpp` (ChaCha20, HChaCha20), `detail/poly1305.hpp` (Poly1305).
/// - Keys from a secret: core's `hkdf` (`hash/kdf.hpp`).
/// - Group: \ref aead.
///
/// \impls
/// One: RFC 8439 section 2.8, the Poly1305 key the first 32 bytes of the ChaCha20 block at counter 0, the message
/// encrypted from counter 1, the tag over aad || pad16 || ciphertext || pad16 || len(aad) || len(ciphertext).
///
/// \contracts
/// - Constant time in the key, the plaintext and the tag: ChaCha20 is additions, rotations and XORs; Poly1305's
///   reduction is masked; the tag is compared in full with no early exit. Lengths and the nonce are public.
///   Revealed on purpose (`ct::declassify`): whether the tag matched.
/// - `open` writes nothing it has not authenticated: on a mismatch the output is zeroed and
///   `errc::authentication_failed` returned. Intermediate keys and keystream are wiped.
/// - The input and output may be the same span (in place); otherwise they must not overlap.
/// - `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `errc::invalid_length` when the output is not exactly as long as the input, or the message is longer than RFC
/// 8439 allows (2^38 - 64 bytes); `errc::authentication_failed` from `open` when the tag does not match.
///
/// \examples
/// \snippet aead/chacha20_poly1305_demo.cpp aead
///
/// \perf
/// About one ChaCha20 block and one Poly1305 block per 64 and 16 bytes. See BENCHMARKS.md,
/// `benchmarks/aead/chacha20_poly1305_benchmark.cpp`.
///
/// \testing
/// `tests/aead/chacha20_poly1305_test.cpp`: RFC 8439 sections 2.3.2, 2.4.2, 2.5.2, 2.8.2 and appendix A, the XChaCha
/// draft's vectors, every Wycheproof `chacha20_poly1305_test.json` and `xchacha20_poly1305_test.json` case, and
/// in-place use. `tests/aead/chacha20_poly1305_oracles_test.cpp`: libsodium, OpenSSL and RustCrypto. The secret
/// paths are in the Valgrind check. `demos/aead/chacha20_poly1305_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`.
///
/// \gotchas
/// Never reuse a nonce under the same key: with ChaCha20-Poly1305 a repeat reveals the XOR of two plaintexts and lets
/// an attacker forge tags. With random nonces use XChaCha20-Poly1305. The tag authenticates the associated data but
/// does not hide it.
///
/// \status
/// Experimental (0.4).

#ifndef snicholls_crypto_aead_chacha20_poly1305_hpp
#define snicholls_crypto_aead_chacha20_poly1305_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/chacha20.hpp>
#include <snicholls/crypto/detail/poly1305.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

/// \brief Authenticated encryption with associated data.
namespace snicholls::crypto::aead {

inline constexpr std::size_t key_size = 32;      ///< The key: 32 bytes.
inline constexpr std::size_t tag_size = 16;      ///< The tag: 16 bytes.
inline constexpr std::size_t nonce_size = 12;    ///< ChaCha20-Poly1305's nonce: 12 bytes.
inline constexpr std::size_t xnonce_size = 24;   ///< XChaCha20-Poly1305's nonce: 24 bytes.

/// \brief A 16-byte authentication tag.
using tag = std::array<std::uint8_t, tag_size>;

namespace detail {

inline constexpr std::uint64_t max_message = (std::uint64_t{1} << 38) - 64;

constexpr void pad16(crypto::detail::poly1305& mac, std::size_t n) noexcept
{
    const std::array<std::uint8_t, 16> zeros{};
    if (n % 16 != 0)
        mac.update(std::span<const std::uint8_t>(zeros).first(16 - n % 16));
}

constexpr tag compute_tag(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                          std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext) noexcept
{
    auto block = crypto::detail::chacha20_block(key, 0, nonce);
    crypto::detail::poly1305 mac(std::span<const std::uint8_t, 32>(block.data(), 32));
    secure_wipe(block);
    mac.update(aad);
    pad16(mac, aad.size());
    mac.update(ciphertext);
    pad16(mac, ciphertext.size());
    std::array<std::uint8_t, 16> lengths{};
    for (std::size_t i = 0; i < 8; ++i) {
        lengths[i] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(aad.size()) >> (8 * i));
        lengths[8 + i] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(ciphertext.size()) >> (8 * i));
    }
    mac.update(lengths);
    return mac.finish();
}

// The two tags equal, in constant time: every byte compared, the result revealed once
constexpr bool tags_equal(const tag& a, std::span<const std::uint8_t, 16> b) noexcept
{
    std::uint64_t diff = 0;
    for (std::size_t i = 0; i < 16; ++i)
        diff |= static_cast<std::uint64_t>(a[i] ^ b[i]);
    return ct::declassify(ct::mask_is_zero(diff)) != 0;
}

constexpr bool lengths_ok(std::size_t in, std::size_t out) noexcept { return in == out && in <= max_message; }

// XChaCha20's subkey and 12-byte nonce from the key and the 24-byte nonce
struct xparams {
    secret_bytes<32> key;
    std::array<std::uint8_t, 12> nonce{};
};

constexpr xparams xchacha(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 24> nonce) noexcept
{
    xparams x{secret_bytes<32>(crypto::detail::hchacha20(key, nonce.first<16>())), {}};
    for (std::size_t i = 0; i < 8; ++i)
        x.nonce[4 + i] = nonce[16 + i];
    return x;
}

} // namespace detail

/// \brief Encrypts and authenticates (RFC 8439 section 2.8). Constant time in the key and the plaintext.
/// \ingroup aead
/// \param key The 32-byte key.
/// \param nonce The 12-byte nonce, never repeated under this key.
/// \param aad Associated data, authenticated but not encrypted (may be empty).
/// \param plaintext The message.
/// \param ciphertext Where the ciphertext goes: exactly as long as the plaintext (may be the same span).
/// \return The tag, or `errc::invalid_length`.
[[nodiscard]] constexpr result<tag, errc> chacha20_poly1305_seal(std::span<const std::uint8_t, 32> key,
                                                                 std::span<const std::uint8_t, 12> nonce,
                                                                 std::span<const std::uint8_t> aad,
                                                                 std::span<const std::uint8_t> plaintext,
                                                                 std::span<std::uint8_t> ciphertext) noexcept
{
    if (!detail::lengths_ok(plaintext.size(), ciphertext.size()))
        return err(errc::invalid_length);
    crypto::detail::chacha20_xor(key, 1, nonce, plaintext, ciphertext);
    return ok(detail::compute_tag(key, nonce, aad, ciphertext));
}

/// \brief Checks the tag and decrypts (RFC 8439 section 2.8). Constant time in the key, the plaintext and the tag.
/// \ingroup aead
/// \param key The 32-byte key.
/// \param nonce The 12-byte nonce used to seal.
/// \param aad The associated data used to seal.
/// \param ciphertext The ciphertext.
/// \param received The 16-byte tag.
/// \param plaintext Where the plaintext goes: exactly as long as the ciphertext (may be the same span). Zeroed when
/// the tag does not match.
/// \return Success, `errc::authentication_failed` or `errc::invalid_length`.
[[nodiscard]] constexpr result<void, errc> chacha20_poly1305_open(std::span<const std::uint8_t, 32> key,
                                                                  std::span<const std::uint8_t, 12> nonce,
                                                                  std::span<const std::uint8_t> aad,
                                                                  std::span<const std::uint8_t> ciphertext,
                                                                  std::span<const std::uint8_t, 16> received,
                                                                  std::span<std::uint8_t> plaintext) noexcept
{
    if (!detail::lengths_ok(ciphertext.size(), plaintext.size()))
        return err(errc::invalid_length);
    const tag expected = detail::compute_tag(key, nonce, aad, ciphertext);
    if (!detail::tags_equal(expected, received)) {
        for (auto& b : plaintext)
            b = 0;
        return err(errc::authentication_failed);
    }
    crypto::detail::chacha20_xor(key, 1, nonce, ciphertext, plaintext);
    return ok();
}

/// \brief Encrypts and authenticates with a 24-byte nonce (XChaCha20-Poly1305), safe to choose at random. Constant
/// time in the key and the plaintext.
/// \ingroup aead
/// \param key The 32-byte key.
/// \param nonce The 24-byte nonce (random, or never repeated).
/// \param aad Associated data, authenticated but not encrypted.
/// \param plaintext The message.
/// \param ciphertext Where the ciphertext goes: exactly as long as the plaintext (may be the same span).
/// \return The tag, or `errc::invalid_length`.
[[nodiscard]] constexpr result<tag, errc> xchacha20_poly1305_seal(std::span<const std::uint8_t, 32> key,
                                                                  std::span<const std::uint8_t, 24> nonce,
                                                                  std::span<const std::uint8_t> aad,
                                                                  std::span<const std::uint8_t> plaintext,
                                                                  std::span<std::uint8_t> ciphertext) noexcept
{
    const auto x = detail::xchacha(key, nonce);
    return chacha20_poly1305_seal(x.key.reveal(), x.nonce, aad, plaintext, ciphertext);
}

/// \brief Checks the tag and decrypts, with a 24-byte nonce (XChaCha20-Poly1305). Constant time in the key, the
/// plaintext and the tag.
/// \ingroup aead
/// \param key The 32-byte key.
/// \param nonce The 24-byte nonce used to seal.
/// \param aad The associated data used to seal.
/// \param ciphertext The ciphertext.
/// \param received The 16-byte tag.
/// \param plaintext Where the plaintext goes: exactly as long as the ciphertext (may be the same span). Zeroed when
/// the tag does not match.
/// \return Success, `errc::authentication_failed` or `errc::invalid_length`.
[[nodiscard]] constexpr result<void, errc> xchacha20_poly1305_open(std::span<const std::uint8_t, 32> key,
                                                                   std::span<const std::uint8_t, 24> nonce,
                                                                   std::span<const std::uint8_t> aad,
                                                                   std::span<const std::uint8_t> ciphertext,
                                                                   std::span<const std::uint8_t, 16> received,
                                                                   std::span<std::uint8_t> plaintext) noexcept
{
    const auto x = detail::xchacha(key, nonce);
    return chacha20_poly1305_open(x.key.reveal(), x.nonce, aad, ciphertext, received, plaintext);
}

} // namespace snicholls::crypto::aead

#endif /* snicholls_crypto_aead_chacha20_poly1305_hpp */

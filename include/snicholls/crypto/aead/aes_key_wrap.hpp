//
//  aes_key_wrap.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief AES-256 key wrap (RFC 3394; JOSE's A256KW): a key encrypted and authenticated under a key-encryption key.
/// \ingroup aead
///
/// \overview
/// `aes256_key_wrap(kek, key, out)` wraps a key of n 64-bit blocks (n >= 2; 16, 24 or 32 bytes for AES keys) into
/// n + 1 blocks; `aes256_key_unwrap` reverses it and checks the integrity value A6A6A6A6A6A6A6A6 in constant time,
/// releasing nothing when it does not match. JWE's A256KW wraps the content-encryption key this way.
///
/// \relations
/// `detail/aes.hpp`; `aead/aes256_gcm.hpp`. Group: \ref aead.
///
/// \impls
/// One: RFC 3394 section 2.2.1 and 2.2.2 (the index-based form), six rounds over the blocks.
///
/// \contracts
/// Constant time in the key-encryption key and the wrapped key; the length is public; the integrity check is a
/// masked comparison whose result alone is revealed. Intermediates are wiped. `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `errc::invalid_length` for a key that is not a whole number of 64-bit blocks, fewer than two, more than 64, or an
/// output of the wrong length; `errc::authentication_failed` from unwrap when the integrity value does not match.
///
/// \examples
/// \snippet aead/aes_key_wrap_demo.cpp keywrap
///
/// \perf
/// 6 n AES blocks.
///
/// \testing
/// `tests/aead/aes_key_wrap_test.cpp`: RFC 3394 section 4.3, 4.5 and 4.6 (256-bit key-encryption keys), every
/// Wycheproof `aes_wrap_test.json` case with a 256-bit key. `demos/aead/aes_key_wrap_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`.
///
/// \gotchas
/// Key wrap is for keys (uniformly random data), not messages: use an AEAD for anything else.
///
/// \status
/// Experimental (0.4).

#ifndef snicholls_crypto_aead_aes_key_wrap_hpp
#define snicholls_crypto_aead_aes_key_wrap_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/aes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace snicholls::crypto::aead {

/// \brief The most 64-bit blocks a key to wrap may have (a 512-byte key).
inline constexpr std::size_t key_wrap_max_blocks = 64;

/// \brief Wraps a key under a 256-bit key-encryption key (RFC 3394 section 2.2.1). Constant time in both keys.
/// \ingroup aead
/// \param kek The 32-byte key-encryption key.
/// \param key The key to wrap: 16 to 512 bytes, a multiple of 8.
/// \param out Exactly 8 bytes longer than key.
/// \return Success, or `errc::invalid_length`.
[[nodiscard]] constexpr result<void, errc> aes256_key_wrap(std::span<const std::uint8_t, 32> kek, std::span<const std::uint8_t> key,
                                                           std::span<std::uint8_t> out) noexcept
{
    const std::size_t n = key.size() / 8;
    if (key.size() % 8 != 0 || n < 2 || n > key_wrap_max_blocks || out.size() != key.size() + 8)
        return err(errc::invalid_length);
    const crypto::detail::aes256 aes(kek);
    std::array<std::uint8_t, 8> a{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
    for (std::size_t i = 0; i < key.size(); ++i)
        out[8 + i] = key[i];
    for (std::size_t j = 0; j < 6; ++j)
        for (std::size_t i = 1; i <= n; ++i) {
            std::array<std::uint8_t, 16> b{};
            for (std::size_t k = 0; k < 8; ++k) {
                b[k] = a[k];
                b[8 + k] = out[8 * i + k];
            }
            b = aes.encrypt(b);
            const std::uint64_t t = static_cast<std::uint64_t>(n * j + i);
            for (std::size_t k = 0; k < 8; ++k) {
                a[k] = static_cast<std::uint8_t>(b[k] ^ static_cast<std::uint8_t>(t >> (56 - 8 * k)));
                out[8 * i + k] = b[8 + k];
            }
            secure_wipe(b);
        }
    for (std::size_t k = 0; k < 8; ++k)
        out[k] = a[k];
    return ok();
}

/// \brief Unwraps a key (RFC 3394 section 2.2.2), checking the integrity value in constant time. Constant time in
/// both keys.
/// \ingroup aead
/// \param kek The 32-byte key-encryption key.
/// \param wrapped The wrapped key: 24 to 520 bytes, a multiple of 8.
/// \param out Exactly 8 bytes shorter than wrapped; zeroed when the integrity check fails.
/// \return Success, `errc::authentication_failed` or `errc::invalid_length`.
[[nodiscard]] constexpr result<void, errc> aes256_key_unwrap(std::span<const std::uint8_t, 32> kek, std::span<const std::uint8_t> wrapped,
                                                             std::span<std::uint8_t> out) noexcept
{
    if (wrapped.size() % 8 != 0 || wrapped.size() < 24 || wrapped.size() > 8 * (key_wrap_max_blocks + 1) ||
        out.size() + 8 != wrapped.size())
        return err(errc::invalid_length);
    const std::size_t n = wrapped.size() / 8 - 1;
    const crypto::detail::aes256 aes(kek);
    std::array<std::uint8_t, 8> a{};
    for (std::size_t k = 0; k < 8; ++k)
        a[k] = wrapped[k];
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = wrapped[8 + i];
    for (std::size_t j = 6; j-- > 0;)
        for (std::size_t i = n; i >= 1; --i) {
            const std::uint64_t t = static_cast<std::uint64_t>(n * j + i);
            std::array<std::uint8_t, 16> b{};
            for (std::size_t k = 0; k < 8; ++k) {
                b[k] = static_cast<std::uint8_t>(a[k] ^ static_cast<std::uint8_t>(t >> (56 - 8 * k)));
                b[8 + k] = out[8 * (i - 1) + k];
            }
            b = aes.decrypt(b);
            for (std::size_t k = 0; k < 8; ++k) {
                a[k] = b[k];
                out[8 * (i - 1) + k] = b[8 + k];
            }
            secure_wipe(b);
        }
    std::uint64_t diff = 0;
    for (const auto v : a)
        diff |= static_cast<std::uint64_t>(v ^ 0xa6);
    if (ct::declassify(ct::mask_is_zero(diff)) == 0) {
        for (auto& v : out)
            v = 0;
        return err(errc::authentication_failed);
    }
    return ok();
}

} // namespace snicholls::crypto::aead

#endif /* snicholls_crypto_aead_aes_key_wrap_hpp */

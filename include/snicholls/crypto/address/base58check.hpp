//
//  base58check.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Base58check: base58 of a payload and the first four bytes of its double SHA-256.
/// \ingroup address
///
/// \overview
/// The text of Bitcoin's P2PKH and P2SH addresses (version byte 0x00 / 0x05 and a HASH160), Wallet Import Format keys
/// (0x80, the key, and 0x01 for a compressed public key), BIP-32 extended keys (`xprv` / `xpub`, 78-byte payloads),
/// TRON addresses (0x41) and, with XRPL's alphabet, XRP Ledger addresses. The checksum catches typing errors: decoding
/// verifies it and refuses the text on any mismatch.
///
/// - `base58check_encode<MaxBytes>(payload)` / `base58check_decode<MaxBytes>(text)`: any payload up to the cap.
/// - `base58check_encode_exact(std::array<std::uint8_t, N>)` / `base58check_decode_exact<N>(text)`: a payload of a
///   fixed size, such as the 78 bytes of an extended key; the decode refuses any other length.
/// - `base58check_checksum(payload)`: the four bytes alone.
///
/// \relations
/// - `address/base58.hpp`: the encoding underneath and its alphabets.
/// - `hd/extended_key.hpp`: `xprv` / `xpub` are base58check of 78 bytes.
/// - Group: \ref address.
///
/// \impls
/// One. SHA-256 is the library's interim implementation (`detail/hashes.hpp`), to become snicholls-core's when core
/// releases its hashes; nothing here changes then.
///
/// \contracts
/// - `constexpr`, `noexcept`, no allocation.
/// - **Not constant time** (see base58.hpp): addresses are public; for text that carries a secret (WIF, `xprv`) see
///   "Known issues".
/// - The checksum comparison itself is constant time (`ct::equal`), which costs nothing and leaves no oracle on how
///   many checksum bytes matched.
///
/// \errors
/// `errc::invalid_length` (over the cap; a decoded body shorter than the 4 checksum bytes; a wrong length for the
/// exact form), `errc::invalid_character`, `errc::invalid_checksum`.
///
/// \examples
/// \snippet address/base58check_demo.cpp base58check
///
/// \perf
/// `benchmarks/address/base58_benchmark.cpp`, macOS x86-64 (Xeon W-3245, 3.2 GHz), Apple Clang 17, Release,
/// 2026-11-20: an address encodes in 1.4 us and decodes in 1.2 us; a 78-byte extended key encodes in 7.4 us and
/// decodes in 5.0 us (base58's quadratic cost dominates; the double SHA-256 is about 0.9 us of each).
///
/// \testing
/// `tests/address/base58check_test.cpp` (the addresses and WIF of private key 1, the BIP-32 test vector 1 master key,
/// XRPL's special addresses, a corrupted checksum in every position), `demos/address/base58check_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstddef>`, `<cstdint>`, `<span>`, `<string_view>`; core's `result.hpp` and
/// `containers/inplace_vector.hpp`.
///
/// \gotchas
/// A WIF key or an `xprv` passes through this codec in variable time and lives briefly in its buffers, which are
/// wiped before return; the text the caller receives is the caller's to wipe. The same reasoning as base58's applies:
/// this text exists only at the boundary with a person.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_address_base58check_hpp
#define snicholls_crypto_address_base58check_hpp

#include <snicholls/core/containers/inplace_vector.hpp>
#include <snicholls/core/result.hpp>
#include <snicholls/crypto/address/base58.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace snicholls::crypto::address {

/// \brief The first four bytes of SHA-256(SHA-256(payload)).
/// \param payload The payload.
/// \return The checksum.
[[nodiscard]] constexpr std::array<std::uint8_t, 4> base58check_checksum(std::span<const std::uint8_t> payload) noexcept
{
    const auto once = crypto::detail::sha256::hash(payload);
    const auto twice = crypto::detail::sha256::hash(once);
    return {twice[0], twice[1], twice[2], twice[3]};
}

/// \brief The text of a payload of up to `MaxBytes` bytes.
/// \ingroup address
/// \tparam MaxBytes The payload cap.
template <std::size_t MaxBytes = base58_default_max_bytes>
using base58check_text = containers::inplace_vector<char, base58_encoded_capacity(MaxBytes + 4)>;

/// \brief Encodes a payload with its checksum.
/// \tparam MaxBytes The payload cap.
/// \param payload The payload (version byte included), at most `MaxBytes`.
/// \param alphabet The alphabet.
/// \return The text, or `errc::invalid_length` over the cap.
template <std::size_t MaxBytes = base58_default_max_bytes>
[[nodiscard]] constexpr result<base58check_text<MaxBytes>, errc>
base58check_encode(std::span<const std::uint8_t> payload, const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    if (payload.size() > MaxBytes)
        return err(errc::invalid_length);
    std::array<std::uint8_t, MaxBytes + 4> full{};
    for (std::size_t i = 0; i < payload.size(); ++i)
        full[i] = payload[i];
    const auto check = base58check_checksum(payload);
    for (std::size_t i = 0; i < 4; ++i)
        full[payload.size() + i] = check[i];
    std::array<char, base58_encoded_capacity(MaxBytes + 4)> buffer{};
    const auto n = base58_encode_to<MaxBytes + 4>(std::span<const std::uint8_t>(full).first(payload.size() + 4), buffer, alphabet);
    secure_wipe(full);
    if (!n) {
        secure_wipe(buffer);
        return err(n.unwrap_err());
    }
    base58check_text<MaxBytes> text;
    for (std::size_t i = 0; i < *n; ++i)
        (void)text.try_push_back(buffer[i]);
    secure_wipe(buffer);
    return ok(text);
}

/// \brief Encodes a fixed-size payload; cannot fail.
/// \tparam N The payload size (78 for an extended key, 21 for an address, 34 for a compressed WIF key).
/// \param payload The payload.
/// \param alphabet The alphabet.
/// \return The text.
template <std::size_t N>
[[nodiscard]] constexpr base58check_text<N> base58check_encode_exact(const std::array<std::uint8_t, N>& payload,
                                                                     const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    return base58check_encode<N>(payload, alphabet).unwrap_unchecked();
}

/// \brief Decodes and verifies; the payload without its checksum.
/// \tparam MaxBytes The payload cap.
/// \param text The text.
/// \param alphabet The alphabet.
/// \return The payload.
template <std::size_t MaxBytes = base58_default_max_bytes>
[[nodiscard]] constexpr result<containers::inplace_vector<std::uint8_t, MaxBytes>, errc>
base58check_decode(std::string_view text, const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    std::array<std::uint8_t, MaxBytes + 4> raw{};
    const auto n = base58_decode_to<MaxBytes + 4>(text, raw, alphabet);
    if (!n) {
        secure_wipe(raw);
        return err(n.unwrap_err());
    }
    if (*n < 4) {
        secure_wipe(raw);
        return err(errc::invalid_length);
    }
    const std::size_t body = *n - 4;
    const auto check = base58check_checksum(std::span<const std::uint8_t>(raw).first(body));
    if (!ct::equal(check, std::span<const std::uint8_t>(raw).subspan(body, 4))) {
        secure_wipe(raw);
        return err(errc::invalid_checksum);
    }
    containers::inplace_vector<std::uint8_t, MaxBytes> payload;
    for (std::size_t i = 0; i < body; ++i)
        (void)payload.try_push_back(raw[i]);
    secure_wipe(raw);
    return ok(payload);
}

/// \brief Decodes and verifies a payload of exactly `N` bytes.
/// \tparam N The payload size.
/// \param text The text.
/// \param alphabet The alphabet.
/// \return The payload, or `errc::invalid_length` for any other size.
template <std::size_t N>
[[nodiscard]] constexpr result<std::array<std::uint8_t, N>, errc> base58check_decode_exact(std::string_view text,
                                                                                          const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    auto decoded = base58check_decode<N>(text, alphabet);
    if (!decoded)
        return err(decoded.unwrap_err());
    if (decoded->size() != N) {
        secure_wipe(*decoded);
        return err(errc::invalid_length);
    }
    std::array<std::uint8_t, N> payload{};
    for (std::size_t i = 0; i < N; ++i)
        payload[i] = (*decoded)[i];
    secure_wipe(*decoded);
    return ok(payload);
}

} // namespace snicholls::crypto::address

#endif /* snicholls_crypto_address_base58check_hpp */

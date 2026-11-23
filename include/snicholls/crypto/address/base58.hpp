//
//  base58.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Base58 with any 58-symbol alphabet (Bitcoin, XRPL, Flickr): strict, allocation-free, `constexpr`.
/// \ingroup address
///
/// \overview
/// Base58 writes bytes as a big number in base 58, with each leading zero byte written as the alphabet's first
/// symbol. It is the text of Bitcoin's legacy addresses and keys (through `base58check.hpp`), XRPL's addresses (the
/// same scheme, another alphabet), Solana's public keys and IPFS's CIDv0 (raw, no checksum).
///
/// - `base58_encode<MaxBytes>(bytes, alphabet)` and `base58_decode<MaxBytes>(text, alphabet)` return core's
///   `containers::inplace_vector`; `base58_encode_to` / `base58_decode_to` write into a caller's span.
/// - The alphabet is a value: `bitcoin_base58`, `xrpl_base58`, `flickr_base58`, or `make_base58_alphabet(...)`.
///
/// Decoding is strict: any character outside the alphabet (whitespace, `0`, `O`, `I`, `l` in Bitcoin's) is
/// `errc::invalid_character`; nothing is trimmed or repaired. The empty text is the empty byte string (as in Bitcoin
/// Core's vectors).
///
/// Use base58check (`base58check.hpp`) for anything a person types: raw base58 has no checksum.
///
/// \relations
/// - `address/base58check.hpp`: base58 with a 4-byte double-SHA-256 checksum.
/// - `address/bech32.hpp`: the other address text.
/// - `snicholls::containers::inplace_vector` (core): the fixed-capacity results.
/// - Group: \ref address.
///
/// \impls
/// One: the schoolbook conversion between base 256 and base 58, O(n^2) in the length, done in the output buffer.
///
/// \contracts
/// - Every function is `constexpr` and `noexcept`; nothing allocates; the alphabets are built by the compiler.
/// - **Not constant time**: the work depends on the number of leading zeros and on each digit. Addresses and public
///   keys are public data. See "Known issues" for text that carries a secret.
/// - Inputs are capped at `MaxBytes` bytes (default `base58_default_max_bytes`, 128) or the matching text length
///   (`base58_encoded_capacity(MaxBytes)`), because the cost grows with the square of the length: 128 bytes is
///   ample for every address, key and extended key, and bounds a hostile input to microseconds.
///
/// \errors
/// `errc::invalid_length` (input over the cap, or output span too small), `errc::invalid_character` (decode only).
///
/// \examples
/// \snippet address/base58_demo.cpp base58
///
/// \perf
/// `benchmarks/address/base58_benchmark.cpp`, macOS x86-64 (Xeon W-3245, 3.2 GHz), Apple Clang 17, Release,
/// 2026-11-20: a 25-byte address encodes in 0.54 us and decodes in 0.29 us. The cost is quadratic in the length.
///
/// \testing
/// `tests/address/base58_test.cpp` (Bitcoin Core's `base58_encode_decode.json`, XRPL's special addresses, every
/// boundary of the caps, every rejected character), `demos/address/base58_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstddef>`, `<cstdint>`, `<span>`, `<string_view>`; core's `result.hpp` and
/// `containers/inplace_vector.hpp`.
///
/// \gotchas
/// Wallet Import Format keys and `xprv` text are base58 of a secret. This codec is not constant time, so the time to
/// encode or decode them depends on their digits. That is the accepted practice (every wallet does the same) because
/// the text exists only to be shown to, or typed by, a person: an attacker who can time it closely can usually read
/// the screen. Keep secrets in binary form (`secret_bytes`) and convert to text only at that boundary.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_address_base58_hpp
#define snicholls_crypto_address_base58_hpp

#include <snicholls/core/containers/inplace_vector.hpp>
#include <snicholls/core/result.hpp>
#include <snicholls/crypto/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

/// \brief Address and key text: base58, base58check, bech32 and segwit addresses.
namespace snicholls::crypto::address {

/// \brief A base58 alphabet: 58 distinct printable ASCII symbols, and the value of each character (-1 for none).
/// \ingroup address
struct base58_alphabet {
    std::array<char, 58> symbols{};       ///< The symbol of each digit, 0 first.
    std::array<std::int8_t, 128> values{}; ///< The digit of each ASCII character, -1 for a character not in the alphabet.
    bool valid = false;                   ///< Whether the symbols were 58 distinct printable ASCII characters.
};

/// \brief Builds an alphabet from its 58 symbols, digit 0 first.
/// \param symbols The symbols.
/// \return The alphabet; `valid` is false unless there are exactly 58 distinct printable ASCII symbols.
[[nodiscard]] constexpr base58_alphabet make_base58_alphabet(std::string_view symbols) noexcept
{
    base58_alphabet a;
    for (auto& v : a.values)
        v = -1;
    if (symbols.size() != 58)
        return a;
    for (std::size_t i = 0; i < 58; ++i) {
        const auto c = static_cast<unsigned char>(symbols[i]);
        if (c < 33 || c > 126 || a.values[c] != -1)
            return a;
        a.symbols[i] = symbols[i];
        a.values[c] = static_cast<std::int8_t>(i);
    }
    a.valid = true;
    return a;
}

/// \brief Bitcoin's alphabet (no `0`, `O`, `I`, `l`); also Solana's, IPFS's and TRON's.
inline constexpr base58_alphabet bitcoin_base58 = make_base58_alphabet("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
/// \brief The XRP Ledger's alphabet: its first symbol is `r`, so a leading zero byte is an `r`.
inline constexpr base58_alphabet xrpl_base58 = make_base58_alphabet("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz");
/// \brief Flickr's alphabet (Bitcoin's with the cases swapped).
inline constexpr base58_alphabet flickr_base58 = make_base58_alphabet("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ");
static_assert(bitcoin_base58.valid && xrpl_base58.valid && flickr_base58.valid);

/// \brief The default cap on the bytes encoded or decoded in one call.
inline constexpr std::size_t base58_default_max_bytes = 128;

/// \brief The longest text `n` bytes can encode to: ceil(n log 256 / log 58), bounded above by n * 138 / 100 + 1.
/// \param n A number of bytes.
/// \return The text capacity needed.
[[nodiscard]] constexpr std::size_t base58_encoded_capacity(std::size_t n) noexcept { return n * 138 / 100 + 1; }

/// \brief Encodes into a caller's buffer.
/// \tparam MaxBytes The input cap.
/// \param bytes The bytes, at most `MaxBytes`.
/// \param out Where the text goes; `base58_encoded_capacity(bytes.size())` always suffices.
/// \param alphabet The alphabet.
/// \return The number of characters written.
template <std::size_t MaxBytes = base58_default_max_bytes>
[[nodiscard]] constexpr result<std::size_t, errc> base58_encode_to(std::span<const std::uint8_t> bytes, std::span<char> out,
                                                                   const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    if (bytes.size() > MaxBytes)
        return err(errc::invalid_length);
    std::size_t zeros = 0;
    while (zeros < bytes.size() && bytes[zeros] == 0) {   // one leading symbol per leading zero byte
        if (zeros < out.size())
            out[zeros] = alphabet.symbols[0];
        ++zeros;
    }
    if (zeros > out.size())
        return err(errc::invalid_length);
    // Base-58 digits of the rest, least significant first, built in out[zeros...]
    const std::span<char> digits = out.subspan(zeros);
    std::size_t length = 0;
    for (std::size_t i = zeros; i < bytes.size(); ++i) {
        unsigned carry = bytes[i];
        for (std::size_t j = 0; j < length; ++j) {
            carry += static_cast<unsigned>(static_cast<unsigned char>(digits[j])) << 8;
            digits[j] = static_cast<char>(carry % 58);
            carry /= 58;
        }
        while (carry != 0) {
            if (length == digits.size())
                return err(errc::invalid_length);
            digits[length++] = static_cast<char>(carry % 58);
            carry /= 58;
        }
    }
    // Most significant first, each digit mapped to its symbol, in one two-ended pass (one loop, which GCC 13's
    // vectoriser does not turn into stores it cannot bound)
    std::size_t lo = 0, hi = length;
    while (lo + 1 < hi) {
        --hi;
        const auto a = static_cast<unsigned char>(digits[lo]), b = static_cast<unsigned char>(digits[hi]);
        digits[lo] = alphabet.symbols[b];
        digits[hi] = alphabet.symbols[a];
        ++lo;
    }
    if (lo + 1 == hi)
        digits[lo] = alphabet.symbols[static_cast<unsigned char>(digits[lo])];
    return ok(zeros + length);
}

/// \brief Decodes into a caller's buffer.
/// \tparam MaxBytes The cap: text longer than `base58_encoded_capacity(MaxBytes)` is refused.
/// \param text The text; every character must be in the alphabet.
/// \param out Where the bytes go.
/// \param alphabet The alphabet.
/// \return The number of bytes written.
template <std::size_t MaxBytes = base58_default_max_bytes>
[[nodiscard]] constexpr result<std::size_t, errc> base58_decode_to(std::string_view text, std::span<std::uint8_t> out,
                                                                   const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    if (text.size() > base58_encoded_capacity(MaxBytes))
        return err(errc::invalid_length);
    std::size_t zeros = 0;
    while (zeros < text.size() && text[zeros] == alphabet.symbols[0])
        ++zeros;
    if (zeros > out.size())
        return err(errc::invalid_length);
    const std::span<std::uint8_t> bytes = out.subspan(zeros);
    std::size_t length = 0;   // bytes of the rest, least significant first
    for (std::size_t i = zeros; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        const int digit = c < 128 ? alphabet.values[c] : -1;
        if (digit < 0)
            return err(errc::invalid_character);
        unsigned carry = static_cast<unsigned>(digit);
        for (std::size_t j = 0; j < length; ++j) {
            carry += bytes[j] * 58u;
            bytes[j] = static_cast<std::uint8_t>(carry & 0xff);
            carry >>= 8;
        }
        while (carry != 0) {
            if (length == bytes.size())
                return err(errc::invalid_length);
            bytes[length++] = static_cast<std::uint8_t>(carry & 0xff);
            carry >>= 8;
        }
    }
    // Most significant first. length never exceeds bytes.size() (the loop above refuses to grow past it), but GCC
    // cannot carry that through the loop, and bounded by length alone this reversal is vectorised by GCC 13 on aarch64
    // into stores past a one-byte buffer that it then reports (-Wstringop-overflow). Bounded by both, it is not.
    const std::size_t n = length < bytes.size() ? length : bytes.size();
    for (std::size_t i = 0; i < n / 2; ++i) {
        const std::uint8_t t = bytes[i];
        bytes[i] = bytes[n - 1 - i];
        bytes[n - 1 - i] = t;
    }
    for (std::size_t i = 0; i < zeros; ++i)
        out[i] = 0;
    if (zeros + length > MaxBytes)
        return err(errc::invalid_length);
    return ok(zeros + length);
}

/// \brief The text of up to `MaxBytes` bytes.
/// \ingroup address
/// \tparam MaxBytes The input cap.
template <std::size_t MaxBytes = base58_default_max_bytes>
using base58_text = containers::inplace_vector<char, base58_encoded_capacity(MaxBytes)>;

/// \brief Encodes into a fixed-capacity string.
/// \tparam MaxBytes The input cap.
/// \param bytes The bytes, at most `MaxBytes`.
/// \param alphabet The alphabet.
/// \return The text, or `errc::invalid_length` over the cap.
template <std::size_t MaxBytes = base58_default_max_bytes>
[[nodiscard]] constexpr result<base58_text<MaxBytes>, errc> base58_encode(std::span<const std::uint8_t> bytes,
                                                                          const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    std::array<char, base58_encoded_capacity(MaxBytes)> buffer{};
    const auto n = base58_encode_to<MaxBytes>(bytes, buffer, alphabet);
    if (!n)
        return err(n.unwrap_err());
    base58_text<MaxBytes> text;
    for (std::size_t i = 0; i < *n; ++i)
        (void)text.try_push_back(buffer[i]);
    return ok(text);
}

/// \brief Decodes into a fixed-capacity byte string.
/// \tparam MaxBytes The output cap.
/// \param text The text.
/// \param alphabet The alphabet.
/// \return The bytes, or `errc::invalid_length` / `errc::invalid_character`.
template <std::size_t MaxBytes = base58_default_max_bytes>
[[nodiscard]] constexpr result<containers::inplace_vector<std::uint8_t, MaxBytes>, errc>
base58_decode(std::string_view text, const base58_alphabet& alphabet = bitcoin_base58) noexcept
{
    std::array<std::uint8_t, MaxBytes> buffer{};
    const auto n = base58_decode_to<MaxBytes>(text, buffer, alphabet);
    if (!n)
        return err(n.unwrap_err());
    containers::inplace_vector<std::uint8_t, MaxBytes> bytes;
    for (std::size_t i = 0; i < *n; ++i)
        (void)bytes.try_push_back(buffer[i]);
    return ok(bytes);
}

} // namespace snicholls::crypto::address

#endif /* snicholls_crypto_address_base58_hpp */

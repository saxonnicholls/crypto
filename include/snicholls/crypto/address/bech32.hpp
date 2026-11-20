//
//  bech32.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief Bech32 (BIP-173), bech32m (BIP-350), 8-to-5-bit regrouping, and segwit addresses.
/// \ingroup address
///
/// \overview
/// Bech32 is a human-readable part (the HRP: `bc`, `tb`, `cosmos`, ...), the separator `1`, data in a 32-symbol
/// alphabet, and a six-symbol BCH checksum that detects any four substitutions. Bech32m (BIP-350) changes only the
/// constant the checksum is xored with, closing bech32's insertion weakness. Segwit addresses carry a witness version
/// (0 to 16) and a program of 2 to 40 bytes: version 0 uses bech32 and a 20- or 32-byte program, versions 1 and up
/// (taproot is 1) use bech32m.
///
/// - `bech32_encode<MaxLength>(hrp, values, variant)` / `bech32_decode<MaxLength>(text)`: 5-bit values, any HRP.
/// - `convert_bits<From, To, Pad, N>(in)`: regrouping, with BIP-173's padding rules when `Pad` is false.
/// - `segwit_encode(hrp, version, program)` / `segwit_decode(hrp, address)`: addresses, every BIP-173 and BIP-350
///   rule; `witness_program::script_pubkey()` gives the output script.
///
/// Decoding is strict, as both BIPs require: printable ASCII only (33 to 126), no mixed case (either all lower or all
/// upper; the result is lower case), the last `1` is the separator, an HRP of 1 to 83 characters, at least six data
/// symbols, and at most 90 characters in all unless `MaxLength` is raised (Lightning invoices exceed 90).
///
/// \relations
/// - `address/base58check.hpp`: the legacy address text.
/// - `snicholls::containers::inplace_vector` (core): the fixed-capacity results.
/// - Group: \ref address.
///
/// \impls
/// One: the BIPs' reference algorithm, written for fixed buffers.
///
/// \contracts
/// - Every function is `constexpr` and `noexcept`; nothing allocates.
/// - **Not constant time**: addresses are public data.
/// - Encoding writes lower case; decoding accepts all-upper (QR codes) and returns lower case.
///
/// \errors
/// `errc::invalid_length` (over `MaxLength`, fewer than six checksum symbols, a value list too long),
/// `errc::invalid_character` (outside 33 to 126, or a data symbol outside the alphabet, or a value of 32 or more),
/// `errc::non_canonical` (mixed case; padding of five bits or more, or non-zero padding, when regrouping),
/// `errc::invalid_hrp` (no separator, an empty or too long HRP, or not the HRP expected), `errc::invalid_checksum`
/// (wrong checksum, or the wrong variant for the witness version), `errc::invalid_witness_version`,
/// `errc::invalid_witness_program`.
///
/// \examples
/// \snippet address/bech32_demo.cpp bech32
///
/// \perf
/// `benchmarks/address/bech32_benchmark.cpp`, macOS x86-64 (Xeon W-3245, 3.2 GHz), Apple Clang 17, Release,
/// 2026-11-20: a P2WPKH address encodes in 0.22 us and decodes in 0.33 us; a taproot address in 0.31 us and 0.48 us.
///
/// \testing
/// `tests/address/bech32_test.cpp`: every valid and invalid string and address of BIP-173 and BIP-350,
/// `demos/address/bech32_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstddef>`, `<cstdint>`, `<span>`, `<string_view>`; core's `result.hpp` and
/// `containers/inplace_vector.hpp`.
///
/// \gotchas
/// BIP-173's own invalid list includes a checksum computed over the upper-case HRP (`A1G7SGD8`): the checksum is
/// always over the lower-case form, and this library follows the BIP.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_address_bech32_hpp
#define snicholls_crypto_address_bech32_hpp

#include <snicholls/core/containers/inplace_vector.hpp>
#include <snicholls/core/result.hpp>
#include <snicholls/crypto/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace snicholls::crypto::address {

/// \brief Which checksum: BIP-173's bech32 or BIP-350's bech32m.
/// \ingroup address
enum class bech32_variant : std::uint8_t {
    bech32,    ///< BIP-173: the checksum constant 1. Segwit version 0.
    bech32m,   ///< BIP-350: the checksum constant 0x2bc830a3. Segwit versions 1 to 16.
};

/// \brief The longest bech32 string BIP-173 allows.
inline constexpr std::size_t bech32_max_length = 90;

/// \brief The 32 data symbols, value 0 first.
inline constexpr std::string_view bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

namespace detail {

constexpr std::uint32_t bech32_constant(bech32_variant v) noexcept { return v == bech32_variant::bech32 ? 1u : 0x2bc830a3u; }

constexpr std::uint32_t polymod_step(std::uint32_t chk, std::uint8_t value) noexcept
{
    constexpr std::uint32_t generator[5] = {0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
    const std::uint32_t top = chk >> 25;
    chk = ((chk & 0x1ffffffu) << 5) ^ value;
    for (int i = 0; i < 5; ++i)
        chk ^= ((top >> i) & 1) ? generator[i] : 0;
    return chk;
}

// The checksum state after the expanded HRP: high bits of each character, a zero, low bits of each character
constexpr std::uint32_t polymod_hrp(std::string_view hrp) noexcept
{
    std::uint32_t chk = 1;
    for (const char c : hrp)
        chk = polymod_step(chk, static_cast<std::uint8_t>(static_cast<unsigned char>(c) >> 5));
    chk = polymod_step(chk, 0);
    for (const char c : hrp)
        chk = polymod_step(chk, static_cast<std::uint8_t>(static_cast<unsigned char>(c) & 31));
    return chk;
}

constexpr int charset_value(char c) noexcept
{
    for (std::size_t i = 0; i < bech32_charset.size(); ++i)
        if (bech32_charset[i] == c)
            return static_cast<int>(i);
    return -1;
}

constexpr char to_lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

} // namespace detail

/// \brief The BCH checksum polynomial of BIP-173 over an HRP and values, as the BIPs define it.
/// \param hrp The lower-case HRP.
/// \param values The 5-bit values, checksum included when verifying.
/// \return The polymod: the variant's constant for a valid string.
[[nodiscard]] constexpr std::uint32_t bech32_polymod(std::string_view hrp, std::span<const std::uint8_t> values) noexcept
{
    std::uint32_t chk = detail::polymod_hrp(hrp);
    for (const std::uint8_t v : values)
        chk = detail::polymod_step(chk, v);
    return chk;
}

/// \brief Bech32 text of at most `MaxLength` characters.
/// \ingroup address
/// \tparam MaxLength The cap.
template <std::size_t MaxLength = bech32_max_length>
using bech32_text = containers::inplace_vector<char, MaxLength>;

/// \brief A decoded bech32 string.
/// \ingroup address
/// \tparam MaxLength The cap it was decoded under.
template <std::size_t MaxLength = bech32_max_length>
struct bech32_decoded {
    containers::inplace_vector<char, MaxLength> hrp;            ///< The HRP, lower case.
    containers::inplace_vector<std::uint8_t, MaxLength> values; ///< The 5-bit data values, without the checksum.
    bech32_variant variant = bech32_variant::bech32;            ///< Which checksum matched.
};

/// \brief Encodes an HRP and 5-bit values.
/// \tparam MaxLength The cap on the text (90 by BIP-173).
/// \param hrp 1 to 83 characters, each 33 to 126; upper case is written as lower case.
/// \param values Values below 32.
/// \param variant The checksum.
/// \return The lower-case text.
template <std::size_t MaxLength = bech32_max_length>
[[nodiscard]] constexpr result<bech32_text<MaxLength>, errc> bech32_encode(std::string_view hrp, std::span<const std::uint8_t> values,
                                                                           bech32_variant variant) noexcept
{
    if (hrp.empty() || hrp.size() > 83)
        return err(errc::invalid_hrp);
    if (hrp.size() + 1 + values.size() + 6 > MaxLength)
        return err(errc::invalid_length);
    std::array<char, 83> lower{};
    for (std::size_t i = 0; i < hrp.size(); ++i) {
        const auto c = static_cast<unsigned char>(hrp[i]);
        if (c < 33 || c > 126)
            return err(errc::invalid_hrp);
        lower[i] = detail::to_lower(hrp[i]);
    }
    const std::string_view h(lower.data(), hrp.size());
    std::uint32_t chk = detail::polymod_hrp(h);
    bech32_text<MaxLength> text;
    for (const char c : h)
        (void)text.try_push_back(c);
    (void)text.try_push_back('1');
    for (const std::uint8_t v : values) {
        if (v >= 32)
            return err(errc::invalid_character);
        chk = detail::polymod_step(chk, v);
        (void)text.try_push_back(bech32_charset[v]);
    }
    for (int i = 0; i < 6; ++i)
        chk = detail::polymod_step(chk, 0);
    chk ^= detail::bech32_constant(variant);
    for (int i = 0; i < 6; ++i)
        (void)text.try_push_back(bech32_charset[(chk >> (5 * (5 - i))) & 31]);
    return ok(text);
}

/// \brief Decodes and verifies a bech32 or bech32m string.
/// \tparam MaxLength The cap on the text (90 by BIP-173).
/// \param text The text: all lower or all upper case.
/// \return The HRP, the values and the variant.
template <std::size_t MaxLength = bech32_max_length>
[[nodiscard]] constexpr result<bech32_decoded<MaxLength>, errc> bech32_decode(std::string_view text) noexcept
{
    if (text.size() > MaxLength)
        return err(errc::invalid_length);
    bool lower = false, upper = false;
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 33 || c > 126)
            return err(errc::invalid_character);
        lower = lower || (c >= 'a' && c <= 'z');
        upper = upper || (c >= 'A' && c <= 'Z');
    }
    if (lower && upper)
        return err(errc::non_canonical);
    const std::size_t sep = text.rfind('1');
    if (sep == std::string_view::npos || sep == 0 || sep > 83)
        return err(errc::invalid_hrp);
    if (text.size() - sep - 1 < 6)
        return err(errc::invalid_length);
    bech32_decoded<MaxLength> out;
    for (std::size_t i = 0; i < sep; ++i)
        (void)out.hrp.try_push_back(detail::to_lower(text[i]));
    std::uint32_t chk = detail::polymod_hrp(std::string_view(out.hrp.data(), out.hrp.size()));
    const std::size_t data_end = text.size() - 6;
    for (std::size_t i = sep + 1; i < text.size(); ++i) {
        const int v = detail::charset_value(detail::to_lower(text[i]));
        if (v < 0)
            return err(errc::invalid_character);
        chk = detail::polymod_step(chk, static_cast<std::uint8_t>(v));
        if (i < data_end)
            (void)out.values.try_push_back(static_cast<std::uint8_t>(v));
    }
    if (chk == detail::bech32_constant(bech32_variant::bech32))
        out.variant = bech32_variant::bech32;
    else if (chk == detail::bech32_constant(bech32_variant::bech32m))
        out.variant = bech32_variant::bech32m;
    else
        return err(errc::invalid_checksum);
    return ok(out);
}

/// \brief Regroups bits: `From`-bit values to `To`-bit values, most significant first.
/// \tparam From The input width (1 to 8).
/// \tparam To The output width (1 to 8).
/// \tparam Pad Whether to pad the last group with zeros (encoding). Without it (decoding), fewer than `From` leftover
/// bits are allowed only if they are zero, as BIP-173 requires.
/// \tparam N The output capacity.
/// \param in The values, each below 2^From.
/// \return The regrouped values.
template <unsigned From, unsigned To, bool Pad, std::size_t N>
    requires(From >= 1 && From <= 8 && To >= 1 && To <= 8)
[[nodiscard]] constexpr result<containers::inplace_vector<std::uint8_t, N>, errc> convert_bits(std::span<const std::uint8_t> in) noexcept
{
    constexpr std::uint32_t max_value = (1u << To) - 1;
    std::uint32_t acc = 0;
    unsigned bits = 0;
    containers::inplace_vector<std::uint8_t, N> out;
    for (const std::uint8_t v : in) {
        if ((v >> From) != 0)
            return err(errc::invalid_character);
        acc = ((acc << From) | v) & 0xffffffu;
        bits += From;
        while (bits >= To) {
            bits -= To;
            if (!out.try_push_back(static_cast<std::uint8_t>((acc >> bits) & max_value)))
                return err(errc::invalid_length);
        }
    }
    if constexpr (Pad) {
        if (bits > 0 && !out.try_push_back(static_cast<std::uint8_t>((acc << (To - bits)) & max_value)))
            return err(errc::invalid_length);
    } else {
        if (bits >= From || ((acc << (To - bits)) & max_value) != 0)
            return err(errc::non_canonical);
    }
    return ok(out);
}

/// \brief A segwit witness version and program.
/// \ingroup address
struct witness_program {
    std::uint8_t version = 0;                                ///< 0 to 16.
    containers::inplace_vector<std::uint8_t, 40> program;    ///< 2 to 40 bytes; 20 or 32 for version 0.

    /// \brief The output script: OP_0 or OP_1..OP_16, then a push of the program.
    /// \return The scriptPubKey bytes.
    [[nodiscard]] constexpr containers::inplace_vector<std::uint8_t, 42> script_pubkey() const noexcept
    {
        containers::inplace_vector<std::uint8_t, 42> s;
        (void)s.try_push_back(static_cast<std::uint8_t>(version == 0 ? 0x00 : 0x50 + version));
        (void)s.try_push_back(static_cast<std::uint8_t>(program.size()));
        for (const std::uint8_t b : program)
            (void)s.try_push_back(b);
        return s;
    }
};

/// \brief Encodes a segwit address.
/// \param hrp The network's HRP (`bc`, `tb`, `bcrt`).
/// \param version The witness version, 0 to 16.
/// \param program The witness program: 2 to 40 bytes, 20 or 32 for version 0.
/// \return The address, bech32 for version 0 and bech32m otherwise.
[[nodiscard]] constexpr result<bech32_text<>, errc> segwit_encode(std::string_view hrp, std::uint8_t version,
                                                                   std::span<const std::uint8_t> program) noexcept
{
    if (version > 16)
        return err(errc::invalid_witness_version);
    if (program.size() < 2 || program.size() > 40 || (version == 0 && program.size() != 20 && program.size() != 32))
        return err(errc::invalid_witness_program);
    auto five = convert_bits<8, 5, true, 64>(program);
    if (!five)
        return err(five.unwrap_err());
    std::array<std::uint8_t, 65> values{};
    values[0] = version;
    for (std::size_t i = 0; i < five->size(); ++i)
        values[i + 1] = (*five)[i];
    return bech32_encode(hrp, std::span<const std::uint8_t>(values).first(five->size() + 1),
                         version == 0 ? bech32_variant::bech32 : bech32_variant::bech32m);
}

/// \brief Decodes and checks a segwit address for the expected network.
/// \param hrp The HRP expected (compared without regard to case).
/// \param address The address.
/// \return The version and program.
[[nodiscard]] constexpr result<witness_program, errc> segwit_decode(std::string_view hrp, std::string_view address) noexcept
{
    auto d = bech32_decode(address);
    if (!d)
        return err(d.unwrap_err());
    if (d->hrp.size() != hrp.size())
        return err(errc::invalid_hrp);
    for (std::size_t i = 0; i < hrp.size(); ++i)
        if (d->hrp[i] != detail::to_lower(hrp[i]))
            return err(errc::invalid_hrp);
    if (d->values.size() == 0)
        return err(errc::invalid_witness_program);
    const std::uint8_t version = d->values[0];
    if (version > 16)
        return err(errc::invalid_witness_version);
    if ((version == 0) != (d->variant == bech32_variant::bech32))
        return err(errc::invalid_checksum);
    auto program = convert_bits<5, 8, false, 64>(std::span<const std::uint8_t>(d->values.data(), d->values.size()).subspan(1));
    if (!program)
        return err(program.unwrap_err());
    if (program->size() < 2 || program->size() > 40 || (version == 0 && program->size() != 20 && program->size() != 32))
        return err(errc::invalid_witness_program);
    witness_program w;
    w.version = version;
    for (const std::uint8_t b : *program)
        (void)w.program.try_push_back(b);
    return ok(w);
}

} // namespace snicholls::crypto::address

#endif /* snicholls_crypto_address_bech32_hpp */

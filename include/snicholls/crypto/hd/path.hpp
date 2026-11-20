//
//  path.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `hd::derivation_path`: BIP-32 paths ("m/44'/60'/0'/0/0"), strict parsing, formatting, and the BIP-44 family.
/// \ingroup wallet
///
/// \overview
/// A derivation path is the list of child indices from a master key to a key; an index at or above 2^31 is
/// hardened, written with a mark (`'`, or `h` / `H`). This header holds a path in a fixed-capacity value, parses
/// and formats its text, and builds the standard wallet paths:
///
/// | Purpose | Standard | Use |
/// |---|---|---|
/// | 44' | BIP-44 | the general multi-coin layout (Ethereum m/44'/60'/0'/0/i, TRON 195', Solana 501') |
/// | 49' | BIP-49 | Bitcoin P2WPKH nested in P2SH |
/// | 84' | BIP-84 | Bitcoin native SegWit P2WPKH |
/// | 86' | BIP-86 | Bitcoin Taproot single key |
///
/// all as m / purpose' / coin_type' / account' / change / address_index (`wallet_path`).
///
/// **Strict grammar.** "m", or "m" followed by components "/" index [mark], where the index is decimal with no sign,
/// no leading zero (except "0" itself) and below 2^31, and the mark is `'`, `h` or `H`. Anything else (an empty
/// component, a trailing slash, whitespace, "M", a hardened bit written as a number) is `errc::invalid_path`. A path
/// is never silently changed: in particular nothing here hardens an index that was not marked.
///
/// \relations
/// - `hd/bip32.hpp`, `hd/slip10.hpp`: derivation along a path. SLIP-10 for Ed25519 needs `all_hardened()`.
/// - Group: \ref wallet.
///
/// \impls
/// One.
///
/// \contracts
/// - Paths are public data: this header is variable time and makes no constant-time claim.
/// - Value type, trivially copyable, no allocation; every function `constexpr` and `noexcept`.
/// - Capacity `max_depth` = 32 components. BIP-32 records depth in one byte (255), but no standard path is deeper
///   than six, and a fixed capacity keeps the type small (132 bytes); a deeper path is `errc::invalid_path`.
///
/// \errors
/// `errc::invalid_path` for text that does not parse, an index at or above 2^31 given to a builder, a BIP-44 change
/// other than 0 or 1, or a path deeper than `max_depth`.
///
/// \examples
/// \snippet hd/path_demo.cpp path
///
/// \perf
/// Not benchmarked: parsing a path is a few dozen character tests, nothing beside a derivation.
///
/// \testing
/// `tests/hd/path_test.cpp` (the grammar's every edge, at compile time and at run time), `demos/hd/path_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstddef>`, `<cstdint>`, `<span>`, `<string_view>`; core's `result.hpp`.
///
/// \gotchas
/// `h` and `H` are accepted on input; `format` always writes `'`.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_hd_path_hpp
#define snicholls_crypto_hd_path_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

/// \brief Hierarchical deterministic keys: paths, BIP-32 and SLIP-10.
namespace snicholls::crypto::hd {

/// \brief The bit that marks a hardened index.
inline constexpr std::uint32_t hardened_bit = 0x80000000u;

/// \brief The hardened form of an index.
/// \pre `i < 2^31`.
/// \param i The index.
/// \return `i | 2^31`.
[[nodiscard]] constexpr std::uint32_t hardened(std::uint32_t i) noexcept { return i | hardened_bit; }

/// \brief Whether an index is hardened.
/// \param i The index.
/// \return `true` at or above 2^31.
[[nodiscard]] constexpr bool is_hardened(std::uint32_t i) noexcept { return (i & hardened_bit) != 0; }

/// \brief Standard purposes (the first component, BIP-43).
namespace purpose {
inline constexpr std::uint32_t bip44 = 44;   ///< BIP-44: multi-coin accounts.
inline constexpr std::uint32_t bip49 = 49;   ///< BIP-49: P2WPKH nested in P2SH.
inline constexpr std::uint32_t bip84 = 84;   ///< BIP-84: native SegWit P2WPKH.
inline constexpr std::uint32_t bip86 = 86;   ///< BIP-86: Taproot single key.
} // namespace purpose

/// \brief Registered coin types (SLIP-44), the second component.
namespace coin_type {
inline constexpr std::uint32_t bitcoin = 0;     ///< Bitcoin.
inline constexpr std::uint32_t testnet = 1;     ///< Every coin's testnets.
inline constexpr std::uint32_t ethereum = 60;   ///< Ethereum and EVM chains.
inline constexpr std::uint32_t tron = 195;      ///< TRON.
inline constexpr std::uint32_t solana = 501;    ///< Solana (SLIP-10 Ed25519, hardened throughout).
} // namespace coin_type

/// \brief A BIP-32 derivation path: up to `max_depth` child indices from the master key.
/// \ingroup wallet
///
/// \overview
/// See the file description. Index i of the path is the i-th child taken from the master; the empty path is "m".
class derivation_path {
public:
    /// \brief The most components a path holds.
    static constexpr std::size_t max_depth = 32;
    /// \brief The longest text `format` writes: "m" and, per component, "/" plus ten digits plus a mark.
    static constexpr std::size_t max_text_length = 1 + max_depth * 12;

    /// \brief The empty path, "m".
    constexpr derivation_path() noexcept = default;

    /// \brief Parses strict path text (see the file description).
    /// \param text The text.
    /// \return The path, or `errc::invalid_path`.
    [[nodiscard]] static constexpr result<derivation_path, errc> parse(std::string_view text) noexcept
    {
        derivation_path p;
        if (text.empty() || text[0] != 'm')
            return err(errc::invalid_path);
        std::size_t i = 1;
        while (i < text.size()) {
            if (text[i] != '/' || ++i == text.size())
                return err(errc::invalid_path);
            const std::size_t start = i;
            std::uint64_t v = 0;
            while (i < text.size() && text[i] >= '0' && text[i] <= '9' && i - start < 10)
                v = v * 10 + static_cast<std::uint64_t>(text[i++] - '0');
            const std::size_t digits = i - start;
            if (digits == 0 || (digits > 1 && text[start] == '0') || v >= hardened_bit ||
                (i < text.size() && text[i] >= '0' && text[i] <= '9'))
                return err(errc::invalid_path);
            auto index = static_cast<std::uint32_t>(v);
            if (i < text.size() && (text[i] == '\'' || text[i] == 'h' || text[i] == 'H')) {
                index = hardened(index);
                ++i;
            }
            if (!p.push_back(index))
                return err(errc::invalid_path);
        }
        return ok(p);
    }

    /// \brief Appends a component.
    /// \param index The index, with the hardened bit if hardened.
    /// \return `false` (and no change) if the path is already `max_depth` deep.
    constexpr bool push_back(std::uint32_t index) noexcept
    {
        if (size_ == max_depth)
            return false;
        indices_[size_++] = index;
        return true;
    }

    /// \brief The number of components (the depth of the key it leads to).
    /// \return 0 to `max_depth`.
    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    /// \brief Whether this is "m".
    /// \return `true` for the empty path.
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }
    /// \brief Component `i`.
    /// \pre `i < size()`.
    /// \param i The position.
    /// \return The index, with the hardened bit if hardened.
    [[nodiscard]] constexpr std::uint32_t operator[](std::size_t i) const noexcept { return indices_[i]; }
    /// \brief The components.
    /// \return A view valid while this path lives.
    [[nodiscard]] constexpr std::span<const std::uint32_t> indices() const noexcept { return {indices_.data(), size_}; }
    /// \brief Whether every component is hardened (what SLIP-10 Ed25519 requires; true for "m").
    /// \return `true` if no component is non-hardened.
    [[nodiscard]] constexpr bool all_hardened() const noexcept
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (!is_hardened(indices_[i]))
                return false;
        return true;
    }

    /// \brief Writes the path as text, hardened components marked with `'`.
    /// \param out The buffer; `max_text_length` characters always suffice.
    /// \return The number of characters written (no NUL).
    constexpr std::size_t format(std::span<char, max_text_length> out) const noexcept
    {
        std::size_t n = 0;
        out[n++] = 'm';
        for (std::size_t i = 0; i < size_; ++i) {
            out[n++] = '/';
            std::uint32_t v = indices_[i] & ~hardened_bit;
            char digits[10]{};
            std::size_t d = 0;
            do {
                digits[d++] = static_cast<char>('0' + v % 10);
                v /= 10;
            } while (v != 0);
            while (d > 0)
                out[n++] = digits[--d];
            if (is_hardened(indices_[i]))
                out[n++] = '\'';
        }
        return n;
    }

    /// \brief Equality of components.
    /// \param a A path.
    /// \param b Another.
    /// \return Whether they are the same path.
    [[nodiscard]] friend constexpr bool operator==(const derivation_path& a, const derivation_path& b) noexcept
    {
        if (a.size_ != b.size_)
            return false;
        for (std::size_t i = 0; i < a.size_; ++i)
            if (a.indices_[i] != b.indices_[i])
                return false;
        return true;
    }

private:
    std::array<std::uint32_t, max_depth> indices_{};
    std::size_t size_ = 0;
};

/// \brief The standard wallet path m / purpose' / coin_type' / account' / change / address_index.
/// \param purpose_number `purpose::bip44`, `bip49`, `bip84` or `bip86` (any value below 2^31 is accepted).
/// \param coin The coin type (`coin_type::...`), below 2^31.
/// \param account The account, below 2^31.
/// \param change 0 for receiving addresses, 1 for change.
/// \param address_index The address index, below 2^31.
/// \return The path, or `errc::invalid_path` for an index at or above 2^31 or a change other than 0 or 1.
[[nodiscard]] constexpr result<derivation_path, errc> wallet_path(std::uint32_t purpose_number, std::uint32_t coin,
                                                                   std::uint32_t account, std::uint32_t change,
                                                                   std::uint32_t address_index) noexcept
{
    if (is_hardened(purpose_number) || is_hardened(coin) || is_hardened(account) || change > 1 || is_hardened(address_index))
        return err(errc::invalid_path);
    derivation_path p;
    p.push_back(hardened(purpose_number));
    p.push_back(hardened(coin));
    p.push_back(hardened(account));
    p.push_back(change);
    p.push_back(address_index);
    return ok(p);
}

/// \brief BIP-44: m/44'/coin'/account'/change/index.
/// \param coin The coin type.
/// \param account The account.
/// \param change 0 or 1.
/// \param address_index The address index.
/// \return The path, or `errc::invalid_path`.
[[nodiscard]] constexpr result<derivation_path, errc> bip44_path(std::uint32_t coin, std::uint32_t account,
                                                                  std::uint32_t change, std::uint32_t address_index) noexcept
{
    return wallet_path(purpose::bip44, coin, account, change, address_index);
}

/// \brief BIP-49: m/49'/coin'/account'/change/index.
/// \param coin The coin type.
/// \param account The account.
/// \param change 0 or 1.
/// \param address_index The address index.
/// \return The path, or `errc::invalid_path`.
[[nodiscard]] constexpr result<derivation_path, errc> bip49_path(std::uint32_t coin, std::uint32_t account,
                                                                  std::uint32_t change, std::uint32_t address_index) noexcept
{
    return wallet_path(purpose::bip49, coin, account, change, address_index);
}

/// \brief BIP-84: m/84'/coin'/account'/change/index.
/// \param coin The coin type.
/// \param account The account.
/// \param change 0 or 1.
/// \param address_index The address index.
/// \return The path, or `errc::invalid_path`.
[[nodiscard]] constexpr result<derivation_path, errc> bip84_path(std::uint32_t coin, std::uint32_t account,
                                                                  std::uint32_t change, std::uint32_t address_index) noexcept
{
    return wallet_path(purpose::bip84, coin, account, change, address_index);
}

/// \brief BIP-86: m/86'/coin'/account'/change/index.
/// \param coin The coin type.
/// \param account The account.
/// \param change 0 or 1.
/// \param address_index The address index.
/// \return The path, or `errc::invalid_path`.
[[nodiscard]] constexpr result<derivation_path, errc> bip86_path(std::uint32_t coin, std::uint32_t account,
                                                                  std::uint32_t change, std::uint32_t address_index) noexcept
{
    return wallet_path(purpose::bip86, coin, account, change, address_index);
}

} // namespace snicholls::crypto::hd

#endif /* snicholls_crypto_hd_path_hpp */

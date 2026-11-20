//
//  mnemonic.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `bip39::mnemonic`: entropy to words and back with the checksum, canonical text, and the BIP-39 seed.
/// \ingroup wallet
///
/// \overview
/// A BIP-39 mnemonic is 12, 15, 18, 21 or 24 words from `bip39::english` that encode 16 to 32 bytes of entropy and a
/// checksum of 4 to 8 bits (the first bits of its SHA-256). This header converts between the three forms a wallet
/// meets, and derives the 64-byte seed that BIP-32 and SLIP-10 start from:
///
/// - `from_entropy(bytes)`: entropy to a mnemonic (the checksum computed).
/// - `parse(text)`: canonical text to a mnemonic, the checksum verified.
/// - `mnemonic::to_text(buffer)`: the words, separated by single spaces, into a fixed buffer.
/// - `to_entropy(m)`: the entropy back, in a `secret_bytes<32>`.
/// - `to_seed(m, passphrase)`: PBKDF2-HMAC-SHA512 of the text, salt "mnemonic" + passphrase, 2048 rounds.
///
/// **Canonical text only.** `parse` accepts lower-case words a to z separated by exactly one ASCII space, with no
/// space before the first word or after the last, and nothing else (`errc::non_canonical`). Wallets differ on what
/// they forgive (upper case, several spaces, tabs, a trailing newline) and each forgiveness is a way for two
/// programs to derive different seeds from what a person believes are the same words; a caller that wants to
/// accept looser input normalises it first, visibly.
///
/// **NFKD.** BIP-39 hashes the NFKD normalisation of the mnemonic and of the passphrase. English mnemonics are
/// ASCII, where NFKD changes nothing. A passphrase must therefore be ASCII (`passphrase_form::ascii`, the default),
/// or the caller states that it has already normalised it to NFKD (`passphrase_form::nfkd`), and it is used byte
/// for byte; a non-ASCII passphrase without that statement is refused with `errc::non_canonical`, never hashed as
/// given, because another wallet would hash its NFKD form and the seed would silently differ. This library has no
/// NFKD of its own: snicholls-core's Unicode tables (unreleased) carry canonical decomposition (NFD) only, and NFKD
/// needs the compatibility mappings too. When core has them, `to_seed` can normalise itself.
///
/// \relations
/// - `bip39/wordlist.hpp`: the words.
/// - `hd/bip32.hpp`, `hd/slip10.hpp`: what the seed is for.
/// - `secret.hpp`: the seed and the entropy are `secret_bytes`.
/// - Group: \ref wallet.
///
/// \impls
/// One. The PBKDF2 is the library's interim one (`detail/hashes.hpp`) until snicholls-core releases its own.
///
/// \contracts
/// - Secrets: the entropy, the words, the text and the passphrase. Every path over them is constant time in their
///   values: words are looked up by comparing against all 2048 entries with masks (never a search), `parse` scans
///   the text with masks (no branch on a character, every word slot written on every space), `to_text` places each
///   word with masks over the whole buffer, and the checksum is compared with masks.
/// - Public: the number of words (it is the length of the entropy), the length of the text (`parse` sees it and
///   `to_text` returns it), and which error a failure is. Lengths of individual words are not revealed by timing.
/// - `mnemonic` wipes its word indices on destruction; copies only by `clone()`. No allocation anywhere.
/// - Everything is `constexpr` except `to_seed` (it reads the passphrase's characters as bytes, which a constant
///   expression cannot, and 2048 PBKDF2 rounds are no work for a compiler anyway).
///
/// \errors
/// `from_entropy`: `errc::invalid_mnemonic_length` unless 16, 20, 24, 28 or 32 bytes. `parse`, in this order:
/// `errc::invalid_mnemonic_length` for empty or over-long text, `errc::non_canonical`, `errc::invalid_mnemonic_length`
/// for a word count other than 12, 15, 18, 21 or 24, `errc::unknown_word`, `errc::invalid_checksum`. `to_seed`:
/// `errc::non_canonical` for a non-ASCII passphrase given as `passphrase_form::ascii`.
///
/// \examples
/// \snippet bip39/mnemonic_demo.cpp mnemonic
///
/// \perf
/// `benchmarks/bip39/mnemonic_benchmark.cpp`; the seed's 2048 HMAC-SHA512 rounds dominate. Numbers in BENCHMARKS.md.
///
/// \testing
/// `tests/bip39/mnemonic_test.cpp`: Trezor's 24 English vectors (entropy to words, words to entropy, seed with the
/// passphrase "TREZOR"), every error, non-canonical spacing and case. `demos/bip39/mnemonic_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstddef>`, `<cstdint>`, `<span>`, `<string_view>`; core's `result.hpp`.
///
/// \gotchas
/// `to_text` writes the words without a terminating NUL; it returns the length.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_bip39_mnemonic_hpp
#define snicholls_crypto_bip39_mnemonic_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/bip39/wordlist.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace snicholls::crypto::bip39 {

/// \brief The most words a mnemonic has (24, for 32 bytes of entropy).
inline constexpr std::size_t max_words = 24;
/// \brief The longest canonical text: 24 words of 8 letters and 23 spaces.
inline constexpr std::size_t max_text_length = max_words * max_word_length + (max_words - 1);
/// \brief The most bytes of entropy (32, for 24 words).
inline constexpr std::size_t max_entropy_size = 32;

/// \brief How a passphrase is given to `to_seed`.
enum class passphrase_form : unsigned char {
    ascii,   ///< ASCII only (NFKD leaves it unchanged); anything else is refused.
    nfkd,    ///< Any UTF-8 the caller has already normalised to NFKD; hashed byte for byte.
};

/// \brief A valid BIP-39 mnemonic: 12 to 24 word indices whose checksum holds. Secret; wiped on destruction.
/// \ingroup wallet
///
/// \overview
/// Made only by `from_entropy` and `parse`, so every value has a correct checksum. Holds word indices, not text;
/// `to_text` renders the text.
///
/// \contracts
/// Move-only (`clone()` copies), `noexcept`, `constexpr`; the indices are wiped on destruction and on move.
class mnemonic {
public:
    mnemonic(const mnemonic&) = delete;
    mnemonic& operator=(const mnemonic&) = delete;

    /// \brief Takes the words of `other` and wipes it.
    /// \param other The source, empty afterwards.
    constexpr mnemonic(mnemonic&& other) noexcept : words_(other.words_), count_(other.count_)
    {
        other.wipe();
    }

    /// \brief Takes the words of `other` and wipes it.
    /// \param other The source, empty afterwards.
    /// \return `*this`.
    constexpr mnemonic& operator=(mnemonic&& other) noexcept
    {
        if (this != &other) {
            words_ = other.words_;
            count_ = other.count_;
            other.wipe();
        }
        return *this;
    }

    /// \brief Wipes the words.
    constexpr ~mnemonic() { wipe(); }

    /// \brief An explicit copy.
    /// \return A mnemonic with the same words.
    [[nodiscard]] constexpr mnemonic clone() const noexcept
    {
        mnemonic m;
        m.words_ = words_;
        m.count_ = count_;
        return m;
    }

    /// \brief The number of words: 12, 15, 18, 21 or 24 (public).
    /// \return The count.
    [[nodiscard]] constexpr std::size_t size() const noexcept { return count_; }

    /// \brief The number of bytes of entropy the words encode: 16 to 32.
    /// \return 4 * size() / 3.
    [[nodiscard]] constexpr std::size_t entropy_size() const noexcept { return count_ * 4 / 3; }

    /// \brief The index of word `i` in the list. Reveals a secret: for display and tests.
    /// \pre `i < size()`.
    /// \param i The position.
    /// \return 0 to 2047.
    [[nodiscard]] constexpr std::uint16_t index(std::size_t i) const noexcept { return words_[i]; }

    /// \brief The words as canonical text (single spaces, no NUL), written in constant time.
    /// \param out The buffer; `max_text_length` bytes always suffice.
    /// \return The number of characters written (public: it is the length of what will be shown).
    constexpr std::size_t to_text(std::span<char, max_text_length> out) const noexcept
    {
        for (char& c : out)
            c = 0;
        std::uint64_t pos = 0;
        for (std::size_t w = 0; w < count_; ++w) {
            std::uint64_t packed = 0;
            for (std::uint64_t i = 0; i < word_list_size; ++i)
                packed = ct::select(ct::mask_equal(i, words_[w]), english_packed[i], packed);
            std::uint64_t len = 0;
            for (std::size_t b = 0; b < max_word_length; ++b)
                len += ~ct::mask_is_zero((packed >> (8 * b)) & 0xff) & 1;
            const std::uint64_t space_wanted = ct::mask_from_bit(w + 1 < count_ ? 1 : 0);
            for (std::uint64_t j = 0; j < max_text_length; ++j) {
                const std::uint64_t k = j - pos;
                const std::uint64_t in_word = ct::mask_less(k, len);
                const auto letter = static_cast<unsigned char>((packed >> (8 * (k & 7))) & 0xff);
                const std::uint64_t at_space = ct::mask_equal(k, len) & space_wanted;
                auto c = static_cast<unsigned char>(out[j]);
                c = ct::select<unsigned char>(in_word, letter, c);
                c = ct::select<unsigned char>(at_space, static_cast<unsigned char>(' '), c);
                out[j] = static_cast<char>(c);
            }
            pos += len + (space_wanted & 1);
            secure_wipe(packed);
        }
        return static_cast<std::size_t>(pos);
    }

    /// \brief Constant-time equality of the words.
    /// \param a A mnemonic.
    /// \param b Another.
    /// \return Whether they are the same words.
    [[nodiscard]] friend constexpr bool operator==(const mnemonic& a, const mnemonic& b) noexcept
    {
        std::uint64_t diff = a.count_ ^ b.count_;
        for (std::size_t i = 0; i < max_words; ++i)
            diff |= static_cast<std::uint64_t>(a.words_[i] ^ b.words_[i]);
        return ct::mask_is_zero(diff) != 0;
    }

private:
    constexpr mnemonic() noexcept = default;
    constexpr void wipe() noexcept
    {
        secure_wipe(words_);
        count_ = 0;
    }

    // The mnemonic for `count` words of bits (entropy, then the checksum), big-endian
    static constexpr mnemonic from_bits(const std::array<std::uint8_t, max_entropy_size + 1>& bits, std::size_t count) noexcept
    {
        mnemonic m;
        m.count_ = count;
        for (std::size_t w = 0; w < count; ++w) {
            std::uint32_t v = 0;
            for (std::size_t b = 0; b < 11; ++b) {
                const std::size_t pos = 11 * w + b;   // public positions; the bits themselves are secret
                v = (v << 1) | ((bits[pos / 8] >> (7 - pos % 8)) & 1u);
            }
            m.words_[w] = static_cast<std::uint16_t>(v);
        }
        return m;
    }

    friend constexpr result<mnemonic, errc> from_entropy(std::span<const std::uint8_t> entropy) noexcept;
    friend constexpr result<mnemonic, errc> parse(std::string_view text) noexcept;

    std::array<std::uint16_t, max_words> words_{};
    std::size_t count_ = 0;
};

namespace detail {

// Whether n is a valid word count, and the entropy size for it
constexpr bool valid_word_count(std::size_t n) noexcept { return n >= 12 && n <= 24 && n % 3 == 0; }

// The checksum bits for `size` bytes of entropy, left-aligned in a byte: the first size / 4 bits of SHA-256
constexpr std::uint8_t checksum(std::span<const std::uint8_t> entropy) noexcept
{
    const auto h = crypto::detail::sha256::hash(entropy);
    const std::size_t cs_bits = entropy.size() / 4;
    return static_cast<std::uint8_t>(h[0] & static_cast<std::uint8_t>(0xff << (8 - cs_bits)));
}

} // namespace detail

/// \brief The mnemonic encoding these bytes of entropy.
/// \param entropy 16, 20, 24, 28 or 32 bytes (secret).
/// \return The mnemonic, or `errc::invalid_mnemonic_length`.
[[nodiscard]] constexpr result<mnemonic, errc> from_entropy(std::span<const std::uint8_t> entropy) noexcept
{
    if (entropy.size() < 16 || entropy.size() > max_entropy_size || entropy.size() % 4 != 0)
        return err(errc::invalid_mnemonic_length);
    std::array<std::uint8_t, max_entropy_size + 1> bits{};
    for (std::size_t i = 0; i < entropy.size(); ++i)
        bits[i] = entropy[i];
    bits[entropy.size()] = detail::checksum(entropy);
    mnemonic m = mnemonic::from_bits(bits, entropy.size() * 3 / 4);
    secure_wipe(bits);
    return ok(std::move(m));
}

/// \brief The entropy the words encode.
/// \param m The mnemonic.
/// \return The entropy in its first `m.entropy_size()` bytes; the rest are zero.
[[nodiscard]] constexpr secret_bytes<max_entropy_size> to_entropy(const mnemonic& m) noexcept
{
    std::array<std::uint8_t, max_entropy_size + 1> bits{};
    for (std::size_t w = 0; w < m.size(); ++w)
        for (std::size_t b = 0; b < 11; ++b) {
            const std::size_t pos = 11 * w + b;
            const auto bit = static_cast<std::uint8_t>((m.index(w) >> (10 - b)) & 1u);
            bits[pos / 8] = static_cast<std::uint8_t>(bits[pos / 8] | (bit << (7 - pos % 8)));
        }
    std::array<std::uint8_t, max_entropy_size> e{};
    for (std::size_t i = 0; i < m.entropy_size(); ++i)
        e[i] = bits[i];
    secure_wipe(bits);
    return secret_bytes<max_entropy_size>(std::move(e));
}

/// \brief A mnemonic from canonical text, its checksum verified, in constant time in the words.
/// \param text Lower-case words a to z separated by single spaces (secret).
/// \return The mnemonic, or the first error found (see the file description for the order).
[[nodiscard]] constexpr result<mnemonic, errc> parse(std::string_view text) noexcept
{
    if (text.empty() || text.size() > max_text_length)
        return err(errc::invalid_mnemonic_length);
    // One slot per possible word; on every space every slot is written, the right one with the finished word
    std::array<std::uint64_t, max_words + 1> slot{};
    std::uint64_t bad = 0, count = 0, len = 0, acc = 0, too_long = 0;
    for (const char ch : text) {
        const auto c = static_cast<std::uint64_t>(static_cast<unsigned char>(ch));
        const std::uint64_t space = ct::mask_equal(c, ' ');
        const std::uint64_t letter = ~ct::mask_less(c, 'a') & ~ct::mask_less('z', c);
        bad |= ~(space | letter);
        bad |= space & ct::mask_is_zero(len);                        // a leading or a second space
        const std::uint64_t finished = ct::select(too_long, std::uint64_t{0}, acc);   // 0 matches no word
        for (std::uint64_t k = 0; k <= max_words; ++k)
            slot[k] = ct::select(space & ct::mask_equal(k, count), finished, slot[k]);
        const std::uint64_t fits = letter & ct::mask_less(len, max_word_length);
        too_long = ct::select(space, std::uint64_t{0}, too_long | (letter & ~fits));
        acc = ct::select(space, std::uint64_t{0}, acc | (fits & (c << (8 * (len & 7)))));
        len = ct::select(space, std::uint64_t{0}, len + 1);
        count += space & 1;
    }
    bad |= ct::mask_is_zero(len);                                    // a trailing space
    const std::uint64_t finished = ct::select(too_long, std::uint64_t{0}, acc);
    for (std::uint64_t k = 0; k <= max_words; ++k)
        slot[k] = ct::select(ct::mask_equal(k, count), finished, slot[k]);
    ++count;
    secure_wipe(acc);

    errc failure{};
    if (bad)
        failure = errc::non_canonical;
    else if (!detail::valid_word_count(count))
        failure = errc::invalid_mnemonic_length;
    mnemonic m;
    m.count_ = failure == errc{} ? count : 0;
    std::uint64_t unknown = 0;
    for (std::size_t w = 0; w < m.count_; ++w) {
        const std::uint64_t i = find_word_ct(slot[w]);
        unknown |= ct::mask_equal(i, word_list_size);
        m.words_[w] = static_cast<std::uint16_t>(i & 0x7ff);
    }
    secure_wipe(slot);
    if (failure == errc{} && unknown)
        failure = errc::unknown_word;
    if (failure != errc{})
        return err(failure);

    // The checksum: recompute it from the entropy and compare it with the last bits, with masks
    std::array<std::uint8_t, max_entropy_size + 1> bits{};
    for (std::size_t w = 0; w < m.count_; ++w)
        for (std::size_t b = 0; b < 11; ++b) {
            const std::size_t pos = 11 * w + b;
            const auto bit = static_cast<std::uint8_t>((m.words_[w] >> (10 - b)) & 1u);
            bits[pos / 8] = static_cast<std::uint8_t>(bits[pos / 8] | (bit << (7 - pos % 8)));
        }
    const std::size_t ent = m.entropy_size();
    const std::uint8_t expected = detail::checksum(std::span<const std::uint8_t>(bits).first(ent));
    const std::uint64_t mismatch = ~ct::mask_equal(expected, bits[ent]);
    secure_wipe(bits);
    if (mismatch)
        return err(errc::invalid_checksum);
    return ok(std::move(m));
}

/// \brief The BIP-39 seed: PBKDF2-HMAC-SHA512(text, "mnemonic" + passphrase, 2048 rounds, 64 bytes).
/// \param m The mnemonic.
/// \param passphrase The passphrase (secret), empty for none.
/// \param form Whether the passphrase is plain ASCII (checked) or already NFKD-normalised by the caller.
/// \return The seed, or `errc::non_canonical` for a non-ASCII passphrase given as `passphrase_form::ascii`.
[[nodiscard]] inline result<secret_bytes<64>, errc> to_seed(const mnemonic& m, std::string_view passphrase = {},
                                                            passphrase_form form = passphrase_form::ascii) noexcept
{
    std::uint64_t high = 0;
    for (const char c : passphrase)
        high |= static_cast<unsigned char>(c) & 0x80u;
    if (form == passphrase_form::ascii && high)
        return err(errc::non_canonical);
    std::array<char, max_text_length> text{};
    const std::size_t n = m.to_text(text);
    std::array<std::uint8_t, 64> seed{};
    crypto::detail::pbkdf2_hmac_sha512(crypto::detail::text_bytes({text.data(), n}), crypto::detail::text_bytes("mnemonic"),
                                       crypto::detail::text_bytes(passphrase), 2048, seed);
    secure_wipe(text);
    return ok(secret_bytes<64>(std::move(seed)));
}

} // namespace snicholls::crypto::bip39

#endif /* snicholls_crypto_bip39_mnemonic_hpp */

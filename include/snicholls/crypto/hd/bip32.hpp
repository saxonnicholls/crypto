//
//  bip32.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief BIP-32 hierarchical deterministic keys over secp256k1: the master key from a seed, private and public
/// child derivation, fingerprints, and the `xprv` / `xpub` serialisation (with its `tprv`, `yprv`, `zprv` cousins).
/// \ingroup wallet
///
/// \overview
/// - `extended_private_key::from_seed(seed)`: the master key, HMAC-SHA512 keyed by "Bitcoin seed".
/// - `derive_child(i)` / `derive(path)`: CKDpriv for hardened (i >= 2^31) and non-hardened indices; on an
///   `extended_public_key`, CKDpub for non-hardened indices only.
/// - `public_key()`: the extended public key (the "neutered" key).
/// - `fingerprint()` / `identifier()`: HASH160 of the compressed public key, and its first four bytes.
/// - `serialize(version)` / `to_text(versions)` / `parse(text, versions)`: the 78-byte serialisation and its
///   base58check text (`address/base58check.hpp`), with the versions of BIP-32 (xprv / xpub, tprv / tpub), BIP-49
///   (yprv / ypub) and BIP-84 (zprv / zpub).
///
/// \relations
/// - `bip39/mnemonic.hpp`: where the seed usually comes from; `hd/path.hpp`: the paths; `hd/slip10.hpp`: the Ed25519
///   counterpart; `secp256k1/ecdsa.hpp`: what the derived keys sign with.
/// - Group: \ref wallet.
///
/// \impls
/// One.
///
/// \contracts
/// - Private derivation is constant time in the key, the chain code and the seed: the HMAC has no data-dependent
///   branch, the parent's public key (for a non-hardened child and for the fingerprint) is the constant-time
///   `mul_base`, and the range check of I_L and the sum are masked. The only branch is on the validity of the child
///   (probability below 2^-127), which BIP-32 makes public anyway: the caller moves to the next index.
/// - Public derivation (`extended_public_key`) and `parse` handle public data and may be variable time. An `xprv`'s
///   text holds the key: `parse` of one runs the base58 decoder, which is not constant time (see "Known issues").
/// - Private keys and chain codes are wiped (`secret_bytes`); `extended_private_key` is move-only, `clone()` copies.
/// - `constexpr` and `noexcept` throughout; no allocation.
///
/// \errors
/// `errc::invalid_seed` for a seed outside 16 to 64 bytes; `errc::invalid_derivation` when I_L is at or above n or
/// the child key is zero (or the identity), as BIP-32 specifies, for which the caller uses the next index;
/// `errc::hardened_required` for a hardened index from a public key; `errc::invalid_extended_key` for a serialisation
/// with an unknown or mismatched version, bad key data, a zero depth with a parent or an index, or a key out of
/// range; `errc::invalid_checksum`, `errc::invalid_character`, `errc::invalid_length` from the base58check text.
///
/// \examples
/// \snippet hd/bip32_demo.cpp bip32
///
/// \perf
/// `benchmarks/hd/bip32_benchmark.cpp`: one constant-time multiplication per derivation step (two for a non-hardened
/// one) dominates; see README.md for numbers.
///
/// \testing
/// `tests/hd/bip32_test.cpp`: BIP-32 test vectors 1 to 4 (every chain, xpub and xprv both ways, private and, where the
/// path allows, public derivation) and all sixteen invalid keys of vector 5; SLIP-10's secp256k1 vectors
/// (fingerprints, chain codes, keys); Trezor's BIP-39 master keys. `demos/hd/bip32_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`; the library's HMAC-SHA512, HASH160 and base58check.
///
/// \gotchas
/// The base58 decoder is variable time, so decoding an `xprv` can leak through timing something about the key's
/// text to an observer who can time that one call; keep `xprv` text off paths an attacker can time, or store the 78
/// bytes (`serialize`) instead. The text returned by `to_text` for a private key is key material: wipe it
/// (`secure_wipe`) when done.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_hd_bip32_hpp
#define snicholls_crypto_hd_bip32_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/hd/path.hpp>
#include <snicholls/crypto/secp256k1/keys.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace snicholls::crypto::hd {

/// \brief The four-byte version prefixes of an extended private and public key.
/// \ingroup wallet
struct key_versions {
    std::uint32_t private_version;   ///< xprv, tprv, yprv, zprv.
    std::uint32_t public_version;    ///< xpub, tpub, ypub, zpub.
};

/// \brief BIP-32 mainnet, `xprv` / `xpub`.
inline constexpr key_versions bitcoin_mainnet{0x0488ADE4, 0x0488B21E};
/// \brief BIP-32 testnet, `tprv` / `tpub`.
inline constexpr key_versions bitcoin_testnet{0x04358394, 0x043587CF};
/// \brief BIP-49 (P2WPKH nested in P2SH), `yprv` / `ypub`.
inline constexpr key_versions bip49_mainnet{0x049D7878, 0x049D7CB2};
/// \brief BIP-84 (native P2WPKH), `zprv` / `zpub`.
inline constexpr key_versions bip84_mainnet{0x04B2430C, 0x04B24746};

/// \brief The first four bytes of a key's HASH160: how a child names its parent.
using key_fingerprint = std::array<std::uint8_t, 4>;

/// \brief The base58check text of an extended key (111 characters).
using extended_key_text = address::base58check_text<78>;

namespace detail {
constexpr std::array<std::uint8_t, 4> be32(std::uint32_t v) noexcept
{
    return {static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 8),
            static_cast<std::uint8_t>(v)};
}

constexpr std::uint32_t read_be32(std::span<const std::uint8_t> b) noexcept
{
    return (std::uint32_t{b[0]} << 24) | (std::uint32_t{b[1]} << 16) | (std::uint32_t{b[2]} << 8) | std::uint32_t{b[3]};
}

constexpr std::array<std::uint8_t, 20> identifier_of(const secp256k1::public_key& k) noexcept
{
    return crypto::detail::hash160(k.compressed());
}

// version || depth || parent || child || chain || 33 key bytes
constexpr std::array<std::uint8_t, 78> serialise(std::uint32_t version, std::uint8_t depth, const key_fingerprint& parent,
                                                 std::uint32_t child, std::span<const std::uint8_t, 32> chain,
                                                 std::span<const std::uint8_t, 33> key) noexcept
{
    std::array<std::uint8_t, 78> out{};
    const auto v = be32(version), c = be32(child);
    for (std::size_t i = 0; i < 4; ++i) {
        out[i] = v[i];
        out[5 + i] = parent[i];
        out[9 + i] = c[i];
    }
    out[4] = depth;
    for (std::size_t i = 0; i < 32; ++i)
        out[13 + i] = chain[i];
    for (std::size_t i = 0; i < 33; ++i)
        out[45 + i] = key[i];
    return out;
}

// The header fields every extended key shares, checked for consistency
struct header {
    std::uint32_t version;
    std::uint8_t depth;
    key_fingerprint parent;
    std::uint32_t child;
};

constexpr result<header, errc> read_header(std::span<const std::uint8_t, 78> p) noexcept
{
    header h{read_be32(p.first<4>()), p[4], {p[5], p[6], p[7], p[8]}, read_be32(p.subspan<9, 4>())};
    if (h.depth == 0 && (h.child != 0 || h.parent != key_fingerprint{}))
        return err(errc::invalid_extended_key);   // a master key has no parent and no index
    return ok(h);
}
} // namespace detail

/// \brief A BIP-32 extended public key: a secp256k1 public key, its chain code and its place in the tree. Public data.
/// \ingroup wallet
struct extended_public_key {
    secp256k1::public_key key;            ///< K.
    std::array<std::uint8_t, 32> chain;   ///< c.
    std::uint8_t depth = 0;               ///< 0 for the master key.
    key_fingerprint parent{};             ///< The parent's fingerprint, zero for the master key.
    std::uint32_t child_number = 0;       ///< The index this key was derived with, zero for the master key.

    /// \brief HASH160 of the compressed key.
    /// \return 20 bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 20> identifier() const noexcept { return detail::identifier_of(key); }

    /// \brief The first four bytes of `identifier()`.
    /// \return The fingerprint.
    [[nodiscard]] constexpr key_fingerprint fingerprint() const noexcept
    {
        const auto id = identifier();
        return {id[0], id[1], id[2], id[3]};
    }

    /// \brief CKDpub: the non-hardened child `index`. Variable time; public data.
    /// \param index Below 2^31.
    /// \return The child, or `errc::hardened_required` / `errc::invalid_derivation`.
    [[nodiscard]] constexpr result<extended_public_key, errc> derive_child(std::uint32_t index) const noexcept
    {
        if (is_hardened(index))
            return err(errc::hardened_required);
        crypto::detail::hmac_sha512 m(chain);
        m.update(key.compressed());
        m.update(detail::be32(index));
        const auto i = m.finish();
        const auto il = secp256k1::scalar::from_bytes(std::span<const std::uint8_t, 64>(i).first<32>());
        if (!il)
            return err(errc::invalid_derivation);
        const auto child = (secp256k1::point::mul_base(*il) + secp256k1::point(key.point())).to_affine();
        if (!child)
            return err(errc::invalid_derivation);
        extended_public_key out{secp256k1::public_key(*child), {}, static_cast<std::uint8_t>(depth + 1), fingerprint(), index};
        for (std::size_t j = 0; j < 32; ++j)
            out.chain[j] = i[32 + j];
        return ok(out);
    }

    /// \brief CKDpub along a path of non-hardened indices.
    /// \param path The indices; the leading "m" is this key.
    /// \return The descendant, or the first error.
    [[nodiscard]] constexpr result<extended_public_key, errc> derive(const derivation_path& path) const noexcept
    {
        extended_public_key k = *this;
        for (const std::uint32_t index : path.indices()) {
            auto next = k.derive_child(index);
            if (!next)
                return next;
            k = *next;
        }
        return ok(k);
    }

    /// \brief The 78-byte serialisation.
    /// \param version The version prefix (`bitcoin_mainnet.public_version` for `xpub`).
    /// \return The bytes.
    [[nodiscard]] constexpr std::array<std::uint8_t, 78> serialize(std::uint32_t version = bitcoin_mainnet.public_version) const noexcept
    {
        return detail::serialise(version, depth, parent, child_number, chain, key.compressed());
    }

    /// \brief The base58check text (`xpub...`).
    /// \param versions The version pair; its public version is used.
    /// \return 111 characters.
    [[nodiscard]] constexpr extended_key_text to_text(const key_versions& versions = bitcoin_mainnet) const noexcept
    {
        return address::base58check_encode_exact(serialize(versions.public_version));
    }

    /// \brief A 78-byte serialisation with this public version. Variable time; public data.
    /// \param payload The bytes.
    /// \param versions The accepted version pair.
    /// \return The key, or `errc::invalid_extended_key`.
    [[nodiscard]] static constexpr result<extended_public_key, errc> parse(std::span<const std::uint8_t, 78> payload,
                                                                          const key_versions& versions = bitcoin_mainnet) noexcept
    {
        const auto h = detail::read_header(payload);
        if (!h || h->version != versions.public_version)
            return err(errc::invalid_extended_key);
        const auto k = secp256k1::public_key::parse(payload.subspan<45, 33>());
        if (!k || (payload[45] != 0x02 && payload[45] != 0x03))
            return err(errc::invalid_extended_key);
        extended_public_key out{*k, {}, h->depth, h->parent, h->child};
        for (std::size_t j = 0; j < 32; ++j)
            out.chain[j] = payload[13 + j];
        return ok(out);
    }

    /// \brief The base58check text of an extended public key (`xpub...`). Variable time; public data.
    /// \param text The text.
    /// \param versions The accepted version pair.
    /// \return The key, or the errors of base58check and of `parse(payload)`.
    [[nodiscard]] static constexpr result<extended_public_key, errc> parse(std::string_view text,
                                                                          const key_versions& versions = bitcoin_mainnet) noexcept
    {
        const auto payload = address::base58check_decode_exact<78>(text);
        if (!payload)
            return err(payload.unwrap_err());
        return parse(std::span<const std::uint8_t, 78>(*payload), versions);
    }

    /// \brief Equality of every field.
    /// \param a A key.
    /// \param b Another.
    /// \return Whether they agree.
    [[nodiscard]] friend constexpr bool operator==(const extended_public_key& a, const extended_public_key& b) noexcept = default;
};

/// \brief A BIP-32 extended private key: a secp256k1 private key, its chain code and its place in the tree.
/// \ingroup wallet
class extended_private_key {
public:
    /// \brief The master key of a seed (BIP-32 "master key generation"), in constant time.
    /// \param seed 16 to 64 bytes (a BIP-39 seed is 64).
    /// \return The master key, or `errc::invalid_seed` / `errc::invalid_derivation` (I_L zero or at or above n).
    [[nodiscard]] static constexpr result<extended_private_key, errc> from_seed(std::span<const std::uint8_t> seed) noexcept
    {
        if (seed.size() < 16 || seed.size() > 64)
            return err(errc::invalid_seed);
        auto i = crypto::detail::hmac_sha512::mac(crypto::detail::text_bytes("Bitcoin seed"), seed);
        auto k = secp256k1::private_key::from_bytes(std::span<const std::uint8_t, 64>(i).first<32>());
        if (!k) {
            secure_wipe(i);
            return err(errc::invalid_derivation);
        }
        extended_private_key out(std::move(*k), secret_bytes<32>(std::span<const std::uint8_t, 64>(i).last<32>()), 0, {}, 0);
        secure_wipe(i);
        return ok(std::move(out));
    }

    extended_private_key(const extended_private_key&) = delete;
    extended_private_key& operator=(const extended_private_key&) = delete;
    /// \brief Moves; the source's secrets are wiped.
    constexpr extended_private_key(extended_private_key&&) noexcept = default;
    /// \brief Moves; the source's secrets are wiped.
    /// \return `*this`.
    constexpr extended_private_key& operator=(extended_private_key&&) noexcept = default;

    /// \brief An explicit second copy.
    /// \return The same key.
    [[nodiscard]] constexpr extended_private_key clone() const noexcept
    {
        return extended_private_key(key_.clone(), chain_.clone(), depth_, parent_, child_);
    }

    /// \brief CKDpriv: the child `index`, hardened (index >= 2^31) or not, in constant time.
    /// \param index Any 32-bit index; `hd::hardened(i)` for a hardened one.
    /// \return The child, or `errc::invalid_derivation` (use the next index).
    [[nodiscard]] constexpr result<extended_private_key, errc> derive_child(std::uint32_t index) const noexcept
    {
        const secp256k1::public_key parent_key = key_.public_key();
        crypto::detail::hmac_sha512 m(chain_.reveal());
        if (is_hardened(index)) {
            const std::uint8_t zero = 0;
            m.update(std::span<const std::uint8_t>(&zero, 1));
            m.update(key_.reveal());
        } else {
            m.update(parent_key.compressed());
        }
        m.update(detail::be32(index));
        auto i = m.finish();
        std::uint64_t below = 0;
        secp256k1::scalar il = secp256k1::scalar::from_bytes_ct(std::span<const std::uint8_t, 64>(i).first<32>(), below);
        secp256k1::scalar kp = key_.to_scalar();
        secp256k1::scalar child = il + kp;
        const std::uint64_t valid = below & ~child.is_zero_mask();
        auto child_bytes = child.to_bytes();
        secure_wipe(il);
        secure_wipe(kp);
        secure_wipe(child);
        if (!ct::declassify(valid)) {   // probability below 2^-127, and public by BIP-32's rule
            secure_wipe(i);
            secure_wipe(child_bytes);
            return err(errc::invalid_derivation);
        }
        auto k = secp256k1::private_key::from_secret(secret_bytes<32>(std::move(child_bytes)));
        extended_private_key out(std::move(*k), secret_bytes<32>(std::span<const std::uint8_t, 64>(i).last<32>()),
                                 static_cast<std::uint8_t>(depth_ + 1), fingerprint_of(parent_key), index);
        secure_wipe(i);
        return ok(std::move(out));
    }

    /// \brief CKDpriv along a path.
    /// \param path The indices; the leading "m" is this key.
    /// \return The descendant, or the first error.
    [[nodiscard]] constexpr result<extended_private_key, errc> derive(const derivation_path& path) const noexcept
    {
        extended_private_key k = clone();
        for (const std::uint32_t index : path.indices()) {
            auto next = k.derive_child(index);
            if (!next)
                return next;
            k = std::move(*next);
        }
        return ok(std::move(k));
    }

    /// \brief The extended public key (N(k) in BIP-32's terms).
    /// \return The key with the same chain code, depth, parent and index.
    [[nodiscard]] constexpr extended_public_key public_key() const noexcept
    {
        extended_public_key out{key_.public_key(), {}, depth_, parent_, child_};
        for (std::size_t j = 0; j < 32; ++j)
            out.chain[j] = chain_.reveal()[j];
        return out;
    }

    /// \brief The private key.
    /// \return A reference valid while this key lives.
    [[nodiscard]] constexpr const secp256k1::private_key& private_key() const noexcept { return key_; }
    /// \brief The chain code. Key material: with the public key it derives every non-hardened descendant.
    /// \return A view valid while this key lives.
    [[nodiscard]] constexpr std::span<const std::uint8_t, 32> chain_code() const noexcept { return chain_.reveal(); }
    /// \brief The depth, 0 for the master key.
    /// \return The depth.
    [[nodiscard]] constexpr std::uint8_t depth() const noexcept { return depth_; }
    /// \brief The parent's fingerprint, zero for the master key.
    /// \return Four bytes.
    [[nodiscard]] constexpr key_fingerprint parent_fingerprint() const noexcept { return parent_; }
    /// \brief The index this key was derived with, zero for the master key.
    /// \return The index.
    [[nodiscard]] constexpr std::uint32_t child_number() const noexcept { return child_; }
    /// \brief This key's fingerprint (of its public key).
    /// \return Four bytes.
    [[nodiscard]] constexpr key_fingerprint fingerprint() const noexcept { return fingerprint_of(key_.public_key()); }

    /// \brief The 78-byte serialisation. Key material.
    /// \param version The version prefix (`bitcoin_mainnet.private_version` for `xprv`).
    /// \return The bytes, in a wiped buffer.
    [[nodiscard]] constexpr secret_bytes<78> serialize(std::uint32_t version = bitcoin_mainnet.private_version) const noexcept
    {
        std::array<std::uint8_t, 33> k{};
        for (std::size_t j = 0; j < 32; ++j)
            k[1 + j] = key_.reveal()[j];
        secret_bytes<78> out(detail::serialise(version, depth_, parent_, child_, chain_.reveal(), k));
        secure_wipe(k);
        return out;
    }

    /// \brief The base58check text (`xprv...`). Key material: wipe it when done.
    /// \param versions The version pair; its private version is used.
    /// \return 111 characters.
    [[nodiscard]] constexpr extended_key_text to_text(const key_versions& versions = bitcoin_mainnet) const noexcept
    {
        const auto s = serialize(versions.private_version);
        std::array<std::uint8_t, 78> payload{};
        for (std::size_t j = 0; j < 78; ++j)
            payload[j] = s.reveal()[j];
        auto text = address::base58check_encode_exact(payload);
        secure_wipe(payload);
        return text;
    }

    /// \brief A 78-byte serialisation with this private version.
    /// \param payload The bytes.
    /// \param versions The accepted version pair.
    /// \return The key, or `errc::invalid_extended_key` (wrong version, key data not 00 || k, k out of range).
    [[nodiscard]] static constexpr result<extended_private_key, errc> parse(std::span<const std::uint8_t, 78> payload,
                                                                           const key_versions& versions = bitcoin_mainnet) noexcept
    {
        const auto h = detail::read_header(payload);
        if (!h || h->version != versions.private_version || payload[45] != 0x00)
            return err(errc::invalid_extended_key);
        auto k = secp256k1::private_key::from_bytes(payload.subspan<46, 32>());
        if (!k)
            return err(errc::invalid_extended_key);
        return ok(extended_private_key(std::move(*k), secret_bytes<32>(payload.subspan<13, 32>()), h->depth, h->parent, h->child));
    }

    /// \brief The base58check text of an extended private key (`xprv...`). The decoder is variable time (see the file's
    /// "Known issues").
    /// \param text The text.
    /// \param versions The accepted version pair.
    /// \return The key, or the errors of base58check and of `parse(payload)`.
    [[nodiscard]] static constexpr result<extended_private_key, errc> parse(std::string_view text,
                                                                           const key_versions& versions = bitcoin_mainnet) noexcept
    {
        auto payload = address::base58check_decode_exact<78>(text);
        if (!payload)
            return err(payload.unwrap_err());
        auto out = parse(std::span<const std::uint8_t, 78>(*payload), versions);
        secure_wipe(*payload);
        return out;
    }

private:
    constexpr extended_private_key(secp256k1::private_key&& k, secret_bytes<32>&& c, std::uint8_t depth,
                                   const key_fingerprint& parent, std::uint32_t child) noexcept
        : key_(std::move(k)), chain_(std::move(c)), depth_(depth), parent_(parent), child_(child)
    {
    }

    static constexpr key_fingerprint fingerprint_of(const secp256k1::public_key& k) noexcept
    {
        const auto id = detail::identifier_of(k);
        return {id[0], id[1], id[2], id[3]};
    }

    secp256k1::private_key key_;
    secret_bytes<32> chain_;
    std::uint8_t depth_;
    key_fingerprint parent_;
    std::uint32_t child_;
};

} // namespace snicholls::crypto::hd

#endif /* snicholls_crypto_hd_bip32_hpp */

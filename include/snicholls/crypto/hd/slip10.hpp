//
//  slip10.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief SLIP-10 key derivation for Ed25519: the master key from a seed and hardened child derivation.
/// \ingroup wallet
///
/// \overview
/// Ed25519 keys cannot be added like secp256k1 scalars, so SLIP-10 derives them with HMAC-SHA512 keyed by
/// "ed25519 seed" for the master and by the chain code for each child, and defines **only hardened** children:
/// every index must be at least 2^31. A non-hardened index is refused (`errc::hardened_required`), never silently
/// hardened, so a path written for another curve cannot quietly derive a different key. The node's 32-byte key is an
/// Ed25519 seed (RFC 8032's private key): `key_pair()` makes the signing key, `public_key()` its public half. Solana,
/// Stellar and others derive their keys this way (m/44'/501'/0'/0' for Solana).
///
/// \relations
/// - `hd/bip32.hpp`: the secp256k1 counterpart; `hd/path.hpp`: the paths; `curve25519/ed25519.hpp`: the keys.
/// - Group: \ref wallet.
///
/// \impls
/// One: SLIP-10 for ed25519. SLIP-10's secp256k1 derivation is BIP-32's, which `hd/bip32.hpp` implements (its
/// vectors are tested there); NIST P-256 and curve25519 (X25519) derivation are not provided.
///
/// \contracts
/// - Constant time in the seed, the keys and the chain codes (HMAC-SHA512, then copies); the public key is the
///   constant-time Ed25519 base multiplication. Keys and chain codes live in `secret_bytes` and are wiped;
///   `slip10_ed25519_key` is move-only, `clone()` copies.
/// - `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `errc::invalid_seed` for a seed outside 16 to 64 bytes; `errc::hardened_required` for any index below 2^31.
///
/// \examples
/// \snippet hd/slip10_demo.cpp slip10
///
/// \perf
/// One HMAC-SHA512 per step; `public_key()` and `fingerprint()` cost one Ed25519 base multiplication each. See
/// `benchmarks/hd/bip32_benchmark.cpp`.
///
/// \testing
/// `tests/hd/slip10_test.cpp`: SLIP-10's ed25519 test vectors 1 and 2 (fingerprints, chain codes, private and public
/// keys at every depth) and the refusal of non-hardened indices. `demos/hd/slip10_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`; the library's HMAC-SHA512, HASH160 and Ed25519.
///
/// \gotchas
/// SLIP-10 writes an Ed25519 public key as 33 bytes, a 00 byte before the 32-byte key, and fingerprints that form;
/// `public_key()` returns the 32-byte key, `fingerprint()` hashes the 33-byte form as SLIP-10 does.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_hd_slip10_hpp
#define snicholls_crypto_hd_slip10_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/hd/path.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace snicholls::crypto::hd {

/// \brief A SLIP-10 Ed25519 node: its 32-byte key (an Ed25519 seed), chain code and place in the tree.
/// \ingroup wallet
class slip10_ed25519_key {
public:
    /// \brief The master node of a seed, in constant time.
    /// \param seed 16 to 64 bytes.
    /// \return The node, or `errc::invalid_seed`.
    [[nodiscard]] static constexpr result<slip10_ed25519_key, errc> from_seed(std::span<const std::uint8_t> seed) noexcept
    {
        if (seed.size() < 16 || seed.size() > 64)
            return err(errc::invalid_seed);
        return ok(from_hmac(crypto::detail::hmac_sha512::mac(crypto::detail::text_bytes("ed25519 seed"), seed), 0, {}, 0));
    }

    slip10_ed25519_key(const slip10_ed25519_key&) = delete;
    slip10_ed25519_key& operator=(const slip10_ed25519_key&) = delete;
    /// \brief Moves; the source's secrets are wiped.
    constexpr slip10_ed25519_key(slip10_ed25519_key&&) noexcept = default;
    /// \brief Moves; the source's secrets are wiped.
    /// \return `*this`.
    constexpr slip10_ed25519_key& operator=(slip10_ed25519_key&&) noexcept = default;

    /// \brief An explicit second copy.
    /// \return The same node.
    [[nodiscard]] constexpr slip10_ed25519_key clone() const noexcept
    {
        return slip10_ed25519_key(key_.clone(), chain_.clone(), depth_, parent_, child_);
    }

    /// \brief The hardened child `index`, in constant time.
    /// \param index At least 2^31 (`hd::hardened(i)`).
    /// \return The child, or `errc::hardened_required`.
    [[nodiscard]] constexpr result<slip10_ed25519_key, errc> derive_child(std::uint32_t index) const noexcept
    {
        if (!is_hardened(index))
            return err(errc::hardened_required);
        crypto::detail::hmac_sha512 m(chain_.reveal());
        const std::uint8_t zero = 0;
        m.update(std::span<const std::uint8_t>(&zero, 1));
        m.update(key_.reveal());
        m.update(detail::be32(index));
        return ok(from_hmac(m.finish(), static_cast<std::uint8_t>(depth_ + 1), fingerprint(), index));
    }

    /// \brief The node at a path of hardened indices; the whole path is checked before any derivation.
    /// \param path The indices; the leading "m" is this node.
    /// \return The descendant, or `errc::hardened_required`.
    [[nodiscard]] constexpr result<slip10_ed25519_key, errc> derive(const derivation_path& path) const noexcept
    {
        if (!path.all_hardened())
            return err(errc::hardened_required);
        slip10_ed25519_key k = clone();
        for (const std::uint32_t index : path.indices())
            k = k.derive_child(index).unwrap_unchecked();
        return ok(std::move(k));
    }

    /// \brief The Ed25519 key pair whose seed is this node's key.
    /// \return The signing key.
    [[nodiscard]] constexpr ed25519::key_pair key_pair() const noexcept { return ed25519::key_pair::from_seed(key_.reveal()); }

    /// \brief The 32-byte Ed25519 public key.
    /// \return The key.
    [[nodiscard]] constexpr ed25519::public_key public_key() const noexcept { return ed25519::public_key_from_seed(key_.reveal()); }

    /// \brief The node's key: an Ed25519 seed. Key material.
    /// \return A view valid while this node lives.
    [[nodiscard]] constexpr std::span<const std::uint8_t, 32> private_key() const noexcept { return key_.reveal(); }
    /// \brief The chain code. Key material.
    /// \return A view valid while this node lives.
    [[nodiscard]] constexpr std::span<const std::uint8_t, 32> chain_code() const noexcept { return chain_.reveal(); }
    /// \brief The depth, 0 for the master node.
    /// \return The depth.
    [[nodiscard]] constexpr std::uint8_t depth() const noexcept { return depth_; }
    /// \brief The parent's fingerprint, zero for the master node.
    /// \return Four bytes.
    [[nodiscard]] constexpr key_fingerprint parent_fingerprint() const noexcept { return parent_; }
    /// \brief The index this node was derived with, zero for the master node.
    /// \return The index.
    [[nodiscard]] constexpr std::uint32_t child_number() const noexcept { return child_; }

    /// \brief This node's fingerprint: HASH160 of 00 || public key, its first four bytes (SLIP-10's form).
    /// \return Four bytes.
    [[nodiscard]] constexpr key_fingerprint fingerprint() const noexcept
    {
        std::array<std::uint8_t, 33> pk{};
        const auto p = public_key();
        for (std::size_t i = 0; i < 32; ++i)
            pk[1 + i] = p.bytes[i];
        const auto id = crypto::detail::hash160(pk);
        return {id[0], id[1], id[2], id[3]};
    }

private:
    constexpr slip10_ed25519_key(secret_bytes<32>&& k, secret_bytes<32>&& c, std::uint8_t depth, const key_fingerprint& parent,
                                 std::uint32_t child) noexcept
        : key_(std::move(k)), chain_(std::move(c)), depth_(depth), parent_(parent), child_(child)
    {
    }

    static constexpr slip10_ed25519_key from_hmac(std::array<std::uint8_t, 64> i, std::uint8_t depth, const key_fingerprint& parent,
                                                  std::uint32_t child) noexcept
    {
        const std::span<const std::uint8_t, 64> s(i);
        slip10_ed25519_key out(secret_bytes<32>(s.first<32>()), secret_bytes<32>(s.last<32>()), depth, parent, child);
        secure_wipe(i);
        return out;
    }

    secret_bytes<32> key_;
    secret_bytes<32> chain_;
    std::uint8_t depth_;
    key_fingerprint parent_;
    std::uint32_t child_;
};

} // namespace snicholls::crypto::hd

#endif /* snicholls_crypto_hd_slip10_hpp */

//
//  keys.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `secp256k1::private_key` and `secp256k1::public_key`: validated keys, SEC1 encodings, constant-time
/// derivation of the public key.
/// \ingroup secp256k1
///
/// \overview
/// A `private_key` is 32 bytes in a wiped buffer, checked once to be in [1, n - 1]; its public key is d G, computed in
/// constant time. A `public_key` is a validated curve point (never the identity) with its SEC1 encodings: 33 bytes
/// compressed (02 / 03 and x), 65 bytes uncompressed (04, x and y), and the raw 64-byte x || y that Ethereum hashes
/// into an address.
///
/// \relations
/// - `secp256k1/ecdsa.hpp`, `secp256k1/schnorr.hpp`: sign with a `private_key`, verify against a `public_key`.
/// - `hd/bip32.hpp`: derives `private_key`s.
/// - Group: \ref secp256k1.
///
/// \impls
/// One.
///
/// \contracts
/// - `private_key`: move-only, wiped on destruction; `from_bytes` checks the range in constant time and reveals only
///   whether the key is valid. `public_key()` is constant time in the key.
/// - `public_key`: a value type of public data; `parse` is variable time (public data only) and accepts exactly the
///   02, 03 and 04 forms (hybrid 06 / 07 and the 00 identity encoding are rejected).
/// - Everything is `constexpr` and `noexcept`.
///
/// \errors
/// `errc::invalid_private_key` for 0 or a value at or above n; `errc::invalid_length` for a SEC1 encoding that is
/// neither 33 nor 65 bytes; `errc::invalid_public_key` for a bad prefix, an x or y at or above p, or a point off the
/// curve.
///
/// \examples
/// \snippet secp256k1/keys_demo.cpp keys
///
/// \perf
/// `public_key()` is one constant-time multiplication and one inversion; see `benchmarks/secp256k1/ecdsa_benchmark.cpp`.
///
/// \testing
/// `tests/secp256k1/keys_test.cpp` (keys 1, 2, 3 and n - 1, every rejected encoding), `demos/secp256k1/keys_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`.
///
/// \gotchas
/// An Ethereum address is the last 20 bytes of Keccak-256 of `xy()`; the hash is the caller's (core's `hash/sha3.hpp`).
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secp256k1_keys_hpp
#define snicholls_crypto_secp256k1_keys_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secp256k1/point.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace snicholls::crypto::secp256k1 {

/// \brief A validated secp256k1 public key: a curve point other than the identity. Public data.
/// \ingroup secp256k1
class public_key {
public:
    /// \brief The key of this point.
    /// \param p A point on the curve (not checked: use `parse` for untrusted bytes).
    constexpr explicit public_key(const affine_point& p) noexcept : p_(p) {}

    /// \brief A SEC1 encoding: 33 bytes compressed or 65 bytes uncompressed. Variable time; public data only.
    /// \param bytes The encoding.
    /// \return The key, or `errc::invalid_length` / `errc::invalid_public_key`.
    [[nodiscard]] static constexpr result<public_key, errc> parse(std::span<const std::uint8_t> bytes) noexcept
    {
        if (bytes.size() != 33 && bytes.size() != 65)
            return err(errc::invalid_length);
        const auto x = field_element::from_bytes(bytes.subspan<1, 32>());
        if (!x)
            return err(errc::invalid_public_key);
        if (bytes.size() == 33) {
            if (bytes[0] != 0x02 && bytes[0] != 0x03)
                return err(errc::invalid_public_key);
            const auto p = decompress(*x, bytes[0] & 1);
            if (!p)
                return err(errc::invalid_public_key);
            return ok(public_key(*p));
        }
        if (bytes[0] != 0x04)
            return err(errc::invalid_public_key);
        const auto y = field_element::from_bytes(bytes.subspan<33, 32>());
        if (!y)
            return err(errc::invalid_public_key);
        const affine_point p{*x, *y};
        if (!p.is_on_curve())
            return err(errc::invalid_public_key);
        return ok(public_key(p));
    }

    /// \brief The 33-byte compressed SEC1 encoding.
    /// \return 02 or 03 (the parity of y), then x.
    [[nodiscard]] constexpr std::array<std::uint8_t, 33> compressed() const noexcept
    {
        std::array<std::uint8_t, 33> out{};
        out[0] = static_cast<std::uint8_t>(0x02 | p_.y.is_odd());
        const auto x = p_.x.to_bytes();
        for (std::size_t i = 0; i < 32; ++i)
            out[1 + i] = x[i];
        return out;
    }

    /// \brief The 65-byte uncompressed SEC1 encoding.
    /// \return 04, then x, then y.
    [[nodiscard]] constexpr std::array<std::uint8_t, 65> uncompressed() const noexcept
    {
        std::array<std::uint8_t, 65> out{};
        out[0] = 0x04;
        const auto xy64 = xy();
        for (std::size_t i = 0; i < 64; ++i)
            out[1 + i] = xy64[i];
        return out;
    }

    /// \brief x || y, 64 bytes: what Ethereum hashes with Keccak-256 for an address.
    /// \return The coordinates, big-endian.
    [[nodiscard]] constexpr std::array<std::uint8_t, 64> xy() const noexcept
    {
        std::array<std::uint8_t, 64> out{};
        const auto x = p_.x.to_bytes(), y = p_.y.to_bytes();
        for (std::size_t i = 0; i < 32; ++i) {
            out[i] = x[i];
            out[32 + i] = y[i];
        }
        return out;
    }

    /// \brief The point.
    /// \return The affine coordinates.
    [[nodiscard]] constexpr const affine_point& point() const noexcept { return p_; }

    /// \brief Equality of points.
    /// \param a A key.
    /// \param b Another.
    /// \return Whether they are the same point.
    [[nodiscard]] friend constexpr bool operator==(const public_key& a, const public_key& b) noexcept = default;

private:
    affine_point p_;
};

/// \brief A secp256k1 private key: 32 bytes in [1, n - 1], wiped on destruction.
/// \ingroup secp256k1
class private_key {
public:
    /// \brief A key from 32 big-endian bytes, checked in constant time.
    /// \param bytes The key; the caller still owns and should wipe its copy.
    /// \return The key, or `errc::invalid_private_key` for 0 or a value at or above n.
    [[nodiscard]] static constexpr result<private_key, errc> from_bytes(std::span<const std::uint8_t, 32> bytes) noexcept
    {
        std::uint64_t below = 0;
        scalar d = scalar::from_bytes_ct(bytes, below);
        const std::uint64_t valid = below & ~d.is_zero_mask();
        secure_wipe(d);
        if (!valid)   // reveals only that the key is invalid
            return err(errc::invalid_private_key);
        return ok(private_key(secret_bytes<32>(bytes)));
    }

    /// \brief Takes a key already in a secret buffer, checked in constant time.
    /// \param bytes The key, moved in.
    /// \return The key, or `errc::invalid_private_key`.
    [[nodiscard]] static constexpr result<private_key, errc> from_secret(secret_bytes<32>&& bytes) noexcept
    {
        std::uint64_t below = 0;
        scalar d = scalar::from_bytes_ct(bytes.reveal(), below);
        const std::uint64_t valid = below & ~d.is_zero_mask();
        secure_wipe(d);
        if (!valid)
            return err(errc::invalid_private_key);
        return ok(private_key(std::move(bytes)));
    }

    /// \brief The public key d G, in constant time.
    /// \return The key.
    [[nodiscard]] constexpr secp256k1::public_key public_key() const noexcept
    {
        scalar d = to_scalar();
        std::uint64_t finite = 0;
        const affine_point p = point::mul_base(d).to_affine_ct(finite);   // finite: d is in [1, n - 1]
        secure_wipe(d);
        return secp256k1::public_key(p);
    }

    /// \brief The key as a scalar; the caller wipes it (`secure_wipe`) when done.
    /// \return d.
    [[nodiscard]] constexpr scalar to_scalar() const noexcept { return scalar::from_bytes_reduced(d_.reveal()); }

    /// \brief The key's 32 bytes, big-endian. The one way to the key material.
    /// \return A view valid while this key lives.
    [[nodiscard]] constexpr std::span<const std::uint8_t, 32> reveal() const noexcept { return d_.reveal(); }

    /// \brief An explicit second copy.
    /// \return The same key.
    [[nodiscard]] constexpr private_key clone() const noexcept { return private_key(d_.clone()); }

private:
    constexpr explicit private_key(secret_bytes<32>&& d) noexcept : d_(std::move(d)) {}
    secret_bytes<32> d_;
};

} // namespace snicholls::crypto::secp256k1

#endif /* snicholls_crypto_secp256k1_keys_hpp */

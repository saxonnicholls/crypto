//
//  hashes.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The hashes this library uses - SHA-256, SHA-512, RIPEMD-160, HASH160, HMAC and PBKDF2-HMAC-SHA512 - are
//  snicholls-core's (hash/sha2.hpp, hash/ripemd160.hpp, hash/hmac.hpp, hash/kdf.hpp). This file only adapts them to
//  the shape the library calls: bytes as std::uint8_t in and std::array<std::uint8_t, N> out, and every hash or
//  HMAC state wiped when it dies (core's states are trivially copyable values that do not wipe themselves, and an
//  HMAC state is derived from its key: a chain code, a private key, a mnemonic).
//
//  JOSE's Concat KDF (RFC 7518 4.6.2) is core's jwa_concat_kdf, run over core_wiped<sha256>: core's own hash
//  interface with the state wiped when it dies, since core's KDF leaves its hash objects to their destructors and
//  each holds the Diffie-Hellman shared secret.
//
//  PBKDF2 with a salt in two parts ("mnemonic" and the passphrase, for BIP-39, with no buffer and no length limit)
//  uses core's detail::pbkdf2_blocks, the engine behind core's public pbkdf2_hmac; a public form of it is proposed
//  to core, and this call moves to it when one exists.
//
//  Constant time: core's compression functions have no data-dependent branch or index; the lengths of inputs are
//  public (the Valgrind secret-marking check runs through all of this).
//

#ifndef snicholls_crypto_detail_hashes_hpp
#define snicholls_crypto_detail_hashes_hpp

#include <snicholls/core/hash/hmac.hpp>
#include <snicholls/core/hash/kdf.hpp>
#include <snicholls/core/hash/ripemd160.hpp>
#include <snicholls/core/hash/sha2.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

namespace snicholls::crypto::detail {

// A string literal's characters as bytes, for keys and salts given as text ("Bitcoin seed", "mnemonic")
inline std::span<const std::uint8_t> text_bytes(std::string_view s) noexcept
{
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// A core digest as bytes; the digest is wiped
template <std::size_t N>
constexpr std::array<std::uint8_t, N> to_array(snicholls::digest<N>& d) noexcept
{
    std::array<std::uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i)
        out[i] = static_cast<std::uint8_t>(d.bytes[i]);
    snicholls::secure_wipe(d);
    return out;
}

// One of core's hashes, streaming, wiped on destruction
template <class Core>
class wiped_hash {
    static_assert(std::is_trivially_copyable_v<Core>, "core's hash state is wiped as a trivially copyable value");

public:
    using core_type = Core;
    static constexpr std::size_t block_size = Core::block_size;
    static constexpr std::size_t digest_size = Core::digest_size;
    using digest_type = std::array<std::uint8_t, digest_size>;

    constexpr wiped_hash() noexcept = default;
    constexpr wiped_hash(const wiped_hash&) noexcept = default;
    constexpr wiped_hash& operator=(const wiped_hash&) noexcept = default;
    constexpr ~wiped_hash() { secure_wipe(h_); }

    constexpr void update(std::span<const std::uint8_t> data) noexcept { h_.update(data); }
    constexpr void update(std::string_view s) noexcept { h_.update(s); }

    constexpr digest_type finish() noexcept
    {
        auto d = h_.finish();
        return to_array(d);
    }

    static constexpr digest_type hash(std::span<const std::uint8_t> data) noexcept
    {
        wiped_hash h;
        h.update(data);
        return h.finish();
    }

private:
    Core h_{};
};

using sha256 = wiped_hash<snicholls::sha256>;

// One of core's hashes in core's own interface (hash_function, for core's generic KDFs), wiped on destruction
template <class Core>
class core_wiped : public Core {
    static_assert(std::is_trivially_copyable_v<Core>, "core's hash state is wiped as a trivially copyable value");

public:
    constexpr core_wiped() noexcept = default;
    constexpr core_wiped(const core_wiped&) noexcept = default;
    constexpr core_wiped& operator=(const core_wiped&) noexcept = default;
    constexpr ~core_wiped() { secure_wipe(static_cast<Core&>(*this)); }
};

// JOSE's Concat KDF with SHA-256 (RFC 7518 4.6.2): N bytes from the shared secret z and the header's algorithm,
// apu and apv. N is part of the OtherInfo, so the key is derived whole, through std::byte (core's output type)
template <std::size_t N>
constexpr std::array<std::uint8_t, N> jwa_concat_kdf_sha256(std::span<const std::uint8_t> z, std::string_view algorithm,
                                                            std::span<const std::uint8_t> apu, std::span<const std::uint8_t> apv) noexcept
{
    static_assert(N >= 1 && N <= 1024, "a JOSE key is 16 to 64 bytes");
    std::array<std::byte, N> b{};
    const auto r = snicholls::jwa_concat_kdf<core_wiped<snicholls::sha256>>(z, algorithm, apu, apv, std::span<std::byte>(b));
    (void)r;   // cannot fail: the output is 1 to 1024 bytes
    std::array<std::uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i)
        out[i] = static_cast<std::uint8_t>(b[i]);
    secure_wipe(b);
    return out;
}
using sha512 = wiped_hash<snicholls::sha512>;
using ripemd160 = wiped_hash<snicholls::ripemd160>;

// HASH160 = RIPEMD-160(SHA-256(x)): BIP-32 key identifiers and fingerprints
constexpr std::array<std::uint8_t, 20> hash160(std::span<const std::uint8_t> data) noexcept
{
    auto s = sha256::hash(data);
    const auto r = ripemd160::hash(s);
    secure_wipe(s);
    return r;
}

// Core's HMAC over one of the hashes above, streaming, wiped on destruction
template <class H>
class hmac {
    using core_hmac = snicholls::hmac<typename H::core_type>;
    static_assert(std::is_trivially_copyable_v<core_hmac>, "core's HMAC state is wiped as a trivially copyable value");

public:
    static constexpr std::size_t digest_size = H::digest_size;
    using digest_type = typename H::digest_type;

    constexpr explicit hmac(std::span<const std::uint8_t> key) noexcept : m_(key) {}
    constexpr hmac(const hmac&) noexcept = default;
    constexpr hmac& operator=(const hmac&) noexcept = default;
    constexpr ~hmac()
    {
        if (!std::is_constant_evaluated())   // core's HMAC has no empty state to assign in a constant expression
            secure_wipe(static_cast<void*>(&m_), sizeof m_);
    }

    constexpr void update(std::span<const std::uint8_t> data) noexcept { m_.update(data); }

    constexpr digest_type finish() noexcept
    {
        auto d = m_.finish();
        return to_array(d);
    }

    static constexpr digest_type mac(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) noexcept
    {
        hmac m(key);
        m.update(data);
        return m.finish();
    }

private:
    core_hmac m_;
};

using hmac_sha256 = hmac<sha256>;
using hmac_sha512 = hmac<sha512>;

// PBKDF2 (RFC 8018) with HMAC-SHA512, the salt in two parts, writing out.size() bytes; iterations >= 1
constexpr void pbkdf2_hmac_sha512(std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt,
                                  std::span<const std::uint8_t> salt_tail, std::uint32_t iterations,
                                  std::span<std::uint8_t> out) noexcept
{
    snicholls::detail::pbkdf2_blocks<snicholls::sha512>(
        password,
        [&](snicholls::hmac<snicholls::sha512>& m) {
            m.update(salt);
            m.update(salt_tail);
        },
        iterations, out.size(),
        [&](std::size_t offset, const snicholls::digest<64>& t, std::size_t count) {
            for (std::size_t j = 0; j < count; ++j)
                out[offset + j] = static_cast<std::uint8_t>(t.bytes[j]);
        });
}

constexpr void pbkdf2_hmac_sha512(std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt,
                                  std::uint32_t iterations, std::span<std::uint8_t> out) noexcept
{
    pbkdf2_hmac_sha512(password, salt, {}, iterations, out);
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_hashes_hpp */

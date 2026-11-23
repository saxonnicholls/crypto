//
//  chacha20.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  ChaCha20 (RFC 8439 section 2.3): the block function and the keystream XOR, with a 32-bit counter and a 96-bit
//  nonce; and HChaCha20 (draft-irtf-cfrg-xchacha section 2.2), which derives XChaCha20's subkey from a key and the
//  first 16 bytes of a 24-byte nonce.
//
//  Constant time: additions, rotations and XORs on 32-bit words only, a fixed 20 rounds; no branch or index depends
//  on the key, the nonce or the data. Every intermediate state is wiped. constexpr, no allocation.
//

#ifndef snicholls_crypto_detail_chacha20_hpp
#define snicholls_crypto_detail_chacha20_hpp

#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace snicholls::crypto::detail {

constexpr std::uint32_t load32_le(std::span<const std::uint8_t> b, std::size_t i) noexcept
{
    return static_cast<std::uint32_t>(b[i]) | static_cast<std::uint32_t>(b[i + 1]) << 8 |
           static_cast<std::uint32_t>(b[i + 2]) << 16 | static_cast<std::uint32_t>(b[i + 3]) << 24;
}

constexpr void store32_le(std::span<std::uint8_t> b, std::size_t i, std::uint32_t v) noexcept
{
    b[i] = static_cast<std::uint8_t>(v);
    b[i + 1] = static_cast<std::uint8_t>(v >> 8);
    b[i + 2] = static_cast<std::uint8_t>(v >> 16);
    b[i + 3] = static_cast<std::uint8_t>(v >> 24);
}

constexpr std::uint32_t rotl32(std::uint32_t v, int n) noexcept { return (v << n) | (v >> (32 - n)); }

constexpr void chacha_quarter(std::array<std::uint32_t, 16>& x, std::size_t a, std::size_t b, std::size_t c, std::size_t d) noexcept
{
    x[a] += x[b];
    x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = rotl32(x[b] ^ x[c], 7);
}

constexpr void chacha_rounds(std::array<std::uint32_t, 16>& x) noexcept
{
    for (int i = 0; i < 10; ++i) {
        chacha_quarter(x, 0, 4, 8, 12);
        chacha_quarter(x, 1, 5, 9, 13);
        chacha_quarter(x, 2, 6, 10, 14);
        chacha_quarter(x, 3, 7, 11, 15);
        chacha_quarter(x, 0, 5, 10, 15);
        chacha_quarter(x, 1, 6, 11, 12);
        chacha_quarter(x, 2, 7, 8, 13);
        chacha_quarter(x, 3, 4, 9, 14);
    }
}

// The initial state: "expand 32-byte k", the key, then four words the caller gives (counter and nonce, or the
// 16-byte HChaCha20 input)
constexpr std::array<std::uint32_t, 16> chacha_state(std::span<const std::uint8_t, 32> key, std::uint32_t w12, std::uint32_t w13,
                                                     std::uint32_t w14, std::uint32_t w15) noexcept
{
    std::array<std::uint32_t, 16> s{0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    for (std::size_t i = 0; i < 8; ++i)
        s[4 + i] = load32_le(key, 4 * i);
    s[12] = w12;
    s[13] = w13;
    s[14] = w14;
    s[15] = w15;
    return s;
}

// The 64-byte block for a counter and a 12-byte nonce (RFC 8439 section 2.3)
constexpr std::array<std::uint8_t, 64> chacha20_block(std::span<const std::uint8_t, 32> key, std::uint32_t counter,
                                                      std::span<const std::uint8_t, 12> nonce) noexcept
{
    const auto init = chacha_state(key, counter, load32_le(nonce, 0), load32_le(nonce, 4), load32_le(nonce, 8));
    auto x = init;
    chacha_rounds(x);
    std::array<std::uint8_t, 64> out{};
    for (std::size_t i = 0; i < 16; ++i)
        store32_le(out, 4 * i, x[i] + init[i]);
    secure_wipe(x);
    return out;
}

// out = in XOR the keystream from the counter on (RFC 8439 section 2.4); in and out may be the same span. The
// caller keeps the length within 2^32 blocks of the counter
constexpr void chacha20_xor(std::span<const std::uint8_t, 32> key, std::uint32_t counter, std::span<const std::uint8_t, 12> nonce,
                            std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept
{
    for (std::size_t off = 0; off < in.size(); off += 64, ++counter) {
        auto ks = chacha20_block(key, counter, nonce);
        const std::size_t n = in.size() - off < 64 ? in.size() - off : 64;
        for (std::size_t i = 0; i < n; ++i)
            out[off + i] = static_cast<std::uint8_t>(in[off + i] ^ ks[i]);
        secure_wipe(ks);
    }
}

// HChaCha20: the subkey of XChaCha20 from a key and 16 bytes of nonce (no feed-forward; words 0-3 and 12-15)
constexpr std::array<std::uint8_t, 32> hchacha20(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> n16) noexcept
{
    auto x = chacha_state(key, load32_le(n16, 0), load32_le(n16, 4), load32_le(n16, 8), load32_le(n16, 12));
    chacha_rounds(x);
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 4; ++i) {
        store32_le(out, 4 * i, x[i]);
        store32_le(out, 16 + 4 * i, x[12 + i]);
    }
    secure_wipe(x);
    return out;
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_chacha20_hpp */

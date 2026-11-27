//
//  aes.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  AES-128 and AES-256 (FIPS 197) without tables: the S-box is computed, the GF(2^8) inverse as x^254 by masked
//  multiplication and then the affine map, so no memory index ever depends on the key or the data. Only the forward
//  cipher (GCM and key-wrap verification need decryption only for unwrapping, see aes_decrypt below).
//
//  Constant time throughout: GF(2^8) multiplication by shift and masked XOR, a fixed number of steps; the key
//  schedule and the rounds are fixed sequences. Slower than table or hardware AES (it computes each S-box value),
//  never dependent on secrets. constexpr, no allocation; round keys are wiped.
//

#ifndef snicholls_crypto_detail_aes_hpp
#define snicholls_crypto_detail_aes_hpp

#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace snicholls::crypto::detail {

// a b in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, in constant time
constexpr std::uint8_t gf256_mul(std::uint8_t a, std::uint8_t b) noexcept
{
    std::uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        r ^= static_cast<std::uint8_t>(-(b & 1) & a);
        const std::uint8_t hi = static_cast<std::uint8_t>(-(a >> 7));
        a = static_cast<std::uint8_t>((a << 1) ^ (hi & 0x1b));
        b >>= 1;
    }
    return r;
}

// The S-box: x^254 (the inverse, 0 for 0), then the affine map
constexpr std::uint8_t aes_sbox(std::uint8_t x) noexcept
{
    const std::uint8_t x2 = gf256_mul(x, x);
    const std::uint8_t x3 = gf256_mul(x2, x);
    const std::uint8_t x6 = gf256_mul(x3, x3);
    const std::uint8_t x12 = gf256_mul(x6, x6);
    const std::uint8_t x15 = gf256_mul(x12, x3);
    const std::uint8_t x30 = gf256_mul(x15, x15);
    const std::uint8_t x60 = gf256_mul(x30, x30);
    const std::uint8_t x120 = gf256_mul(x60, x60);
    const std::uint8_t x126 = gf256_mul(x120, x6);
    const std::uint8_t x127 = gf256_mul(x126, x);
    const std::uint8_t inv = gf256_mul(x127, x127);   // x^254
    auto rot = [](std::uint8_t v, int n) { return static_cast<std::uint8_t>((v << n) | (v >> (8 - n))); };
    return static_cast<std::uint8_t>(inv ^ rot(inv, 1) ^ rot(inv, 2) ^ rot(inv, 3) ^ rot(inv, 4) ^ 0x63);
}

// The inverse S-box: the inverse affine map, then x^254
constexpr std::uint8_t aes_inv_sbox(std::uint8_t y) noexcept
{
    auto rot = [](std::uint8_t v, int n) { return static_cast<std::uint8_t>((v << n) | (v >> (8 - n))); };
    const std::uint8_t x = static_cast<std::uint8_t>(rot(y, 1) ^ rot(y, 3) ^ rot(y, 6) ^ 0x05);
    const std::uint8_t x2 = gf256_mul(x, x);
    const std::uint8_t x3 = gf256_mul(x2, x);
    const std::uint8_t x6 = gf256_mul(x3, x3);
    const std::uint8_t x12 = gf256_mul(x6, x6);
    const std::uint8_t x15 = gf256_mul(x12, x3);
    const std::uint8_t x30 = gf256_mul(x15, x15);
    const std::uint8_t x60 = gf256_mul(x30, x30);
    const std::uint8_t x120 = gf256_mul(x60, x60);
    const std::uint8_t x126 = gf256_mul(x120, x6);
    const std::uint8_t x127 = gf256_mul(x126, x);
    return gf256_mul(x127, x127);
}

// AES with a 16- or 32-byte key: its Nr + 1 round keys (11 for AES-128, 15 for AES-256)
template <std::size_t KeyBytes>
class aes_cipher {
    static_assert(KeyBytes == 16 || KeyBytes == 32, "AES-128 or AES-256");

public:
    using block = std::array<std::uint8_t, 16>;
    static constexpr std::size_t rounds = KeyBytes / 4 + 6;

    constexpr explicit aes_cipher(std::span<const std::uint8_t, KeyBytes> key) noexcept
    {
        for (std::size_t i = 0; i < KeyBytes; ++i)
            w_[i] = key[i];
        std::uint8_t rcon = 1;
        for (std::size_t i = KeyBytes; i < w_.size(); i += 4) {
            std::array<std::uint8_t, 4> t{w_[i - 4], w_[i - 3], w_[i - 2], w_[i - 1]};
            if (i % KeyBytes == 0) {   // the position is public
                t = {static_cast<std::uint8_t>(aes_sbox(t[1]) ^ rcon), aes_sbox(t[2]), aes_sbox(t[3]), aes_sbox(t[0])};
                rcon = gf256_mul(rcon, 2);
            } else if (KeyBytes == 32 && i % KeyBytes == 16) {
                t = {aes_sbox(t[0]), aes_sbox(t[1]), aes_sbox(t[2]), aes_sbox(t[3])};
            }
            for (std::size_t j = 0; j < 4; ++j)
                w_[i + j] = static_cast<std::uint8_t>(w_[i - KeyBytes + j] ^ t[j]);
            secure_wipe(t);
        }
    }
    constexpr aes_cipher(const aes_cipher&) noexcept = default;
    constexpr aes_cipher& operator=(const aes_cipher&) noexcept = default;
    constexpr ~aes_cipher() { secure_wipe(w_); }

    [[nodiscard]] constexpr block encrypt(const block& in) const noexcept
    {
        block s = in;
        add_round_key(s, 0);
        for (std::size_t r = 1; r < rounds; ++r) {
            sub_bytes(s);
            shift_rows(s);
            mix_columns(s);
            add_round_key(s, r);
        }
        sub_bytes(s);
        shift_rows(s);
        add_round_key(s, rounds);
        return s;
    }

    [[nodiscard]] constexpr block decrypt(const block& in) const noexcept
    {
        block s = in;
        add_round_key(s, rounds);
        for (std::size_t r = rounds - 1; r > 0; --r) {
            inv_shift_rows(s);
            inv_sub_bytes(s);
            add_round_key(s, r);
            inv_mix_columns(s);
        }
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, 0);
        return s;
    }

private:
    constexpr void add_round_key(block& s, std::size_t r) const noexcept
    {
        for (std::size_t i = 0; i < 16; ++i)
            s[i] ^= w_[16 * r + i];
    }
    static constexpr void sub_bytes(block& s) noexcept
    {
        for (auto& b : s)
            b = aes_sbox(b);
    }
    static constexpr void inv_sub_bytes(block& s) noexcept
    {
        for (auto& b : s)
            b = aes_inv_sbox(b);
    }
    // the state is column-major: s[4 c + r]
    static constexpr void shift_rows(block& s) noexcept
    {
        const block t = s;
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                s[4 * c + r] = t[4 * ((c + r) % 4) + r];
    }
    static constexpr void inv_shift_rows(block& s) noexcept
    {
        const block t = s;
        for (std::size_t c = 0; c < 4; ++c)
            for (std::size_t r = 0; r < 4; ++r)
                s[4 * ((c + r) % 4) + r] = t[4 * c + r];
    }
    static constexpr void mix_columns(block& s) noexcept
    {
        for (std::size_t c = 0; c < 4; ++c) {
            const std::uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
            s[4 * c] = static_cast<std::uint8_t>(gf256_mul(a0, 2) ^ gf256_mul(a1, 3) ^ a2 ^ a3);
            s[4 * c + 1] = static_cast<std::uint8_t>(a0 ^ gf256_mul(a1, 2) ^ gf256_mul(a2, 3) ^ a3);
            s[4 * c + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gf256_mul(a2, 2) ^ gf256_mul(a3, 3));
            s[4 * c + 3] = static_cast<std::uint8_t>(gf256_mul(a0, 3) ^ a1 ^ a2 ^ gf256_mul(a3, 2));
        }
    }
    static constexpr void inv_mix_columns(block& s) noexcept
    {
        for (std::size_t c = 0; c < 4; ++c) {
            const std::uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
            s[4 * c] = static_cast<std::uint8_t>(gf256_mul(a0, 14) ^ gf256_mul(a1, 11) ^ gf256_mul(a2, 13) ^ gf256_mul(a3, 9));
            s[4 * c + 1] = static_cast<std::uint8_t>(gf256_mul(a0, 9) ^ gf256_mul(a1, 14) ^ gf256_mul(a2, 11) ^ gf256_mul(a3, 13));
            s[4 * c + 2] = static_cast<std::uint8_t>(gf256_mul(a0, 13) ^ gf256_mul(a1, 9) ^ gf256_mul(a2, 14) ^ gf256_mul(a3, 11));
            s[4 * c + 3] = static_cast<std::uint8_t>(gf256_mul(a0, 11) ^ gf256_mul(a1, 13) ^ gf256_mul(a2, 9) ^ gf256_mul(a3, 14));
        }
    }

    std::array<std::uint8_t, 16 * (rounds + 1)> w_{};
};

using aes128 = aes_cipher<16>;
using aes256 = aes_cipher<32>;

// GHASH's multiplication in GF(2^128) (NIST SP 800-38D, Algorithm 1), bit by bit with masks: constant time
constexpr std::array<std::uint8_t, 16> ghash_mul(const std::array<std::uint8_t, 16>& x, const std::array<std::uint8_t, 16>& y) noexcept
{
    std::uint64_t zh = 0, zl = 0;
    std::uint64_t vh = 0, vl = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        vh = vh << 8 | y[i];
        vl = vl << 8 | y[8 + i];
    }
    for (std::size_t i = 0; i < 128; ++i) {
        const std::uint64_t bit = (x[i / 8] >> (7 - i % 8)) & 1;
        const std::uint64_t m = 0 - bit;
        zh ^= vh & m;
        zl ^= vl & m;
        const std::uint64_t lsb = 0 - (vl & 1);
        vl = (vl >> 1) | (vh << 63);
        vh = (vh >> 1) ^ (lsb & 0xe100000000000000ull);
    }
    std::array<std::uint8_t, 16> out{};
    for (std::size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>(zh >> (56 - 8 * i));
        out[8 + i] = static_cast<std::uint8_t>(zl >> (56 - 8 * i));
    }
    return out;
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_aes_hpp */

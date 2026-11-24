//
//  poly1305.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Poly1305 (RFC 8439 section 2.5): the one-time authenticator, in radix 2^26 (five limbs, products in 64 bits, as
//  poly1305-donna-32).
//
//  Constant time: every block is processed the same way (the final partial block padded, its high bit set as data,
//  not by a branch on it), the final reduction modulo 2^130 - 5 is selected by a mask, and the key's r is clamped by
//  masking. The key and the accumulator are wiped. constexpr, no allocation.
//

#ifndef snicholls_crypto_detail_poly1305_hpp
#define snicholls_crypto_detail_poly1305_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/chacha20.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace snicholls::crypto::detail {

class poly1305 {
public:
    // A one-time key: r (clamped) then s
    constexpr explicit poly1305(std::span<const std::uint8_t, 32> key) noexcept
    {
        r_[0] = load32_le(key, 0) & 0x3ffffffu;
        r_[1] = (load32_le(key, 3) >> 2) & 0x3ffff03u;
        r_[2] = (load32_le(key, 6) >> 4) & 0x3ffc0ffu;
        r_[3] = (load32_le(key, 9) >> 6) & 0x3f03fffu;
        r_[4] = (load32_le(key, 12) >> 8) & 0x00fffffu;
        for (std::size_t i = 0; i < 4; ++i)
            pad_[i] = load32_le(key, 16 + 4 * i);
    }
    constexpr poly1305(const poly1305&) noexcept = default;
    constexpr poly1305& operator=(const poly1305&) noexcept = default;
    constexpr ~poly1305()
    {
        secure_wipe(r_);
        secure_wipe(h_);
        secure_wipe(pad_);
        secure_wipe(buf_);
    }

    constexpr void update(std::span<const std::uint8_t> m) noexcept
    {
        for (const auto b : m) {
            buf_[used_++] = b;
            if (used_ == 16) {
                block(buf_, 1);
                used_ = 0;
            }
        }
    }

    // The 16-byte tag; the object is spent
    constexpr std::array<std::uint8_t, 16> finish() noexcept
    {
        if (used_ != 0) {   // the length of the data is public: a partial last block
            buf_[used_] = 1;
            for (std::size_t i = used_ + 1; i < 16; ++i)
                buf_[i] = 0;
            block(buf_, 0);
        }
        // fully carry h
        std::uint32_t c = h_[1] >> 26;
        h_[1] &= 0x3ffffff;
        h_[2] += c;
        c = h_[2] >> 26;
        h_[2] &= 0x3ffffff;
        h_[3] += c;
        c = h_[3] >> 26;
        h_[3] &= 0x3ffffff;
        h_[4] += c;
        c = h_[4] >> 26;
        h_[4] &= 0x3ffffff;
        h_[0] += c * 5;
        c = h_[0] >> 26;
        h_[0] &= 0x3ffffff;
        h_[1] += c;
        // g = h + 5 - 2^130: take g when it does not borrow, by mask
        std::array<std::uint32_t, 5> g{};
        g[0] = h_[0] + 5;
        c = g[0] >> 26;
        g[0] &= 0x3ffffff;
        g[1] = h_[1] + c;
        c = g[1] >> 26;
        g[1] &= 0x3ffffff;
        g[2] = h_[2] + c;
        c = g[2] >> 26;
        g[2] &= 0x3ffffff;
        g[3] = h_[3] + c;
        c = g[3] >> 26;
        g[3] &= 0x3ffffff;
        g[4] = h_[4] + c - (1u << 26);
        // all ones when g >= 0; through ct's barrier and select, so no compiler turns the choice into a branch
        const std::uint64_t mask = ct::mask_from_bit((g[4] >> 31) ^ 1);
        for (std::size_t i = 0; i < 5; ++i)
            h_[i] = static_cast<std::uint32_t>(ct::select(mask, g[i], h_[i]));
        // h mod 2^128, plus s
        const std::uint32_t w0 = h_[0] | (h_[1] << 26);
        const std::uint32_t w1 = (h_[1] >> 6) | (h_[2] << 20);
        const std::uint32_t w2 = (h_[2] >> 12) | (h_[3] << 14);
        const std::uint32_t w3 = (h_[3] >> 18) | (h_[4] << 8);
        std::uint64_t f = static_cast<std::uint64_t>(w0) + pad_[0];
        std::array<std::uint8_t, 16> tag{};
        store32_le(tag, 0, static_cast<std::uint32_t>(f));
        f = static_cast<std::uint64_t>(w1) + pad_[1] + (f >> 32);
        store32_le(tag, 4, static_cast<std::uint32_t>(f));
        f = static_cast<std::uint64_t>(w2) + pad_[2] + (f >> 32);
        store32_le(tag, 8, static_cast<std::uint32_t>(f));
        f = static_cast<std::uint64_t>(w3) + pad_[3] + (f >> 32);
        store32_le(tag, 12, static_cast<std::uint32_t>(f));
        secure_wipe(g);
        return tag;
    }

private:
    // h = (h + block) r mod 2^130 - 5; hibit 1 for a full block (2^128 added), 0 for the padded last block
    constexpr void block(const std::array<std::uint8_t, 16>& m, std::uint32_t hibit) noexcept
    {
        const std::uint32_t r0 = r_[0], r1 = r_[1], r2 = r_[2], r3 = r_[3], r4 = r_[4];
        const std::uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        std::uint32_t h0 = h_[0] + (load32_le(m, 0) & 0x3ffffff);
        std::uint32_t h1 = h_[1] + ((load32_le(m, 3) >> 2) & 0x3ffffff);
        std::uint32_t h2 = h_[2] + ((load32_le(m, 6) >> 4) & 0x3ffffff);
        std::uint32_t h3 = h_[3] + ((load32_le(m, 9) >> 6) & 0x3ffffff);
        std::uint32_t h4 = h_[4] + ((load32_le(m, 12) >> 8) | (hibit << 24));
        using u64 = std::uint64_t;
        const u64 d0 = u64(h0) * r0 + u64(h1) * s4 + u64(h2) * s3 + u64(h3) * s2 + u64(h4) * s1;
        u64 d1 = u64(h0) * r1 + u64(h1) * r0 + u64(h2) * s4 + u64(h3) * s3 + u64(h4) * s2;
        u64 d2 = u64(h0) * r2 + u64(h1) * r1 + u64(h2) * r0 + u64(h3) * s4 + u64(h4) * s3;
        u64 d3 = u64(h0) * r3 + u64(h1) * r2 + u64(h2) * r1 + u64(h3) * r0 + u64(h4) * s4;
        u64 d4 = u64(h0) * r4 + u64(h1) * r3 + u64(h2) * r2 + u64(h3) * r1 + u64(h4) * r0;
        std::uint32_t c = static_cast<std::uint32_t>(d0 >> 26);
        h0 = static_cast<std::uint32_t>(d0) & 0x3ffffff;
        d1 += c;
        c = static_cast<std::uint32_t>(d1 >> 26);
        h1 = static_cast<std::uint32_t>(d1) & 0x3ffffff;
        d2 += c;
        c = static_cast<std::uint32_t>(d2 >> 26);
        h2 = static_cast<std::uint32_t>(d2) & 0x3ffffff;
        d3 += c;
        c = static_cast<std::uint32_t>(d3 >> 26);
        h3 = static_cast<std::uint32_t>(d3) & 0x3ffffff;
        d4 += c;
        c = static_cast<std::uint32_t>(d4 >> 26);
        h4 = static_cast<std::uint32_t>(d4) & 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;
        h_ = {h0, h1, h2, h3, h4};
    }

    std::array<std::uint32_t, 5> r_{};
    std::array<std::uint32_t, 5> h_{};
    std::array<std::uint32_t, 4> pad_{};
    std::array<std::uint8_t, 16> buf_{};
    std::size_t used_ = 0;
};

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_poly1305_hpp */

//
//  hashes.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  INTERIM. SHA-256, SHA-512, HMAC, PBKDF2-HMAC-SHA512 and RIPEMD-160, written here only until snicholls-core
//  provides them: by the family's placement rules every constexpr hash, MAC and KDF belongs to core, and core's
//  are being written for its 0.17.0 release. When crypto pins that release, this file becomes a set of aliases of
//  core's (or is deleted and its callers switched), in one commit, with the same tests passing. Nothing outside
//  snicholls::crypto may use it. RIPEMD-160 is proposed to core as well (BIP-32 fingerprints need HASH160).
//
//  All of it is constexpr, allocation-free and streaming, and every state that may hold key material (an HMAC key,
//  a PBKDF2 password) is wiped when it dies. The compression functions have no data-dependent branches or indices.
//

#ifndef snicholls_crypto_detail_hashes_hpp
#define snicholls_crypto_detail_hashes_hpp

#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace snicholls::crypto::detail {

constexpr std::uint32_t rotr32(std::uint32_t x, int n) noexcept { return (x >> n) | (x << (32 - n)); }
constexpr std::uint32_t rotl32(std::uint32_t x, int n) noexcept { return (x << n) | (x >> (32 - n)); }
constexpr std::uint64_t rotr64(std::uint64_t x, int n) noexcept { return (x >> n) | (x << (64 - n)); }

// A string literal's characters as bytes, for keys and salts given as text ("Bitcoin seed", "mnemonic")
inline std::span<const std::uint8_t> text_bytes(std::string_view s) noexcept
{
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// The Merkle-Damgard skeleton every hash here shares: a block buffer, a length, and the algorithm's compress().
// Word is the type of the length counter's unit (bytes are counted in a 64-bit counter, enough for 2^61 bytes).
template <class Derived, std::size_t Block, std::size_t Digest>
class md_hash {
public:
    static constexpr std::size_t block_size = Block;
    static constexpr std::size_t digest_size = Digest;
    using digest_type = std::array<std::uint8_t, Digest>;

    constexpr void update(std::span<const std::uint8_t> data) noexcept
    {
        for (const std::uint8_t b : data) {
            buffer_[used_++] = b;
            if (used_ == Block) {
                static_cast<Derived*>(this)->compress(buffer_.data());
                used_ = 0;
            }
        }
        length_ += data.size();
    }
    constexpr void update(std::string_view s) noexcept
    {
        for (const char c : s) {
            const auto b = static_cast<std::uint8_t>(c);
            update(std::span<const std::uint8_t>(&b, 1));
        }
    }

    constexpr ~md_hash() { secure_wipe(buffer_); }

protected:
    constexpr md_hash() noexcept = default;
    constexpr md_hash(const md_hash&) noexcept = default;
    constexpr md_hash& operator=(const md_hash&) noexcept = default;

    // Pads with 0x80, zeros and the bit length (big-endian unless little_endian_length), Length bytes of it
    template <std::size_t Length, bool LittleEndianLength = false>
    constexpr void pad() noexcept
    {
        const std::uint64_t bits = length_ * 8;
        const std::uint8_t one = 0x80;
        const std::uint8_t zero = 0;
        const std::size_t keep = length_;
        update(std::span<const std::uint8_t>(&one, 1));
        while (used_ != Block - Length)
            update(std::span<const std::uint8_t>(&zero, 1));
        for (std::size_t i = 0; i < Length; ++i) {
            const std::size_t shift = LittleEndianLength ? 8 * i : 8 * (Length - 1 - i);
            const auto b = static_cast<std::uint8_t>(shift < 64 ? (bits >> shift) & 0xff : 0);
            update(std::span<const std::uint8_t>(&b, 1));
        }
        length_ = keep;
    }

    std::array<std::uint8_t, Block> buffer_{};
    std::size_t used_ = 0;
    std::uint64_t length_ = 0;
};

class sha256 : public md_hash<sha256, 64, 32> {
public:
    constexpr sha256() noexcept = default;
    constexpr sha256(const sha256&) noexcept = default;
    constexpr sha256& operator=(const sha256&) noexcept = default;
    constexpr ~sha256() { secure_wipe(h_); }

    constexpr digest_type finish() noexcept
    {
        pad<8>();
        digest_type out{};
        for (std::size_t i = 0; i < 8; ++i)
            for (std::size_t j = 0; j < 4; ++j)
                out[4 * i + j] = static_cast<std::uint8_t>(h_[i] >> (24 - 8 * j));
        return out;
    }

    static constexpr digest_type hash(std::span<const std::uint8_t> data) noexcept
    {
        sha256 h;
        h.update(data);
        return h.finish();
    }

    constexpr void compress(const std::uint8_t* p) noexcept
    {
        constexpr std::uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        std::array<std::uint32_t, 64> w{};
        for (int i = 0; i < 16; ++i)
            w[i] = (std::uint32_t{p[4 * i]} << 24) | (std::uint32_t{p[4 * i + 1]} << 16) | (std::uint32_t{p[4 * i + 2]} << 8) |
                   std::uint32_t{p[4 * i + 3]};
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t t1 = h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
            const std::uint32_t t2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
        secure_wipe(w);
    }

private:
    std::array<std::uint32_t, 8> h_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
};

class sha512 : public md_hash<sha512, 128, 64> {
public:
    constexpr sha512() noexcept = default;
    constexpr sha512(const sha512&) noexcept = default;
    constexpr sha512& operator=(const sha512&) noexcept = default;
    constexpr ~sha512() { secure_wipe(h_); }

    constexpr digest_type finish() noexcept
    {
        pad<16>();
        digest_type out{};
        for (std::size_t i = 0; i < 8; ++i)
            for (std::size_t j = 0; j < 8; ++j)
                out[8 * i + j] = static_cast<std::uint8_t>(h_[i] >> (56 - 8 * j));
        return out;
    }

    static constexpr digest_type hash(std::span<const std::uint8_t> data) noexcept
    {
        sha512 h;
        h.update(data);
        return h.finish();
    }

    constexpr void compress(const std::uint8_t* p) noexcept
    {
        constexpr std::uint64_t k[80] = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
        std::array<std::uint64_t, 80> w{};
        for (int i = 0; i < 16; ++i) {
            std::uint64_t x = 0;
            for (int j = 0; j < 8; ++j)
                x = (x << 8) | p[8 * i + j];
            w[i] = x;
        }
        for (int i = 16; i < 80; ++i) {
            const std::uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            const std::uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 80; ++i) {
            const std::uint64_t t1 = h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
            const std::uint64_t t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
        secure_wipe(w);
    }

private:
    std::array<std::uint64_t, 8> h_{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
};

class ripemd160 : public md_hash<ripemd160, 64, 20> {
public:
    constexpr ripemd160() noexcept = default;

    constexpr digest_type finish() noexcept
    {
        pad<8, true>();
        digest_type out{};
        for (std::size_t i = 0; i < 5; ++i)
            for (std::size_t j = 0; j < 4; ++j)
                out[4 * i + j] = static_cast<std::uint8_t>(h_[i] >> (8 * j));
        return out;
    }

    static constexpr digest_type hash(std::span<const std::uint8_t> data) noexcept
    {
        ripemd160 h;
        h.update(data);
        return h.finish();
    }

    constexpr void compress(const std::uint8_t* p) noexcept
    {
        constexpr int rl[80] = {0, 1, 2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 7,  4,  13, 1,
                                10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1,
                                2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15,
                                14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
        constexpr int rr[80] = {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7,
                                0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9,
                                11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13,
                                9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
        constexpr int sl[80] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13,
                                11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15,
                                14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6,
                                8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
        constexpr int sr[80] = {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7,
                                12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14,
                                12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9,
                                12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};
        constexpr std::uint32_t kl[5] = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
        constexpr std::uint32_t kr[5] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};
        std::uint32_t x[16]{};
        for (int i = 0; i < 16; ++i)
            x[i] = std::uint32_t{p[4 * i]} | (std::uint32_t{p[4 * i + 1]} << 8) | (std::uint32_t{p[4 * i + 2]} << 16) |
                   (std::uint32_t{p[4 * i + 3]} << 24);
        auto f = [](int j, std::uint32_t a, std::uint32_t b, std::uint32_t c) -> std::uint32_t {
            switch (j / 16) {   // the round number, public: never data
            case 0: return a ^ b ^ c;
            case 1: return (a & b) | (~a & c);
            case 2: return (a | ~b) ^ c;
            case 3: return (a & c) | (b & ~c);
            default: return a ^ (b | ~c);
            }
        };
        std::uint32_t al = h_[0], bl = h_[1], cl = h_[2], dl = h_[3], el = h_[4];
        std::uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;
        for (int j = 0; j < 80; ++j) {
            std::uint32_t t = rotl32(al + f(j, bl, cl, dl) + x[rl[j]] + kl[j / 16], sl[j]) + el;
            al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = t;
            t = rotl32(ar + f(79 - j, br, cr, dr) + x[rr[j]] + kr[j / 16], sr[j]) + er;
            ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = t;
        }
        const std::uint32_t t = h_[1] + cl + dr;
        h_[1] = h_[2] + dl + er;
        h_[2] = h_[3] + el + ar;
        h_[3] = h_[4] + al + br;
        h_[4] = h_[0] + bl + cr;
        h_[0] = t;
    }

private:
    std::array<std::uint32_t, 5> h_{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
};

// HASH160 = RIPEMD-160(SHA-256(x)): BIP-32 key identifiers and fingerprints
constexpr std::array<std::uint8_t, 20> hash160(std::span<const std::uint8_t> data) noexcept
{
    const auto s = sha256::hash(data);
    return ripemd160::hash(s);
}

// HMAC (RFC 2104) over any hash above, streaming. The key is absorbed at construction and wiped with the object.
template <class H>
class hmac {
public:
    static constexpr std::size_t digest_size = H::digest_size;
    using digest_type = typename H::digest_type;

    constexpr explicit hmac(std::span<const std::uint8_t> key) noexcept
    {
        std::array<std::uint8_t, H::block_size> k{};
        if (key.size() > H::block_size) {
            const auto d = H::hash(key);
            for (std::size_t i = 0; i < d.size(); ++i)
                k[i] = d[i];
        } else {
            for (std::size_t i = 0; i < key.size(); ++i)
                k[i] = key[i];
        }
        std::array<std::uint8_t, H::block_size> pad{};
        for (std::size_t i = 0; i < pad.size(); ++i)
            pad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36);
        inner_.update(pad);
        for (std::size_t i = 0; i < pad.size(); ++i)
            pad[i] = static_cast<std::uint8_t>(k[i] ^ 0x5c);
        outer_.update(pad);
        secure_wipe(k);
        secure_wipe(pad);
    }

    constexpr void update(std::span<const std::uint8_t> data) noexcept { inner_.update(data); }

    constexpr digest_type finish() noexcept
    {
        auto d = inner_.finish();
        outer_.update(d);
        secure_wipe(d);
        return outer_.finish();
    }

    static constexpr digest_type mac(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) noexcept
    {
        hmac m(key);
        m.update(data);
        return m.finish();
    }

private:
    H inner_;
    H outer_;
};

using hmac_sha256 = hmac<sha256>;
using hmac_sha512 = hmac<sha512>;

// PBKDF2 (RFC 8018) with HMAC-SHA512, writing out.size() bytes. iterations >= 1.
constexpr void pbkdf2_hmac_sha512(std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt,
                                  std::uint32_t iterations, std::span<std::uint8_t> out) noexcept
{
    const hmac_sha512 keyed(password);   // the password absorbed once, copied per block
    std::uint32_t block = 1;
    for (std::size_t done = 0; done < out.size(); ++block) {
        hmac_sha512 m = keyed;
        m.update(salt);
        const std::uint8_t be[4] = {static_cast<std::uint8_t>(block >> 24), static_cast<std::uint8_t>(block >> 16),
                                    static_cast<std::uint8_t>(block >> 8), static_cast<std::uint8_t>(block)};
        m.update(be);
        auto u = m.finish();
        auto t = u;
        for (std::uint32_t i = 1; i < iterations; ++i) {
            hmac_sha512 mi = keyed;
            mi.update(u);
            u = mi.finish();
            for (std::size_t j = 0; j < t.size(); ++j)
                t[j] ^= u[j];
        }
        for (std::size_t j = 0; j < t.size() && done < out.size(); ++j)
            out[done++] = t[j];
        secure_wipe(u);
        secure_wipe(t);
    }
}

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_hashes_hpp */

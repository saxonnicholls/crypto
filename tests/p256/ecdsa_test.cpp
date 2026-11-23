//
//  ecdsa_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/p256/ecdsa.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <optional>
#include <string>

using namespace snicholls::crypto::p256;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
// RFC 6979 appendix A.2.5: P-256, its key and public key
constexpr auto rfc_key = hex<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
constexpr auto rfc_ux = hex<32>("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
constexpr auto rfc_uy = hex<32>("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");

std::array<std::uint8_t, 32> n_minus(const std::array<std::uint8_t, 32>& n, const std::array<std::uint8_t, 32>& s)
{
    std::array<std::uint8_t, 32> out{};
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        const int d = n[i] - s[i] - borrow;
        borrow = d < 0;
        out[i] = static_cast<std::uint8_t>(d + (borrow ? 256 : 0));
    }
    return out;
}

constexpr std::array<std::uint8_t, 32> sha256_of(std::string_view s)
{
    snicholls::crypto::detail::sha256 h;
    h.update(s);
    return h.finish();
}
} // namespace

// RFC 6979 A.2.5 with SHA-256, at compile time: the public key and the "sample" signature byte for byte
static_assert(private_key::from_bytes(rfc_key).unwrap().public_key().point().x.to_bytes() == rfc_ux);
static_assert(sign(private_key::from_bytes(rfc_key).unwrap(), sha256_of("sample")).r ==
              hex<32>("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"));

TEST(CryptoP256Ecdsa, Rfc6979AppendixA25Sha256)
{
    const auto key = private_key::from_bytes(rfc_key).unwrap();
    const auto pub = key.public_key();
    EXPECT_EQ(pub.point().x.to_bytes(), rfc_ux);
    EXPECT_EQ(pub.point().y.to_bytes(), rfc_uy);
    const auto sample = sign(key, sha256_of("sample"));
    EXPECT_EQ(to_hex(sample.r), "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    EXPECT_EQ(to_hex(sample.s), "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    const auto test = sign(key, sha256_of("test"));
    EXPECT_EQ(to_hex(test.r), "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367");
    EXPECT_EQ(to_hex(test.s), "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083");
    EXPECT_TRUE(verify(pub, sha256_of("sample"), sample));
    EXPECT_TRUE(verify(pub, sha256_of("test"), test));
    EXPECT_FALSE(verify(pub, sha256_of("test"), sample));
}

namespace {
struct counts {
    int valid = 0, invalid = 0;
};

// Every case of a Wycheproof P-256 file: DER signatures, or P1363's r || s (where only 64 bytes can be a signature)
counts wycheproof(const std::string& name, bool p1363)
{
    counts c;
    std::optional<public_key> key;
    for (const auto& f : read_fixture("wycheproof/" + name)) {
        if (f[0] == "key") {
            const auto k = hex_bytes(f[2]);
            key = public_key::parse(k).unwrap();
            continue;
        }
        const auto msg = hex_bytes(f[2]), sig = hex_bytes(f[3]);
        snicholls::crypto::detail::sha256 h;
        h.update(std::span<const std::uint8_t>(msg.data(), msg.size()));
        const auto hash = h.finish();
        bool ok = false;
        if (p1363) {
            if (sig.size() == 64)
                ok = static_cast<bool>(verify(*key, hash, signature::from_jose(std::span<const std::uint8_t, 64>(sig.data(), 64))));
        } else if (const auto s = signature::from_der(sig)) {
            ok = static_cast<bool>(verify(*key, hash, *s));
        }
        EXPECT_EQ(ok, f[1] == "valid") << name << " tcId " << f[0];
        (f[1] == "valid" ? c.valid : c.invalid) += 1;
    }
    return c;
}
} // namespace

TEST(CryptoP256Wycheproof, Sha256DerAndP1363)
{
    const auto der = wycheproof("ecdsa_p256_sha256.txt", false);
    const auto p1363 = wycheproof("ecdsa_p256_sha256_p1363.txt", true);
    EXPECT_GT(der.valid, 0);
    EXPECT_GT(der.invalid, 0);
    EXPECT_GT(p1363.valid, 0);
    // 597 and 374 fixture lines, less one key line per group
    EXPECT_GT(der.valid + der.invalid, 450);
    EXPECT_GT(p1363.valid + p1363.invalid, 250);
}

TEST(CryptoP256Keys, RangeEncodingAndRoundTrips)
{
    const auto n = scalar::order_bytes();
    EXPECT_EQ(private_key::from_bytes(n).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(private_key::from_bytes(std::array<std::uint8_t, 32>{}).unwrap_err(), errc::invalid_private_key);
    auto n_minus_1 = n;
    n_minus_1[31] -= 1;
    const auto top = private_key::from_bytes(n_minus_1).unwrap();
    // (n - 1) G = -G
    const auto g = point::base().to_affine().value();
    EXPECT_EQ(top.public_key().point().x, g.x);
    EXPECT_EQ(top.public_key().point().y, -g.y);
    const auto pub = private_key::from_bytes(rfc_key).unwrap().public_key();
    EXPECT_EQ(public_key::parse(pub.compressed()).unwrap(), pub);
    EXPECT_EQ(public_key::parse(pub.uncompressed()).unwrap(), pub);
    auto off = pub.uncompressed();
    off[64] ^= 1;
    EXPECT_EQ(public_key::parse(off).unwrap_err(), errc::invalid_public_key);
    auto hybrid = pub.uncompressed();
    hybrid[0] = 0x06;
    EXPECT_FALSE(public_key::parse(hybrid));
    EXPECT_FALSE(public_key::parse(std::array<std::uint8_t, 1>{0x00}));
    std::array<std::uint8_t, 33> x_is_p{0x02};
    const auto p = hex<32>("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    std::copy(p.begin(), p.end(), x_is_p.begin() + 1);
    EXPECT_FALSE(public_key::parse(x_is_p));
}

TEST(CryptoP256Signatures, RangesJoseAndDer)
{
    const auto key = private_key::from_bytes(rfc_key).unwrap();
    const auto pub = key.public_key();
    const auto h = sha256_of("sample");
    const auto sig = sign(key, h);
    EXPECT_EQ(signature::from_jose(sig.jose()), sig);
    const auto der = sig.der();
    EXPECT_EQ(signature::from_der(std::span<const std::uint8_t>(der.data(), der.size())).unwrap(), sig);
    // s and n - s both verify (ES256 does not require low-S)
    auto other = sig;
    const auto n = scalar::order_bytes();
    other.s = (scalar::from_bytes(n_minus(n, sig.s)).value()).to_bytes();
    EXPECT_TRUE(verify(pub, h, other));
    signature zero = sig;
    zero.r = {};
    EXPECT_EQ(verify(pub, h, zero).unwrap_err(), errc::invalid_signature);
    signature big = sig;
    big.s = n;
    EXPECT_EQ(verify(pub, h, big).unwrap_err(), errc::invalid_signature);
}

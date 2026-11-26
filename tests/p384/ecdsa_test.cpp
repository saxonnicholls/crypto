//
//  ecdsa_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/p384/ecdsa.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <optional>
#include <string>

using namespace snicholls::crypto::p384;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
// RFC 6979 appendix A.2.6: P-384, its key and public key
constexpr auto rfc_key = hex<48>("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5");
constexpr auto rfc_ux = hex<48>("ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13");
constexpr auto rfc_uy = hex<48>("8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720");
// ... and its SHA-384 signature of "sample"
constexpr auto sample_r = hex<48>("94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46");
constexpr auto sample_s = hex<48>("99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8");

std::array<std::uint8_t, 48> sha384_of(std::string_view s)
{
    snicholls::crypto::detail::sha384 h;
    h.update(s);
    return h.finish();
}

std::array<std::uint8_t, 48> n_minus(const std::array<std::uint8_t, 48>& n, const std::array<std::uint8_t, 48>& s)
{
    std::array<std::uint8_t, 48> out{};
    int borrow = 0;
    for (int i = 47; i >= 0; --i) {
        const int d = n[i] - s[i] - borrow;
        borrow = d < 0;
        out[i] = static_cast<std::uint8_t>(d + (borrow ? 256 : 0));
    }
    return out;
}
} // namespace

TEST(CryptoP384Ecdsa, Rfc6979AppendixA26Sha384)
{
    const auto key = private_key::from_bytes(rfc_key).unwrap();
    const auto pub = key.public_key();
    EXPECT_EQ(pub.point().x.to_bytes(), rfc_ux);
    EXPECT_EQ(pub.point().y.to_bytes(), rfc_uy);
    const signature sample{sample_r, sample_s};
    EXPECT_TRUE(verify(pub, sha384_of("sample"), sample));
    const std::string_view text = "sample";
    EXPECT_TRUE(verify_message(pub, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()), sample));
    EXPECT_FALSE(verify(pub, sha384_of("test"), sample));
    // s and n - s both verify (ES384 does not require low-S); r = 0 and s = n do not
    auto other = sample;
    other.s = n_minus(scalar::order_bytes(), sample.s);
    EXPECT_TRUE(verify(pub, sha384_of("sample"), other));
    auto zero = sample;
    zero.r = {};
    EXPECT_EQ(verify(pub, sha384_of("sample"), zero).unwrap_err(), errc::invalid_signature);
    auto big = sample;
    big.s = scalar::order_bytes();
    EXPECT_EQ(verify(pub, sha384_of("sample"), big).unwrap_err(), errc::invalid_signature);
    // JOSE and DER round trips
    EXPECT_EQ(signature::from_jose(sample.jose()), sample);
    const auto der = sample.der();
    EXPECT_EQ(signature::from_der(std::span<const std::uint8_t>(der.data(), der.size())).unwrap(), sample);
    EXPECT_EQ(der.size(), 104u);   // both integers have their top bit set: a zero byte each
}

namespace {
struct counts {
    int valid = 0, invalid = 0;
};

// Every case of a Wycheproof P-384 file: DER signatures, or P1363's r || s (where only 96 bytes can be a signature)
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
        const std::span<const std::uint8_t> m(msg.data(), msg.size());
        bool ok = false;
        if (p1363) {
            if (sig.size() == 96)
                ok = static_cast<bool>(verify_message(*key, m, signature::from_jose(std::span<const std::uint8_t, 96>(sig.data(), 96))));
        } else if (const auto s = signature::from_der(sig)) {
            ok = static_cast<bool>(verify_message(*key, m, *s));
        }
        EXPECT_EQ(ok, f[1] == "valid") << name << " tcId " << f[0];
        (f[1] == "valid" ? c.valid : c.invalid) += 1;
    }
    return c;
}
} // namespace

TEST(CryptoP384Wycheproof, Sha384DerAndP1363)
{
    const auto der = wycheproof("ecdsa_p384_sha384.txt", false);
    const auto p1363 = wycheproof("ecdsa_p384_sha384_p1363.txt", true);
    EXPECT_GT(der.valid, 0);
    EXPECT_GT(der.invalid, 0);
    EXPECT_GT(p1363.valid, 0);
    // 609 and 384 fixture lines, less one key line per group
    EXPECT_GT(der.valid + der.invalid, 450);
    EXPECT_GT(p1363.valid + p1363.invalid, 250);
}

TEST(CryptoP384Keys, RangeEncodingAndRoundTrips)
{
    const auto n = scalar::order_bytes();
    EXPECT_EQ(private_key::from_bytes(n).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(private_key::from_bytes(std::array<std::uint8_t, 48>{}).unwrap_err(), errc::invalid_private_key);
    auto n_minus_1 = n;
    n_minus_1[47] -= 1;
    const auto top = private_key::from_bytes(n_minus_1).unwrap();
    // (n - 1) G = -G
    const auto g = point::base().to_affine().value();
    EXPECT_EQ(top.public_key().point().x, g.x);
    EXPECT_EQ(top.public_key().point().y, -g.y);
    const auto pub = private_key::from_bytes(rfc_key).unwrap().public_key();
    EXPECT_EQ(public_key::parse(pub.compressed()).unwrap(), pub);
    EXPECT_EQ(public_key::parse(pub.uncompressed()).unwrap(), pub);
    auto off = pub.uncompressed();
    off[96] ^= 1;
    EXPECT_EQ(public_key::parse(off).unwrap_err(), errc::invalid_public_key);
    auto hybrid = pub.uncompressed();
    hybrid[0] = 0x06;
    EXPECT_FALSE(public_key::parse(hybrid));
    EXPECT_FALSE(public_key::parse(std::array<std::uint8_t, 1>{0x00}));
    std::array<std::uint8_t, 49> x_is_p{0x02};
    const auto p = hex<48>("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
    std::copy(p.begin(), p.end(), x_is_p.begin() + 1);
    EXPECT_FALSE(public_key::parse(x_is_p));
    EXPECT_EQ(top.clone().reveal()[47], n_minus_1[47]);
}

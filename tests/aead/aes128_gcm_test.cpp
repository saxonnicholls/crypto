//
//  aes128_gcm_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/aead/aes128_gcm.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace snicholls::crypto::aead;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) { return {v.data(), v.size()}; }

// The GCM specification's test case 2, at compile time: E(0^128) under the zero key, and its tag
constexpr bool test_case_2()
{
    const std::array<std::uint8_t, 16> key{}, pt{};
    const std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 16> ct{};
    const auto t = aes128_gcm_seal(key, nonce, {}, pt, ct).unwrap();
    return ct == hex<16>("0388dace60b6a392f328c2b971b2fe78") && t == hex<16>("ab6e47d42cec13bdf53a67b21257bddf");
}
} // namespace

// FIPS 197 appendix C.1 (AES-128), both ways, and GCM test case 2, at compile time
static_assert(snicholls::crypto::detail::aes128(hex<16>("000102030405060708090a0b0c0d0e0f")).encrypt(hex<16>("00112233445566778899aabbccddeeff")) ==
              hex<16>("69c4e0d86a7b0430d8cdb78070b4c55a"));
static_assert(snicholls::crypto::detail::aes128(hex<16>("000102030405060708090a0b0c0d0e0f")).decrypt(hex<16>("69c4e0d86a7b0430d8cdb78070b4c55a")) ==
              hex<16>("00112233445566778899aabbccddeeff"));
static_assert(test_case_2());

TEST(CryptoAeadAes128Gcm, GcmSpecificationTestCases1To4)
{
    std::vector<std::uint8_t> none;
    EXPECT_EQ(to_hex(aes128_gcm_seal(hex<16>("00000000000000000000000000000000"), hex<12>("000000000000000000000000"), {}, {}, none).unwrap()),
              "58e2fccefa7e3061367f1d57a4e7455a");
    const auto key = hex<16>("feffe9928665731c6d6a8f9467308308");
    const auto nonce = hex<12>("cafebabefacedbaddecaf888");
    const auto p64 = hex_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    auto buf = p64;
    const auto t3 = aes128_gcm_seal(key, nonce, {}, view(buf), buf).unwrap();   // in place
    EXPECT_EQ(to_hex(view(buf)), "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
    EXPECT_EQ(to_hex(t3), "4d5c2af327cd64a62cf35abd2ba6fab4");
    EXPECT_TRUE(aes128_gcm_open(key, nonce, {}, view(buf), t3, buf));
    EXPECT_EQ(buf, p64);

    const std::vector<std::uint8_t> p60(p64.begin(), p64.begin() + 60);
    const auto aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    std::vector<std::uint8_t> c60(60);
    const auto t4 = aes128_gcm_seal(key, nonce, view(aad), view(p60), c60).unwrap();
    EXPECT_EQ(to_hex(view(c60)), "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
    EXPECT_EQ(to_hex(t4), "5bc94fbc3221a5db94fae95ae7121a47");
    auto bad = t4;
    bad[15] ^= 0x80;
    std::vector<std::uint8_t> out(60, 0xaa);
    EXPECT_EQ(aes128_gcm_open(key, nonce, view(aad), view(c60), bad, out).unwrap_err(), errc::authentication_failed);
    EXPECT_EQ(out, std::vector<std::uint8_t>(60, 0));
    EXPECT_EQ(aes128_gcm_seal(key, nonce, {}, view(p60), out = std::vector<std::uint8_t>(59)).unwrap_err(), errc::invalid_length);
}

TEST(CryptoAeadWycheproof, Aes128Gcm96BitNonces)
{
    int valid = 0, invalid = 0, not_offered = 0;
    for (const auto& f : read_fixture("wycheproof/aes128_gcm.txt")) {
        ASSERT_EQ(f.size(), 8u) << "a short fixture line, tcId " << f[0];
        const auto iv = hex_bytes(f[2]), key = hex_bytes(f[3]), aad = hex_bytes(f[4]), msg = hex_bytes(f[5]), ct = hex_bytes(f[6]), tg = hex_bytes(f[7]);
        if (iv.size() != 12) {   // other nonce lengths are not offered by this API
            ++not_offered;
            continue;
        }
        const std::span<const std::uint8_t, 16> k(key.data(), 16);
        const std::span<const std::uint8_t, 12> n(iv.data(), 12);
        std::vector<std::uint8_t> out(ct.size());
        const bool opened = static_cast<bool>(aes128_gcm_open(k, n, view(aad), view(ct), std::span<const std::uint8_t, 16>(tg.data(), 16), out));
        EXPECT_EQ(opened, f[1] == "valid") << "tcId " << f[0];
        if (f[1] == "valid") {
            EXPECT_EQ(out, msg) << "tcId " << f[0];
            std::vector<std::uint8_t> sealed(msg.size());
            EXPECT_EQ(to_hex(aes128_gcm_seal(k, n, view(aad), view(msg), sealed).unwrap()), f[7]) << "tcId " << f[0];
            EXPECT_EQ(sealed, ct) << "tcId " << f[0];
            ++valid;
        } else {
            ++invalid;
        }
    }
    EXPECT_GT(valid, 20);
    EXPECT_GT(invalid, 10);
    EXPECT_EQ(valid + invalid + not_offered, 108);
}

//
//  aes256_gcm_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/aead/aes256_gcm.hpp>
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
}

// FIPS 197 appendix C.3 (AES-256) and the GCM specification's test case 13, at compile time
static_assert(snicholls::crypto::detail::aes256(hex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
                  .encrypt(hex<16>("00112233445566778899aabbccddeeff")) == hex<16>("8ea2b7ca516745bfeafc49904b496089"));
static_assert(snicholls::crypto::detail::aes256(hex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
                  .decrypt(hex<16>("8ea2b7ca516745bfeafc49904b496089")) == hex<16>("00112233445566778899aabbccddeeff"));

TEST(CryptoAeadAes256Gcm, GcmSpecificationTestCases13And15)
{
    std::vector<std::uint8_t> none;
    const auto t13 = aes256_gcm_seal(hex<32>("0000000000000000000000000000000000000000000000000000000000000000"), hex<12>("000000000000000000000000"),
                                     {}, {}, none).unwrap();
    EXPECT_EQ(to_hex(t13), "530f8afbc74536b9a963b4f1c4cb738b");
    const auto key = hex<32>("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const auto nonce = hex<12>("cafebabefacedbaddecaf888");
    auto buf = hex_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    const auto pt = buf;
    const auto t15 = aes256_gcm_seal(key, nonce, {}, view(buf), buf).unwrap();   // in place
    EXPECT_EQ(to_hex(view(buf)), "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
    EXPECT_EQ(to_hex(t15), "b094dac5d93471bdec1a502270e3cc6c");
    EXPECT_TRUE(aes256_gcm_open(key, nonce, {}, view(buf), t15, buf));
    EXPECT_EQ(buf, pt);
    auto bad = t15;
    bad[0] ^= 1;
    std::vector<std::uint8_t> out(pt.size(), 0xaa);
    EXPECT_EQ(aes256_gcm_open(key, nonce, {}, view(pt), bad, out).unwrap_err(), errc::authentication_failed);
    EXPECT_EQ(out, std::vector<std::uint8_t>(pt.size(), 0));
}

TEST(CryptoAeadWycheproof, Aes256Gcm96BitNonces)
{
    int valid = 0, invalid = 0, not_offered = 0;
    for (const auto& f : read_fixture("wycheproof/aes256_gcm.txt")) {
        const auto iv = hex_bytes(f[2]), key = hex_bytes(f[3]), aad = hex_bytes(f[4]), msg = hex_bytes(f[5]), ct = hex_bytes(f[6]), tg = hex_bytes(f[7]);
        if (iv.size() != 12) {   // GCM with other nonce lengths is not offered by this API
            ++not_offered;
            continue;
        }
        const std::span<const std::uint8_t, 32> k(key.data(), 32);
        const std::span<const std::uint8_t, 12> n(iv.data(), 12);
        std::vector<std::uint8_t> out(ct.size());
        const bool opened = static_cast<bool>(aes256_gcm_open(k, n, view(aad), view(ct), std::span<const std::uint8_t, 16>(tg.data(), 16), out));
        EXPECT_EQ(opened, f[1] == "valid") << "tcId " << f[0];
        if (f[1] == "valid") {
            EXPECT_EQ(out, msg) << "tcId " << f[0];
            std::vector<std::uint8_t> sealed(msg.size());
            EXPECT_EQ(to_hex(aes256_gcm_seal(k, n, view(aad), view(msg), sealed).unwrap()), f[7]) << "tcId " << f[0];
            EXPECT_EQ(sealed, ct) << "tcId " << f[0];
            ++valid;
        } else {
            ++invalid;
        }
    }
    EXPECT_GT(valid, 20);
    EXPECT_GT(invalid, 10);
    EXPECT_EQ(valid + invalid + not_offered, 105);
}

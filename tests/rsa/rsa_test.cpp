//
//  rsa_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/rsa/rsa.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <array>
#include <string>
#include <vector>

using namespace snicholls::crypto::rsa;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;

namespace {

std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) { return {v.data(), v.size()}; }

struct counts {
    int valid = 0, invalid = 0, acceptable = 0, keys = 0;
};

// Every case of a Wycheproof RSA fixture, with the group's key read three ways. The only "acceptable" cases (PKCS#1
// v1.5, tcId 8 in each key size) omit the DigestInfo's NULL parameters; this library rebuilds the encoding with the
// NULL and compares it whole, so it refuses them, as its documentation states.
counts run(const std::string& name)
{
    counts c;
    std::vector<public_key> keys;
    std::size_t salt = 0;
    bool pss = false;
    for (const auto& f : read_fixture("wycheproof/" + name)) {
        if (f[0] == "key") {
            keys.clear();
            const auto spki = hex_bytes(f[2]), pkcs1 = hex_bytes(f[3]), n = hex_bytes(f[4]), e = hex_bytes(f[5]);
            keys.push_back(public_key::from_spki_der(view(spki)).unwrap());
            keys.push_back(public_key::from_pkcs1_der(view(pkcs1)).unwrap());
            keys.push_back(public_key::from_components(view(n), view(e)).unwrap());
            pss = !f[6].empty();
            salt = pss ? std::stoul(f[6]) : 0;
            ++c.keys;
            continue;
        }
        const auto msg = hex_bytes(f[2]), sig = hex_bytes(f[3]);
        for (const auto& key : keys) {
            const auto r = pss ? verify_pss_sha256(key, view(msg), view(sig), salt) : verify_pkcs1v15_sha256(key, view(msg), view(sig));
            if (f[1] == "valid") {
                EXPECT_TRUE(r) << name << " tcId " << f[0];
            } else {
                EXPECT_FALSE(r) << name << " tcId " << f[0] << " (" << f[1] << ")";
            }
        }
        (f[1] == "valid" ? c.valid : f[1] == "invalid" ? c.invalid : c.acceptable) += 1;
    }
    return c;
}

} // namespace

TEST(CryptoRsaWycheproof, Pkcs1v15Sha256AllKeySizes)
{
    const auto a = run("rsa_pkcs1_2048_sha256.txt");
    const auto b = run("rsa_pkcs1_3072_sha256.txt");
    const auto c = run("rsa_pkcs1_4096_sha256.txt");
    EXPECT_EQ(a.valid + a.invalid + a.acceptable, 259);
    EXPECT_EQ(b.valid + b.invalid + b.acceptable, 259);
    EXPECT_EQ(c.valid + c.invalid + c.acceptable, 258);
    EXPECT_EQ(a.acceptable + b.acceptable + c.acceptable, 3);   // the missing NULL, refused
    EXPECT_GT(a.valid, 0);
    EXPECT_GT(a.invalid, 200);
}

TEST(CryptoRsaWycheproof, PssSha256Mgf1Salt32AllKeySizes)
{
    const auto a = run("rsa_pss_2048_sha256_mgf1_32.txt");
    const auto b = run("rsa_pss_3072_sha256_mgf1_32.txt");
    const auto c = run("rsa_pss_4096_sha256_mgf1_32.txt");
    EXPECT_EQ(a.valid + a.invalid + b.valid + b.invalid + c.valid + c.invalid, 108 * 3);
    EXPECT_EQ(a.acceptable + b.acceptable + c.acceptable, 0);
    EXPECT_GT(a.valid, 0);
}

TEST(CryptoRsaWycheproof, PssSha256Mgf1SaltZero)
{
    const auto a = run("rsa_pss_2048_sha256_mgf1_0.txt");
    EXPECT_EQ(a.valid + a.invalid + a.acceptable, 103);
    EXPECT_GT(a.valid, 0);
}

namespace {
// Wycheproof's 2048-bit key and its tcId 1 (PKCS#1 v1.5, the empty message)
constexpr auto spki_2048 = snicholls::crypto::test::hex<294>("30820122300d06092a864886f70d01010105000382010f003082010a0282010100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d50203010001");
constexpr auto pkcs1_2048 = snicholls::crypto::test::hex<270>("3082010a0282010100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d50203010001");
constexpr auto n_2048 = snicholls::crypto::test::hex<256>("a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5");
constexpr auto sig_2048 = snicholls::crypto::test::hex<256>("840f5dac53106dd1f9c57219224cf51289290c42f20466875ba8e830ac5690e541536fcc8ab03b731f82bf66d83f194e7e180b3963ec7a2f3f7904a7ce49aed47da4d4b79421eaf937d301b3e696169297b797c32c076a12be4de0b58e003c5123051a84a10c62f8dac2f42a8640008eb3c7cccd6760ff5b51b689763922582845f048fb8150e5a7a6ca2eccc7bdc85349ad5b26c52137a79fa3fe5c29ab5cd7615013219c1941b6708e9c3c23feff5febaf0c8ebca5750b54e3e6e99a3e876b396f27860b7f3ec4e9191703c6332d944f6f69751167680c79c4f6b57f1cc8755d24b6ec158ccdbacdb23107a33cb6b332516c13274d1f9dccc21dced869e486");
constexpr std::array<std::uint8_t, 3> e_65537{0x01, 0x00, 0x01};

std::vector<std::uint8_t> bytes(std::span<const std::uint8_t> s) { return {s.begin(), s.end()}; }
} // namespace

// A whole RS256 verification at compile time: key from DER, Montgomery constants, s^e mod n, the encoding compared
static_assert(verify_pkcs1v15_sha256(public_key::from_spki_der(spki_2048).unwrap(), {}, sig_2048).is_ok());
static_assert(!verify_pkcs1v15_sha256(public_key::from_spki_der(spki_2048).unwrap(), std::array<std::uint8_t, 1>{0}, sig_2048).is_ok());

TEST(CryptoRsaKeys, ComponentsMustBeCanonicalAndWithinTheLimits)
{
    EXPECT_TRUE(public_key::from_components(n_2048, e_65537));
    auto padded = bytes(n_2048);
    padded.insert(padded.begin(), 0);
    EXPECT_EQ(public_key::from_components(view(padded), e_65537).unwrap_err(), errc::non_canonical);
    const std::array<std::uint8_t, 4> e_padded{0x00, 0x01, 0x00, 0x01};
    EXPECT_EQ(public_key::from_components(n_2048, e_padded).unwrap_err(), errc::non_canonical);
    // 1024 bits: too small
    EXPECT_EQ(public_key::from_components(std::span<const std::uint8_t>(n_2048).first(128), e_65537).unwrap_err(), errc::invalid_public_key);
    // 4097 bits: too large
    std::vector<std::uint8_t> big(513, 0xff);
    big[0] = 1;
    EXPECT_EQ(public_key::from_components(view(big), e_65537).unwrap_err(), errc::invalid_public_key);
    // 4096 bits: the largest
    std::vector<std::uint8_t> largest(512, 0xff);
    EXPECT_TRUE(public_key::from_components(view(largest), e_65537));
    // An even modulus; an even, a unit and a too-wide exponent
    auto even = bytes(n_2048);
    even.back() &= 0xfe;
    EXPECT_EQ(public_key::from_components(view(even), e_65537).unwrap_err(), errc::invalid_public_key);
    const std::array<std::uint8_t, 3> e_even{0x01, 0x00, 0x00};
    const std::array<std::uint8_t, 1> e_one{0x01};
    const std::array<std::uint8_t, 9> e_wide{0x01, 0, 0, 0, 0, 0, 0, 0, 0x01};
    EXPECT_EQ(public_key::from_components(n_2048, e_even).unwrap_err(), errc::invalid_public_key);
    EXPECT_EQ(public_key::from_components(n_2048, e_one).unwrap_err(), errc::invalid_public_key);
    EXPECT_EQ(public_key::from_components(n_2048, e_wide).unwrap_err(), errc::invalid_public_key);
    EXPECT_EQ(public_key::from_components({}, e_65537).unwrap_err(), errc::invalid_public_key);
    const auto key = public_key::from_components(n_2048, e_65537).unwrap();
    EXPECT_EQ(key.modulus_bits(), 2048u);
    EXPECT_EQ(key.modulus_bytes(), 256u);
    EXPECT_EQ(key.exponent(), 65537u);
}

TEST(CryptoRsaKeys, DerMustBeDerAndRsaEncryption)
{
    EXPECT_TRUE(public_key::from_spki_der(spki_2048));
    EXPECT_TRUE(public_key::from_spki_der(pkcs1_2048));   // a bare RSAPublicKey is accepted here too
    EXPECT_TRUE(public_key::from_pkcs1_der(pkcs1_2048));
    EXPECT_FALSE(public_key::from_pkcs1_der(spki_2048));  // but not a SubjectPublicKeyInfo there
    auto trailing = bytes(spki_2048);
    trailing.push_back(0);
    EXPECT_FALSE(public_key::from_spki_der(view(trailing)));
    // The AlgorithmIdentifier 30 0d 06 09 <oid> 05 00, at offset 4
    auto wrong_oid = bytes(spki_2048);
    wrong_oid[4 + 2 + 2 + 8] = 0x0b;   // sha256WithRSAEncryption, not rsaEncryption
    EXPECT_FALSE(public_key::from_spki_der(view(wrong_oid)));
    auto no_null = bytes(spki_2048);   // drop the NULL: shorten the AlgorithmIdentifier and the outer SEQUENCE
    no_null.erase(no_null.begin() + 17, no_null.begin() + 19);   // 30 82 01 22 30 0d 06 09 <9 bytes> 05 00
    no_null[5] = 0x0b;
    no_null[3] = static_cast<std::uint8_t>(no_null[3] - 2);
    EXPECT_FALSE(public_key::from_spki_der(view(no_null)));
    auto unused_bits = bytes(spki_2048);
    unused_bits[23] = 0x01;            // BIT STRING 03 82 01 0f at offset 19, then the unused-bit count
    EXPECT_FALSE(public_key::from_spki_der(view(unused_bits)));
    // A long-form length where the short form fits: 30 0d becomes 30 81 0d
    auto long_form = bytes(spki_2048);
    long_form.insert(long_form.begin() + 5, 0x81);
    long_form[3] = static_cast<std::uint8_t>(long_form[3] + 1);
    EXPECT_FALSE(public_key::from_spki_der(view(long_form)));
    // A negative modulus: the INTEGER's leading 00 removed (02 82 01 01 00 a2 ... becomes 02 82 01 00 a2 ...)
    auto negative = bytes(pkcs1_2048);
    negative.erase(negative.begin() + 8);
    negative[7] = 0x00;
    negative[3] = static_cast<std::uint8_t>(negative[3] - 1);
    EXPECT_FALSE(public_key::from_pkcs1_der(view(negative)));
    EXPECT_FALSE(public_key::from_spki_der({}));
}

TEST(CryptoRsaSignatures, LengthAndRangeAreChecked)
{
    const auto key = public_key::from_spki_der(spki_2048).unwrap();
    EXPECT_TRUE(verify_pkcs1v15_sha256(key, {}, sig_2048));
    auto shorter = bytes(sig_2048);
    shorter.pop_back();
    EXPECT_EQ(verify_pkcs1v15_sha256(key, {}, view(shorter)).unwrap_err(), errc::invalid_signature);
    auto longer = bytes(sig_2048);
    longer.insert(longer.begin(), 0);   // the same value, one byte longer: refused, RFC 8017 8.2.2 step 1
    EXPECT_EQ(verify_pkcs1v15_sha256(key, {}, view(longer)).unwrap_err(), errc::invalid_signature);
    EXPECT_EQ(verify_pkcs1v15_sha256(key, {}, n_2048).unwrap_err(), errc::invalid_signature);    // s = n
    const std::array<std::uint8_t, 256> zero{};
    EXPECT_EQ(verify_pkcs1v15_sha256(key, {}, zero).unwrap_err(), errc::invalid_signature);
    std::array<std::uint8_t, 256> out{};
    EXPECT_TRUE(key.open(sig_2048, out));
    EXPECT_EQ(out[0], 0x00);
    EXPECT_EQ(out[1], 0x01);
    // A PSS salt length that cannot fit a 2048-bit modulus
    EXPECT_EQ(verify_pss_sha256(key, {}, sig_2048, 256 - 32 - 1).unwrap_err(), errc::invalid_length);
    EXPECT_EQ(verify_pss_sha256(key, {}, sig_2048, 32).unwrap_err(), errc::invalid_signature);
}

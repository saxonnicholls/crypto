//
//  sign_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/rsa/sign.hpp>
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
using snicholls::crypto::test::to_hex;

namespace {

std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) { return {v.data(), v.size()}; }

// A fixture's key line: the PKCS#8 DER and the components
struct key_parts {
    std::vector<std::uint8_t> pkcs8, n, e, p, q, dp, dq, qinv;
    std::string sha;

    explicit key_parts(const std::vector<std::string>& f)
        : pkcs8(hex_bytes(f[2])), n(hex_bytes(f[3])), e(hex_bytes(f[4])), p(hex_bytes(f[5])), q(hex_bytes(f[6])), dp(hex_bytes(f[7])),
          dq(hex_bytes(f[8])), qinv(hex_bytes(f[9])), sha(f[10])
    {
    }
    auto components() const { return private_key::from_components(view(n), view(e), view(p), view(q), view(dp), view(dq), view(qinv)); }
};

// The first key of a fixture (2048 bits, e = 65537, SHA-256 in the 2048-bit file)
key_parts first_key(const std::string& name)
{
    for (const auto& f : read_fixture("wycheproof/" + name))
        if (f[0] == "key")
            return key_parts(f);
    throw std::runtime_error("no key in " + name);
}

std::vector<std::uint8_t> sign(const private_key& key, const std::string& sha, std::span<const std::uint8_t> msg, bool& ok)
{
    std::vector<std::uint8_t> sig(key.modulus_bytes());
    ok = static_cast<bool>(sha == "SHA-256"   ? sign_pkcs1v15_sha256(key, msg, sig)
                           : sha == "SHA-384" ? sign_pkcs1v15_sha384(key, msg, sig)
                                              : sign_pkcs1v15_sha512(key, msg, sig));
    return sig;
}

// Every case of a Wycheproof signature-generation fixture: the key read from PKCS#8 and from its components, each
// signature byte for byte (PKCS#1 v1.5 is deterministic), and verified. "acceptable" cases are keys with e = 3
int run(const std::string& name)
{
    int signed_ = 0;
    std::vector<private_key> keys;
    std::string sha;
    for (const auto& f : read_fixture("wycheproof/" + name)) {
        if (f[0] == "key") {
            const key_parts k(f);
            keys.clear();
            auto a = private_key::from_pkcs8_der(view(k.pkcs8));
            auto b = k.components();
            EXPECT_TRUE(a) << name;
            EXPECT_TRUE(b) << name;
            if (!a || !b)
                return -1;
            keys.push_back(std::move(*a));
            keys.push_back(std::move(*b));
            sha = k.sha;
            continue;
        }
        const auto msg = hex_bytes(f[2]);
        for (const auto& key : keys) {
            bool ok = false;
            const auto sig = sign(key, sha, view(msg), ok);
            EXPECT_TRUE(ok) << name << " tcId " << f[0];
            EXPECT_EQ(to_hex(view(sig)), f[3]) << name << " tcId " << f[0];
            const auto v = sha == "SHA-256"   ? verify_pkcs1v15_sha256(key.public_key(), view(msg), view(sig))
                           : sha == "SHA-384" ? verify_pkcs1v15_sha384(key.public_key(), view(msg), view(sig))
                                              : verify_pkcs1v15_sha512(key.public_key(), view(msg), view(sig));
            EXPECT_TRUE(v) << name << " tcId " << f[0];
        }
        ++signed_;
    }
    return signed_;
}

} // namespace

TEST(CryptoRsaSignWycheproof, Pkcs1v15ByteForByteAllKeySizes)
{
    EXPECT_EQ(run("rsa_pkcs1_2048_sig_gen.txt"), 27);
    EXPECT_EQ(run("rsa_pkcs1_3072_sig_gen.txt"), 26);
    EXPECT_EQ(run("rsa_pkcs1_4096_sig_gen.txt"), 24);
}

TEST(CryptoRsaSign, OutputLengthAndPrehashedForm)
{
    const auto k = first_key("rsa_pkcs1_2048_sig_gen.txt");
    const auto key = k.components().unwrap();
    EXPECT_EQ(key.modulus_bytes(), 256u);
    const std::array<std::uint8_t, 3> msg{'a', 'b', 'c'};
    std::vector<std::uint8_t> sig(256), again(256), small(255), big(257);
    ASSERT_TRUE(sign_pkcs1v15_sha256(key, msg, sig));
    EXPECT_EQ(sign_pkcs1v15_sha256(key, msg, small).unwrap_err(), errc::invalid_length);
    EXPECT_EQ(sign_pkcs1v15_sha256(key, msg, big).unwrap_err(), errc::invalid_length);
    const auto h = snicholls::crypto::detail::sha256::hash(msg);
    ASSERT_TRUE(sign_pkcs1v15_sha256_prehashed(key, h, again));
    EXPECT_EQ(sig, again);
    // a clone and a moved key sign the same; the moved-from key is wiped and signs nothing
    auto copy = key.clone();
    auto moved = std::move(copy);
    ASSERT_TRUE(sign_pkcs1v15_sha256(moved, msg, again));
    EXPECT_EQ(sig, again);
    EXPECT_FALSE(sign_pkcs1v15_sha256(copy, msg, again));   // NOLINT(bugprone-use-after-move): the wiped state is the test
    EXPECT_EQ(again, std::vector<std::uint8_t>(256, 0));
}

// An encoded message at or above the modulus cannot verify: nothing is released
TEST(CryptoRsaSign, ASignatureThatDoesNotVerifyIsNeverReleased)
{
    const auto k = first_key("rsa_pkcs1_2048_sig_gen.txt");
    const auto key = k.components().unwrap();
    std::vector<std::uint8_t> em(256, 0xff), out(256, 0xaa);
    EXPECT_EQ(key.sign_encoded(view(em), out).unwrap_err(), errc::signing_fault);
    EXPECT_EQ(out, std::vector<std::uint8_t>(256, 0));
    em = k.n;   // m = n: zero modulo n
    EXPECT_EQ(key.sign_encoded(view(em), out).unwrap_err(), errc::signing_fault);
    em.pop_back();
    EXPECT_EQ(key.sign_encoded(view(em), out).unwrap_err(), errc::invalid_length);
}

// The Bellcore fault: one CRT half miscomputed gives an s that is right modulo one prime only, so s^e - m shares a
// factor with n. The CRT core alone produces it; the key's check is what stops it leaving
TEST(CryptoRsaSign, ADamagedCrtHalfGivesASignatureThatDoesNotVerify)
{
    using namespace snicholls::crypto::detail;
    const auto k = first_key("rsa_pkcs1_2048_sig_gen.txt");
    detail::crt_key<16> ck;
    ck.p = make_mont_ct<16>(detail::limbs_from_be<16>(view(k.p)));
    ck.q = make_mont_ct<16>(detail::limbs_from_be<16>(view(k.q)));
    ck.dp = detail::limbs_from_be<16>(view(k.dp));
    ck.dq = detail::limbs_from_be<16>(view(k.dq));
    ck.qinv = detail::limbs_from_be<16>(view(k.qinv));
    std::vector<std::uint8_t> em(256, 0x5a);
    em[0] = 0;
    const auto pub = public_key::from_components(view(k.n), view(k.e)).unwrap();
    const auto opens_to_em = [&](const std::array<std::uint64_t, 32>& s) {
        std::vector<std::uint8_t> sig(256), back(256);
        for (std::size_t i = 0; i < 256; ++i)
            sig[i] = static_cast<std::uint8_t>(s[(255 - i) / 8] >> (8 * ((255 - i) % 8)));
        return pub.open(view(sig), back).is_ok() && back == em;
    };
    EXPECT_TRUE(opens_to_em(detail::crt_power<16>(ck, detail::limbs_from_be<32>(view(em)))));
    ck.dq[3] ^= 0x10;   // the fault
    EXPECT_FALSE(opens_to_em(detail::crt_power<16>(ck, detail::limbs_from_be<32>(view(em)))));
}

// make_mont_ct agrees with make_mont, and mont_pow_ct with mont_pow, on a prime of the key
TEST(CryptoRsaSign, ConstantTimeMontgomeryAgreesWithThePublicForm)
{
    using namespace snicholls::crypto::detail;
    const auto k = first_key("rsa_pkcs1_2048_sig_gen.txt");
    const auto p = detail::limbs_from_be<16>(view(k.p));
    const auto a = make_mont<16>(p), b = make_mont_ct<16>(p);
    EXPECT_EQ(a.m0, b.m0);
    EXPECT_EQ(a.r2, b.r2);
    EXPECT_EQ(a.one, b.one);
    const auto e = detail::limbs_from_be<16>(view(k.dp));
    const auto base = mont_to<16>(detail::limbs_from_be<16>(view(k.qinv)), a);
    EXPECT_EQ(mont_pow<16>(base, e, a), mont_pow_ct<16>(base, e, a));
    limbs_n<16> zero{}, one{};
    one[0] = 1;
    EXPECT_EQ(mont_pow_ct<16>(base, zero, a), a.one);
    EXPECT_EQ(mont_pow_ct<16>(base, one, a), base);
}

TEST(CryptoRsaSignKeys, InconsistentAndOutOfRangeKeysAreRefused)
{
    const auto k = first_key("rsa_pkcs1_2048_sig_gen.txt");
    ASSERT_TRUE(k.components());
    const auto with = [&](auto change) {
        key_parts c = k;
        change(c);
        return c.components();
    };
    // each CRT number changed but still in range: caught by qInv q = 1 mod p, or by the consistency signature
    EXPECT_EQ(with([](key_parts& c) { c.dp.back() ^= 2; }).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(with([](key_parts& c) { c.dq.back() ^= 2; }).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(with([](key_parts& c) { c.qinv.back() ^= 1; }).unwrap_err(), errc::invalid_private_key);
    // p and q swapped: qInv is then for the wrong prime
    EXPECT_EQ(with([](key_parts& c) { std::swap(c.p, c.q); }).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(with([](key_parts& c) { std::swap(c.p, c.q); std::swap(c.dp, c.dq); }).unwrap_err(), errc::invalid_private_key);
    // p q != n, an even prime, p = q, a zero exponent, another public exponent
    EXPECT_EQ(with([](key_parts& c) { c.p.back() ^= 2; }).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(with([](key_parts& c) { c.q.back() ^= 1; }).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(with([](key_parts& c) { c.q = c.p; }).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(with([](key_parts& c) { c.n.back() ^= 2; }).unwrap_err(), errc::invalid_private_key);
    EXPECT_EQ(with([](key_parts& c) { c.e = {0x01, 0x00, 0x03}; }).unwrap_err(), errc::invalid_private_key);
    // dP = p (not below p)
    EXPECT_EQ(with([](key_parts& c) { c.dp = c.p; }).unwrap_err(), errc::invalid_private_key);
    // leading zero bytes, and empty components
    EXPECT_EQ(with([](key_parts& c) { c.p.insert(c.p.begin(), 0); }).unwrap_err(), errc::non_canonical);
    EXPECT_EQ(with([](key_parts& c) { c.dq.insert(c.dq.begin(), 0); }).unwrap_err(), errc::non_canonical);
    EXPECT_EQ(with([](key_parts& c) { c.n.insert(c.n.begin(), 0); }).unwrap_err(), errc::non_canonical);
    EXPECT_EQ(with([](key_parts& c) { c.qinv.clear(); }).unwrap_err(), errc::non_canonical);
    // a prime wider than 2048 bits
    EXPECT_EQ(with([](key_parts& c) { c.p.assign(257, 0xff); }).unwrap_err(), errc::invalid_private_key);
}

// A 1024-bit key is below the limit (the public key's rule): a 2048-bit key's primes as a "key" of their own
TEST(CryptoRsaSignKeys, ModuliBelow2048BitsAreRefused)
{
    const std::vector<std::uint8_t> n(128, 0xc1), e{1, 0, 1}, half(64, 0xc1);
    EXPECT_EQ(private_key::from_components(view(n), view(e), view(half), view(half), view(half), view(half), view(half)).unwrap_err(),
              errc::invalid_private_key);
}

TEST(CryptoRsaSignKeys, DerMustBeExactlyAPrivateKey)
{
    const auto k = first_key("rsa_pkcs1_2048_sig_gen.txt");
    ASSERT_TRUE(private_key::from_pkcs8_der(view(k.pkcs8)));
    // the RSAPrivateKey inside the PKCS#8 (after the 26-byte header: SEQUENCE, version, AlgorithmIdentifier, OCTET STRING)
    const std::vector<std::uint8_t> pkcs1(k.pkcs8.begin() + 26, k.pkcs8.end());
    ASSERT_EQ(pkcs1[0], 0x30);
    EXPECT_TRUE(private_key::from_pkcs1_der(view(pkcs1)));
    EXPECT_FALSE(private_key::from_pkcs8_der(view(pkcs1)));   // each reader reads its own structure only
    EXPECT_FALSE(private_key::from_pkcs1_der(view(k.pkcs8)));
    // trailing bytes, truncation, and every single byte of the header changed
    auto trailing = k.pkcs8;
    trailing.push_back(0);
    EXPECT_EQ(private_key::from_pkcs8_der(view(trailing)).unwrap_err(), errc::invalid_private_key);
    auto cut = k.pkcs8;
    cut.pop_back();
    EXPECT_FALSE(private_key::from_pkcs8_der(view(cut)));
    EXPECT_FALSE(private_key::from_pkcs8_der({}));
    for (std::size_t i = 0; i < 40; ++i) {
        auto bad = k.pkcs8;
        bad[i] ^= 1;
        EXPECT_FALSE(private_key::from_pkcs8_der(view(bad))) << "byte " << i;
    }
    // version 1 (multi-prime) in the RSAPrivateKey
    auto v1 = pkcs1;
    ASSERT_EQ(v1[4], 0x02);
    ASSERT_EQ(v1[6], 0x00);
    v1[6] = 1;
    EXPECT_FALSE(private_key::from_pkcs1_der(view(v1)));
    // an EncryptedPrivateKeyInfo (SEQUENCE { AlgorithmIdentifier, OCTET STRING }): another structure, refused
    const auto encrypted = hex_bytes("302c301806092a864886f70d01050d300b300906052b0e03021a0500041000112233445566778899aabbccddeeff");
    EXPECT_EQ(private_key::from_pkcs8_der(view(encrypted)).unwrap_err(), errc::invalid_private_key);
}

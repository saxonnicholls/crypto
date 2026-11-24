//
//  ecdh_es_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  JOSE's ECDH-ES against other implementations (tests/fixtures/oracles/): the key alone against OpenSSL's ECDH and
//  cryptography's ConcatKDFHash, for every algorithm and length; and whole JWEs made by jose (and opened by
//  cryptography), opened here as the recipient and made again here, byte for byte, as the sender.
//
#include <snicholls/crypto/aead/aes256_gcm.hpp>
#include <snicholls/crypto/aead/aes_key_wrap.hpp>
#include <snicholls/crypto/jose/ecdh_es.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace snicholls::crypto;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

namespace {

std::span<const std::uint8_t, 32> s32(const std::vector<std::uint8_t>& v) { return std::span<const std::uint8_t, 32>(v.data(), 32); }

// The N-byte key for (our secret, the peer's public key) on the row's curve, both directions of the agreement
template <std::size_t N>
std::string derive(const std::string& crv, const std::vector<std::uint8_t>& secret, const std::vector<std::uint8_t>& peer,
                   std::string_view alg, std::span<const std::uint8_t> apu, std::span<const std::uint8_t> apv)
{
    if (crv == "X25519") {
        const secret_bytes<32> s(s32(secret));
        x25519::public_key p;
        std::copy(peer.begin(), peer.end(), p.bytes.begin());
        return to_hex(jose::ecdh_es_x25519<N>(s, p, alg, apu, apv).unwrap().reveal());
    }
    const auto key = p256::private_key::from_bytes(s32(secret)).unwrap();
    const auto pub = p256::public_key::parse(view(peer)).unwrap();
    return to_hex(jose::ecdh_es_p256<N>(key, pub, alg, apu, apv).unwrap().reveal());
}

std::string derive(std::size_t n, const std::string& crv, const std::vector<std::uint8_t>& secret,
                   const std::vector<std::uint8_t>& peer, std::string_view alg, std::span<const std::uint8_t> apu,
                   std::span<const std::uint8_t> apv)
{
    switch (n) {
    case 16: return derive<16>(crv, secret, peer, alg, apu, apv);
    case 24: return derive<24>(crv, secret, peer, alg, apu, apv);
    case 32: return derive<32>(crv, secret, peer, alg, apu, apv);
    case 48: return derive<48>(crv, secret, peer, alg, apu, apv);
    case 64: return derive<64>(crv, secret, peer, alg, apu, apv);
    default: return "unexpected length";
    }
}

// The public key of a row's secret, in the form the row's epk takes
std::vector<std::uint8_t> public_of(const std::string& crv, const std::vector<std::uint8_t>& secret)
{
    if (crv == "X25519") {
        const auto p = x25519::public_key_from_secret(secret_bytes<32>(s32(secret)));
        return {p.bytes.begin(), p.bytes.end()};
    }
    const auto u = p256::private_key::from_bytes(s32(secret)).unwrap().public_key().uncompressed();
    return {u.begin(), u.end()};
}

} // namespace

TEST(CryptoJoseOracles, EcdhEsKeys)
{
    int rows = 0;
    for (const auto& f : oracle_rows("jose_ecdh_es.txt")) {
        const auto rsk = hex_bytes(f[1]), esk = hex_bytes(f[2]), epk = hex_bytes(f[3]), apu = hex_bytes(f[5]), apv = hex_bytes(f[6]);
        const auto n = static_cast<std::size_t>(std::stoul(f[7]));
        // the recipient, with its secret and the epk; the sender, with the ephemeral secret and the recipient's key
        EXPECT_EQ(derive(n, f[0], rsk, epk, f[4], view(apu), view(apv)), f[8]) << "row " << rows;
        EXPECT_EQ(derive(n, f[0], esk, public_of(f[0], rsk), f[4], view(apu), view(apv)), f[8]) << "row " << rows;
        ++rows;
    }
    EXPECT_EQ(rows, 300);
}

TEST(CryptoJoseOracles, WholeJwes)
{
    int rows = 0, wrapped = 0;
    for (const auto& f : oracle_rows("jose_jwe.txt")) {
        const std::string& crv = f[0];
        const bool direct = f[1] == "ECDH-ES";
        const auto rsk = hex_bytes(f[2]), esk = hex_bytes(f[3]), epk = hex_bytes(f[4]), apu = hex_bytes(f[5]), apv = hex_bytes(f[6]);
        const auto cek_in = hex_bytes(f[7]), iv = hex_bytes(f[8]), m = hex_bytes(f[9]), aad = hex_bytes(f[10]);
        const auto encrypted_key = hex_bytes(f[11]), ct = hex_bytes(f[12]), tag = hex_bytes(f[13]);
        const std::string alg = direct ? "A256GCM" : "ECDH-ES+A256KW";
        const std::span<const std::uint8_t, 12> nonce(iv.data(), 12);

        // The recipient: the key from its secret and the epk, the CEK (unwrapped with ECDH-ES+A256KW), the plaintext
        const auto key = hex_bytes(derive(32, crv, rsk, epk, alg, view(apu), view(apv)));
        std::vector<std::uint8_t> cek = key;
        if (!direct) {
            cek.assign(32, 0);
            ASSERT_TRUE(aead::aes256_key_unwrap(s32(key), view(encrypted_key), cek)) << "row " << rows;
            EXPECT_EQ(cek, cek_in) << "row " << rows;
            ++wrapped;
        }
        std::vector<std::uint8_t> back(ct.size());
        ASSERT_TRUE(aead::aes256_gcm_open(s32(cek), nonce, view(aad), view(ct), std::span<const std::uint8_t, 16>(tag.data(), 16), back))
            << "row " << rows;
        EXPECT_EQ(back, m) << "row " << rows;

        // The sender: the same key from the ephemeral secret, and jose's encrypted key, ciphertext and tag again
        EXPECT_EQ(public_of(crv, esk), epk) << "row " << rows;
        EXPECT_EQ(derive(32, crv, esk, public_of(crv, rsk), alg, view(apu), view(apv)), to_hex(view(key))) << "row " << rows;
        if (!direct) {
            std::vector<std::uint8_t> again(40);
            ASSERT_TRUE(aead::aes256_key_wrap(s32(key), view(cek_in), again));
            EXPECT_EQ(again, encrypted_key) << "row " << rows;
        } else {
            EXPECT_TRUE(encrypted_key.empty()) << "row " << rows;
        }
        std::vector<std::uint8_t> sealed(m.size());
        EXPECT_EQ(to_hex(aead::aes256_gcm_seal(s32(cek), nonce, view(aad), view(m), sealed).unwrap()), to_hex(view(tag))) << "row " << rows;
        EXPECT_EQ(sealed, ct) << "row " << rows;

        // A tampered tag is refused
        auto bad = tag;
        bad[0] ^= 1;
        EXPECT_FALSE(aead::aes256_gcm_open(s32(cek), nonce, view(aad), view(ct), std::span<const std::uint8_t, 16>(bad.data(), 16), back));
        ++rows;
    }
    EXPECT_EQ(rows, 120);
    EXPECT_EQ(wrapped, 60);
}

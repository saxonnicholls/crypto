//
//  keys_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  secp256k1 keys against other implementations (tests/fixtures/oracles/, scripts/generate_oracle_fixtures.py):
//  private to public keys, SEC1 parsing, and the Bitcoin and Ethereum addresses of a key.
//
#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/address/bech32.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/keys.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <snicholls/core/hash/sha3.hpp>
#include <gtest/gtest.h>

#include <array>
#include <string>

using namespace snicholls::crypto::secp256k1;
namespace a = snicholls::crypto::address;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::text_of;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

namespace {
std::string ethereum_address(const public_key& k)
{
    const auto xy = k.xy();
    auto d = snicholls::keccak256::hash(std::span<const std::uint8_t>(xy));
    const auto h = snicholls::crypto::detail::to_array(d);
    return to_hex(std::span<const std::uint8_t>(h).subspan(12));
}
} // namespace

TEST(CryptoSecp256k1KeysOracles, PublicKeysAgreeWithEveryOracle)
{
    int valid = 0, refused = 0;
    for (const auto& f : oracle_rows("secp256k1_keys.txt")) {
        const auto sk = hex<32>(f[0]);
        const auto key = private_key::from_bytes(sk);
        if (f[1].empty()) {
            EXPECT_FALSE(key) << f[0];
            ++refused;
            continue;
        }
        ASSERT_TRUE(key) << f[0];
        const auto pub = key->public_key();
        EXPECT_EQ(to_hex(pub.compressed()), f[1]);
        EXPECT_EQ(to_hex(pub.uncompressed()), f[2]);
        ++valid;
    }
    EXPECT_GE(valid, 1000);
    EXPECT_EQ(refused, 5);   // 0, n, n + 1, 2^256 - 1, p
}

TEST(CryptoSecp256k1KeysOracles, Sec1ParsingAgreesAndRefusesTheHybridForm)
{
    int rows = 0;
    for (const auto& f : oracle_rows("sec1_parse.txt")) {
        const auto bytes = hex_bytes(f[0]);
        const auto key = public_key::parse(view(bytes));
        // "hybrid" rows: libsecp256k1 reads SEC1's 0x06 / 0x07 form, k256 and noble do not, nor does this library
        if (f[1].empty()) {
            EXPECT_FALSE(key) << f[0] << " (" << f[2] << ")";
        } else {
            EXPECT_TRUE(key) << f[0];
            if (key) {
                EXPECT_EQ(to_hex(key->compressed()), f[1]);
            }
        }
        ++rows;
    }
    EXPECT_GE(rows, 1700);
}

TEST(CryptoSecp256k1KeysOracles, BitcoinAndEthereumAddressesOfAKey)
{
    int rows = 0;
    for (const auto& f : oracle_rows("key_addresses.txt")) {
        const auto bytes = hex_bytes(f[0]);
        const auto key = public_key::parse(view(bytes)).unwrap();
        const auto c = key.compressed();
        const auto h160 = snicholls::crypto::detail::hash160(c);
        std::array<std::uint8_t, 21> p2pkh{};
        p2pkh[0] = 0x00;
        std::copy(h160.begin(), h160.end(), p2pkh.begin() + 1);
        EXPECT_EQ(text_of(a::base58check_encode_exact(p2pkh)), f[1]);
        std::array<std::uint8_t, 22> redeem{0x00, 0x14};
        std::copy(h160.begin(), h160.end(), redeem.begin() + 2);
        const auto script_hash = snicholls::crypto::detail::hash160(redeem);
        std::array<std::uint8_t, 21> p2sh{};
        p2sh[0] = 0x05;
        std::copy(script_hash.begin(), script_hash.end(), p2sh.begin() + 1);
        EXPECT_EQ(text_of(a::base58check_encode_exact(p2sh)), f[2]);
        EXPECT_EQ(text_of(a::segwit_encode("bc", 0, h160).unwrap()), f[3]);
        const auto output_key = hex_bytes(f[4]);
        EXPECT_EQ(text_of(a::segwit_encode("bc", 1, view(output_key)).unwrap()), f[5]);
        EXPECT_EQ(ethereum_address(key), f[6]);
        ++rows;
    }
    EXPECT_EQ(rows, 400);
}

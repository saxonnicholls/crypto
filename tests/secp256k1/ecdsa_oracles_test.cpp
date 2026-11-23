//
//  ecdsa_oracles_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  ECDSA on secp256k1 against other implementations (tests/fixtures/oracles/, scripts/generate_oracle_fixtures.py):
//  RFC 6979 signatures byte for byte with libsecp256k1, k256, noble, ethers and OpenSSL; recovery; verification
//  under both high-S policies; DER; Ethereum's ecrecover.
//
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <snicholls/crypto/test/oracles.hpp>
#include <snicholls/core/hash/sha3.hpp>
#include <gtest/gtest.h>

#include <string>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::oracle_rows;
using snicholls::crypto::test::to_hex;
using snicholls::crypto::test::view;

TEST(CryptoSecp256k1EcdsaOracles, SignaturesAreByteForByteTheOracles)
{
    int rows = 0;
    for (const auto& f : oracle_rows("ecdsa_sign.txt")) {
        const auto key = private_key::from_bytes(hex<32>(f[0])).unwrap();
        const auto h = hex<32>(f[1]);
        const auto sig = sign(key, h);
        EXPECT_EQ(to_hex(sig.sig.r), f[2]) << f[0] << " " << f[1];
        EXPECT_EQ(to_hex(sig.sig.s), f[3]);
        EXPECT_EQ(std::to_string(sig.recovery_id), f[4]);
        const auto der = sig.sig.der();
        EXPECT_EQ(to_hex(std::span<const std::uint8_t>(der.data(), der.size())), f[5]);
        ++rows;
    }
    EXPECT_EQ(rows, 1010);
}

TEST(CryptoSecp256k1EcdsaOracles, RecoveryAgreesIncludingRefusals)
{
    int recovered = 0, refused = 0;
    for (const auto& f : oracle_rows("ecdsa_recover.txt")) {
        const auto h = hex<32>(f[0]);
        const auto sig = signature::from_compact(hex<64>(f[1]));
        const auto id = static_cast<std::uint8_t>(std::stoi(f[2]));
        const auto key = recover(h, sig, id, high_s::accept);
        if (f[3].empty()) {
            EXPECT_FALSE(key) << f[0] << " " << f[1] << " " << f[2];
            ++refused;
        } else {
            EXPECT_TRUE(key) << f[0] << " " << f[1] << " " << f[2];
            if (!key)
                continue;
            EXPECT_EQ(to_hex(key->compressed()), f[3]);
            ++recovered;
        }
    }
    EXPECT_GE(recovered, 700);
    EXPECT_GE(refused, 100);
}

TEST(CryptoSecp256k1EcdsaOracles, VerificationAgreesUnderBothHighSPolicies)
{
    int rows = 0, valid = 0;
    for (const auto& f : oracle_rows("ecdsa_verify.txt")) {
        const auto pub_bytes = hex_bytes(f[0]);
        const auto pub = public_key::parse(view(pub_bytes)).unwrap();
        const auto h = hex<32>(f[1]);
        const auto sig = signature::from_compact(hex<64>(f[2]));
        const auto policy = f[3] == "accept" ? high_s::accept : high_s::reject;
        const bool ok = static_cast<bool>(verify(pub, h, sig, policy));
        EXPECT_EQ(ok, f[4] == "1") << f[0] << " " << f[1] << " " << f[2] << " " << f[3];
        ++rows;
        valid += ok;
    }
    EXPECT_EQ(rows, 6640);
    EXPECT_GE(valid, 1000);
}

TEST(CryptoSecp256k1EcdsaOracles, DerIsReadAsStrictlyAsBip66AndVerifiedAlike)
{
    int parsed = 0, refused = 0;
    for (const auto& f : oracle_rows("ecdsa_der.txt")) {
        const auto pub_bytes = hex_bytes(f[0]);
        const auto pub = public_key::parse(view(pub_bytes)).unwrap();
        const auto h = hex<32>(f[1]);
        const auto der = hex_bytes(f[2]);
        const auto sig = signature::from_der(view(der));
        if (f[3].empty()) {
            EXPECT_FALSE(sig) << f[2];
            EXPECT_EQ(f[4], "0");
            ++refused;
            continue;
        }
        ASSERT_TRUE(sig) << f[2];
        EXPECT_EQ(to_hex(sig->compact()), f[3]);
        EXPECT_EQ(static_cast<bool>(verify(pub, h, *sig, high_s::accept)), f[4] == "1") << f[2];
        ++parsed;
    }
    EXPECT_GE(parsed, 1000);
    EXPECT_GE(refused, 1000);
}

TEST(CryptoSecp256k1EcdsaOracles, EthereumEcrecoverGivesEthersAddresses)
{
    int recovered = 0, refused = 0;
    for (const auto& f : oracle_rows("ethereum.txt")) {
        const auto h = hex<32>(f[0]);
        const auto rsv = hex<65>(f[1]);
        const auto key = recover_ethereum(h, rsv, high_s::accept);
        if (f[2].empty()) {
            EXPECT_FALSE(key) << f[1];
            ++refused;
            continue;
        }
        ASSERT_TRUE(key) << f[1];
        const auto xy = key->xy();
        auto d = snicholls::keccak256::hash(std::span<const std::uint8_t>(xy));
        const auto digest = snicholls::crypto::detail::to_array(d);
        EXPECT_EQ(to_hex(std::span<const std::uint8_t>(digest).subspan(12)), f[2]) << f[1];
        ++recovered;
    }
    EXPECT_GE(recovered, 300);
    EXPECT_GE(refused, 1);
}

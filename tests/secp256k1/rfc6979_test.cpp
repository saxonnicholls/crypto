//
//  rfc6979_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/rfc6979.hpp>
#include <snicholls/crypto/secp256k1/scalar.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

using snicholls::crypto::secp256k1::rfc6979;
using snicholls::crypto::test::bytes_of;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;
namespace d = snicholls::crypto::detail;

TEST(CryptoSecp256k1Rfc6979, AppendixA25P256WithSha256)
{
    // RFC 6979 A.2.5: the P-256 key and the nonces for "sample" and "test" with SHA-256
    constexpr auto q = hex<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    constexpr auto x = hex<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    {
        rfc6979 gen(x, d::sha256::hash(bytes_of("sample")), q);
        EXPECT_EQ(to_hex(gen.next().reveal()), "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
    }
    {
        rfc6979 gen(x, d::sha256::hash(bytes_of("test")), q);
        EXPECT_EQ(to_hex(gen.next().reveal()), "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0");
    }
}

TEST(CryptoSecp256k1Rfc6979, Secp256k1PublishedNonces)
{
    const auto n = snicholls::crypto::secp256k1::scalar::order_bytes();
    constexpr auto one = hex<32>("0000000000000000000000000000000000000000000000000000000000000001");
    {
        rfc6979 gen(one, d::sha256::hash(bytes_of("Satoshi Nakamoto")), n);
        EXPECT_EQ(to_hex(gen.next().reveal()), "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15");
    }
    {
        rfc6979 gen(one, d::sha256::hash(bytes_of("All those moments will be lost in time, like tears in rain. Time to die...")), n);
        EXPECT_EQ(to_hex(gen.next().reveal()), "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3");
    }
}

TEST(CryptoSecp256k1Rfc6979, SuccessiveCandidatesDifferAndExtraDataChangesThem)
{
    const auto n = snicholls::crypto::secp256k1::scalar::order_bytes();
    constexpr auto key = hex<32>("0000000000000000000000000000000000000000000000000000000000000007");
    const auto h = d::sha256::hash(bytes_of("message"));
    rfc6979 a(key, h, n);
    const auto first = to_hex(a.next().reveal());
    EXPECT_NE(first, to_hex(a.next().reveal()));
    const auto extra = hex<32>("0000000000000000000000000000000000000000000000000000000000000001");
    rfc6979 b(key, h, n, extra);
    EXPECT_NE(first, to_hex(b.next().reveal()));
}

TEST(CryptoSecp256k1Rfc6979, HashAtOrAboveTheOrderIsReduced)
{
    // A hash equal to n reduces to zero: the same nonce as the all-zero hash
    const auto n = snicholls::crypto::secp256k1::scalar::order_bytes();
    constexpr auto key = hex<32>("0000000000000000000000000000000000000000000000000000000000000003");
    rfc6979 a(key, n, n);
    rfc6979 b(key, hex<32>("0000000000000000000000000000000000000000000000000000000000000000"), n);
    EXPECT_EQ(to_hex(a.next().reveal()), to_hex(b.next().reveal()));
}

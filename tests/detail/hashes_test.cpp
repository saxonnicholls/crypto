//
//  hashes_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// The interim hashes against their standards' vectors: FIPS 180-4 examples (SHA-256, SHA-512), the RIPEMD-160
// authors' list, RFC 4231 (HMAC-SHA-256 and -512) and the PBKDF2-HMAC-SHA512 values every BIP-39 library uses.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace d = snicholls::crypto::detail;
using snicholls::crypto::test::bytes_of;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::to_hex;

// Computed by the compiler
static_assert(d::sha256::hash({})[0] == 0xe3);
static_assert(d::sha512::hash({})[0] == 0xcf);
static_assert(d::ripemd160::hash({})[0] == 0x9c);

TEST(CryptoDetailHashes, Sha256Fips180Examples)
{
    EXPECT_EQ(to_hex(d::sha256::hash({})), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(to_hex(d::sha256::hash(bytes_of("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(to_hex(d::sha256::hash(bytes_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    const std::string million(1000000, 'a');
    EXPECT_EQ(to_hex(d::sha256::hash(bytes_of(million))), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(CryptoDetailHashes, Sha512Fips180Examples)
{
    EXPECT_EQ(to_hex(d::sha512::hash(bytes_of("abc"))),
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    EXPECT_EQ(to_hex(d::sha512::hash(bytes_of(
                  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))),
              "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TEST(CryptoDetailHashes, StreamingEqualsOneShotAcrossBlockBoundaries)
{
    std::vector<std::uint8_t> msg(300);
    for (std::size_t i = 0; i < msg.size(); ++i)
        msg[i] = static_cast<std::uint8_t>(i * 7);
    for (std::size_t split = 0; split <= msg.size(); split += 37) {
        d::sha512 h;
        h.update(std::span<const std::uint8_t>(msg).first(split));
        h.update(std::span<const std::uint8_t>(msg).subspan(split));
        EXPECT_EQ(h.finish(), d::sha512::hash(msg)) << split;
        d::sha256 g;
        g.update(std::span<const std::uint8_t>(msg).first(split));
        g.update(std::span<const std::uint8_t>(msg).subspan(split));
        EXPECT_EQ(g.finish(), d::sha256::hash(msg)) << split;
    }
}

TEST(CryptoDetailHashes, Ripemd160AuthorsVectors)
{
    EXPECT_EQ(to_hex(d::ripemd160::hash({})), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    EXPECT_EQ(to_hex(d::ripemd160::hash(bytes_of("abc"))), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    EXPECT_EQ(to_hex(d::ripemd160::hash(bytes_of("message digest"))), "5d0689ef49d2fae572b881b123a85ffa21595f36");
    EXPECT_EQ(to_hex(d::ripemd160::hash(bytes_of("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))),
              "9b752e45573d4b39f4dbd3323cab82bf63326bfb");
    const std::string million(1000000, 'a');
    EXPECT_EQ(to_hex(d::ripemd160::hash(bytes_of(million))), "52783243c1697bdbe16d37f97f68f08325dc1528");
}

TEST(CryptoDetailHashes, Hash160OfTheGeneratorsCompressedKey)
{
    // HASH160 of 02 || G.x: the hash behind the address of private key 1
    const auto pub = hex_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    EXPECT_EQ(to_hex(d::hash160(pub)), "751e76e8199196d454941c45d1b3a323f1433bd6");
}

TEST(CryptoDetailHashes, HmacRfc4231)
{
    struct tc { std::string key, data, s256, s512; };
    const tc cases[] = {
        {std::string(20, '\x0b'), "Hi There",
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
         "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
        {"Jefe", "what do ya want for nothing?",
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
         "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
        {std::string(131, '\xaa'), "Test Using Larger Than Block-Size Key - Hash Key First",
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
         "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"},
    };
    for (const auto& c : cases) {
        EXPECT_EQ(to_hex(d::hmac_sha256::mac(bytes_of(c.key), bytes_of(c.data))), c.s256);
        EXPECT_EQ(to_hex(d::hmac_sha512::mac(bytes_of(c.key), bytes_of(c.data))), c.s512);
    }
}

TEST(CryptoDetailHashes, Pbkdf2HmacSha512)
{
    std::array<std::uint8_t, 64> out{};
    d::pbkdf2_hmac_sha512(bytes_of("password"), bytes_of("salt"), 1, out);
    EXPECT_EQ(to_hex(out), "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce");
    d::pbkdf2_hmac_sha512(bytes_of("password"), bytes_of("salt"), 2, out);
    EXPECT_EQ(to_hex(out), "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e");
    d::pbkdf2_hmac_sha512(bytes_of("password"), bytes_of("salt"), 4096, out);
    EXPECT_EQ(to_hex(out), "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5");
    // A length that is not a multiple of the block, spanning two blocks
    std::array<std::uint8_t, 80> longer{};
    d::pbkdf2_hmac_sha512(bytes_of("password"), bytes_of("salt"), 1, longer);
    EXPECT_EQ(to_hex(std::span<const std::uint8_t>(longer).first(64)),
              "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce");
}

//
//  chacha20_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/chacha20.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <string_view>
#include <vector>

using namespace snicholls::crypto::detail;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

namespace {
constexpr auto key = hex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

// RFC 8439 section 2.3.2: the block for counter 1 (checked against OpenSSL too)
static_assert(chacha20_block(key, 1, hex<12>("000000090000004a00000000")) ==
              hex<64>("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"));

TEST(CryptoDetailChaCha20, Rfc8439Section242AndHChaCha20)
{
    constexpr std::string_view s =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::vector<std::uint8_t> pt(s.begin(), s.end()), ct(pt.size());
    chacha20_xor(key, 1, hex<12>("000000000000004a00000000"), pt, ct);
    EXPECT_EQ(to_hex(ct), "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65"
                          "152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8e"
                          "edf2785e42874d");
    chacha20_xor(key, 1, hex<12>("000000000000004a00000000"), ct, ct);   // in place, back again
    EXPECT_EQ(ct, pt);
    // draft-irtf-cfrg-xchacha section 2.2.1
    EXPECT_EQ(to_hex(hchacha20(key, hex<16>("000000090000004a0000000031415927"))),
              "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
}

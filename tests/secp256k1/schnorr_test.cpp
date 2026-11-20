//
//  schnorr_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/secp256k1/schnorr.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> arr(const std::string& h)
{
    const auto v = hex_bytes(h);
    std::array<std::uint8_t, N> a{};
    std::copy(v.begin(), v.end(), a.begin());
    return a;
}
} // namespace

TEST(CryptoSecp256k1Schnorr, Bip340TestVectors)
{
    int signed_rows = 0, verified_rows = 0;
    for (const auto& f : read_fixture("bip340.txt")) {
        const xonly_public_key pk{arr<32>(f[2])};
        const auto msg = hex_bytes(f[4]);
        const schnorr_signature sig{arr<64>(f[5])};
        const bool expected = f[6] == "TRUE";
        if (!f[1].empty()) {
            const auto key = private_key::from_bytes(arr<32>(f[1])).unwrap();
            EXPECT_EQ(xonly_public_key_of(key), pk) << "index " << f[0];
            EXPECT_EQ(to_hex(schnorr_sign(key, msg, arr<32>(f[3])).bytes), f[5]) << "index " << f[0];
            ++signed_rows;
        }
        EXPECT_EQ(static_cast<bool>(schnorr_verify(pk, msg, sig)), expected) << "index " << f[0];
        ++verified_rows;
    }
    EXPECT_EQ(verified_rows, 19);
    EXPECT_GE(signed_rows, 4);
}

TEST(CryptoSecp256k1Schnorr, ErrorsSayWhichInputWasBad)
{
    const auto key = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000003")).unwrap();
    const std::array<std::uint8_t, 32> aux{};
    const std::array<std::uint8_t, 3> msg{1, 2, 3};
    const auto pk = xonly_public_key_of(key);
    auto sig = schnorr_sign(key, msg, aux);
    EXPECT_TRUE(schnorr_verify(pk, msg, sig));
    // x = 5 is not on the curve
    EXPECT_EQ(schnorr_verify(xonly_public_key{hex<32>("0000000000000000000000000000000000000000000000000000000000000005")}, msg, sig)
                  .unwrap_err(),
              errc::invalid_public_key);
    sig.bytes[63] ^= 1;
    EXPECT_EQ(schnorr_verify(pk, msg, sig).unwrap_err(), errc::invalid_signature);
    // s = n
    const auto n = scalar::order_bytes();
    std::copy(n.begin(), n.end(), sig.bytes.begin() + 32);
    EXPECT_EQ(schnorr_verify(pk, msg, sig).unwrap_err(), errc::invalid_signature);
}

TEST(CryptoSecp256k1Schnorr, AuxiliaryRandomnessChangesTheSignatureNotItsValidity)
{
    const auto key = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000007")).unwrap();
    const std::array<std::uint8_t, 32> zeros{};
    const auto ones = hex<32>("0101010101010101010101010101010101010101010101010101010101010101");
    const std::array<std::uint8_t, 0> empty{};
    const auto a = schnorr_sign(key, empty, zeros), b = schnorr_sign(key, empty, ones);
    EXPECT_FALSE(a == b);
    EXPECT_TRUE(schnorr_verify(xonly_public_key_of(key), empty, a));
    EXPECT_TRUE(schnorr_verify(xonly_public_key_of(key), empty, b));
}

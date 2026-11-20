//
//  base58check_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Base58check against published addresses and keys: private key 1's addresses and WIF keys, BIP-32 test vector 1's
// master key, and the XRP Ledger's special addresses (xrpl.org, "Addresses", Special Addresses).
#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace a = snicholls::crypto::address;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::to_hex;

namespace {
template <class V>
std::string text_of(const V& v) { return std::string(v.data(), v.size()); }
template <class V>
std::string hex_of(const V& v) { return to_hex(std::span<const std::uint8_t>(v.data(), v.size())); }
} // namespace

static_assert(a::base58check_checksum({})[0] == 0x5d);   // SHA-256d of nothing begins 5df6e0e2

TEST(CryptoAddressBase58check, AddressesOfPrivateKeyOne)
{
    // HASH160 of the compressed and uncompressed public keys of private key 1, version 0x00
    const auto compressed = hex<21>("00751e76e8199196d454941c45d1b3a323f1433bd6");
    const auto uncompressed = hex<21>("0091b24bf9f5288532960ac687abb035127b1d28a5");
    EXPECT_EQ(text_of(a::base58check_encode_exact(compressed)), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    EXPECT_EQ(text_of(a::base58check_encode_exact(uncompressed)), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
    EXPECT_EQ(*a::base58check_decode_exact<21>("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"), compressed);
}

TEST(CryptoAddressBase58check, WalletImportFormatOfPrivateKeyOne)
{
    std::array<std::uint8_t, 34> wif{};
    wif[0] = 0x80;
    wif[32] = 0x01;   // the key, 1
    wif[33] = 0x01;   // compressed public key
    EXPECT_EQ(text_of(a::base58check_encode_exact(wif)), "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    std::array<std::uint8_t, 33> wif_uncompressed{};
    wif_uncompressed[0] = 0x80;
    wif_uncompressed[32] = 0x01;
    EXPECT_EQ(text_of(a::base58check_encode_exact(wif_uncompressed)), "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
}

TEST(CryptoAddressBase58check, Bip32Vector1MasterKeyRoundTrips)
{
    const std::string xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const auto payload = a::base58check_decode_exact<78>(xprv);
    ASSERT_TRUE(payload);
    EXPECT_EQ(to_hex(std::span<const std::uint8_t>(*payload).first(4)), "0488ade4");
    EXPECT_EQ(to_hex(std::span<const std::uint8_t>(*payload).subspan(13, 32)),
              "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");   // the chain code
    EXPECT_EQ(text_of(a::base58check_encode_exact(*payload)), xprv);
    // Any other payload length is refused by the exact form, accepted by the general one
    EXPECT_EQ(a::base58check_decode_exact<77>(xprv).unwrap_err(), errc::invalid_length);
    EXPECT_EQ(a::base58check_decode<128>(xprv)->size(), 78u);
}

TEST(CryptoAddressBase58check, XrplSpecialAddresses)
{
    std::array<std::uint8_t, 21> zero{}, one{};
    one[20] = 1;
    EXPECT_EQ(text_of(a::base58check_encode_exact(zero, a::xrpl_base58)), "rrrrrrrrrrrrrrrrrrrrrhoLvTp");   // ACCOUNT_ZERO
    EXPECT_EQ(text_of(a::base58check_encode_exact(one, a::xrpl_base58)), "rrrrrrrrrrrrrrrrrrrrBZbvji");    // ACCOUNT_ONE
    const auto genesis = a::base58check_decode_exact<21>("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", a::xrpl_base58);
    ASSERT_TRUE(genesis);
    EXPECT_EQ(to_hex(*genesis), "00b5f762798a53d543a014caf8b297cff8f2f937e8");
    // The same address read with Bitcoin's alphabet has the wrong checksum, not a valid payload
    EXPECT_FALSE(a::base58check_decode("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));
}

TEST(CryptoAddressBase58check, KnownAddressDecodesToItsHash)
{
    const auto p = a::base58check_decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    ASSERT_TRUE(p);
    EXPECT_EQ(hex_of(*p), "0077bff20c60e522dfaa3350c39b030a5d004e839a");
}

TEST(CryptoAddressBase58check, EverySingleCharacterChangeIsDetected)
{
    const std::string good = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    int detected = 0, total = 0;
    for (std::size_t i = 0; i < good.size(); ++i) {
        for (const char c : std::string("23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")) {
            if (c == good[i])
                continue;
            std::string bad = good;
            bad[i] = c;
            const auto r = a::base58check_decode(bad);
            ++total;
            detected += !r;
            if (r)
                ADD_FAILURE() << bad;
        }
    }
    EXPECT_EQ(detected, total);
}

TEST(CryptoAddressBase58check, ShortAndOversizedInputsAreRefused)
{
    EXPECT_EQ(a::base58check_decode("").unwrap_err(), errc::invalid_length);
    EXPECT_EQ(a::base58check_decode("2g").unwrap_err(), errc::invalid_length);   // one byte: no room for a checksum
    EXPECT_EQ(a::base58check_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAM0").unwrap_err(), errc::invalid_character);
    // Four bytes that are exactly the checksum of the empty payload: an empty payload, valid
    const std::array<std::uint8_t, 0> empty{};
    const auto t = a::base58check_encode_exact(empty);
    EXPECT_EQ(a::base58check_decode(std::string(t.data(), t.size()))->size(), 0u);
    std::array<std::uint8_t, 129> big{};
    EXPECT_EQ(a::base58check_encode(big).unwrap_err(), errc::invalid_length);
}

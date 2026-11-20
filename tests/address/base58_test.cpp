//
//  base58_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Base58 against Bitcoin Core's src/test/data/base58_encode_decode.json (tests/fixtures/address/base58.txt), XRPL's
// special addresses, and every boundary of the caps.
#include <snicholls/crypto/address/base58.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace a = snicholls::crypto::address;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
template <class V>
std::string text_of(const V& v) { return std::string(v.data(), v.size()); }
template <class V>
std::vector<std::uint8_t> bytes_of_vector(const V& v) { return std::vector<std::uint8_t>(v.begin(), v.end()); }
} // namespace

// Evaluated by the compiler: "a" -> "2g", and back
static_assert([] {
    const std::array<std::uint8_t, 1> in{0x61};
    const auto t = a::base58_encode(in);
    return t && t->size() == 2 && (*t)[0] == '2' && (*t)[1] == 'g';
}());
static_assert([] {
    const auto b = a::base58_decode("2g");
    return b && b->size() == 1 && (*b)[0] == 0x61;
}());
static_assert(!a::make_base58_alphabet("too short").valid);
static_assert(!a::make_base58_alphabet("1123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxy").valid);   // a repeat
static_assert(a::base58_encoded_capacity(25) >= 34);

TEST(CryptoAddressBase58, BitcoinCoreVectorsEncodeAndDecode)
{
    const auto rows = read_fixture("address/base58.txt");
    ASSERT_EQ(rows.size(), 14u);
    for (const auto& r : rows) {
        const auto bytes = hex_bytes(r[0]);
        const auto text = a::base58_encode<256>(bytes);
        ASSERT_TRUE(text) << r[0];
        EXPECT_EQ(text_of(*text), r[1]);
        const auto back = a::base58_decode<256>(r[1]);
        ASSERT_TRUE(back) << r[1];
        EXPECT_EQ(bytes_of_vector(*back), bytes);
    }
}

TEST(CryptoAddressBase58, EmptyIsEmptyBothWays)
{
    EXPECT_EQ(a::base58_encode({})->size(), 0u);
    EXPECT_EQ(a::base58_decode("")->size(), 0u);
}

TEST(CryptoAddressBase58, LeadingZerosAreTheAlphabetsFirstSymbol)
{
    const std::array<std::uint8_t, 3> zeros{};
    EXPECT_EQ(text_of(*a::base58_encode(zeros)), "111");
    EXPECT_EQ(text_of(*a::base58_encode(zeros, a::xrpl_base58)), "rrr");
    const std::array<std::uint8_t, 3> one{0, 0, 1};
    EXPECT_EQ(text_of(*a::base58_encode(one)), "112");
    EXPECT_EQ(bytes_of_vector(*a::base58_decode("112")), (std::vector<std::uint8_t>{0, 0, 1}));
}

TEST(CryptoAddressBase58, FlickrAlphabetAgreesWithTheOracle)
{
    // Core's "simply a long string" vector in Flickr's alphabet, as the Python base58 2.1.1 package encodes it
    const auto bytes = hex_bytes("73696d706c792061206c6f6e6720737472696e67");
    EXPECT_EQ(text_of(*a::base58_encode(bytes, a::flickr_base58)), "2BfUPJGMeSrM59QhwSTLj2EEPkV2");
    EXPECT_EQ(bytes_of_vector(*a::base58_decode("2BfUPJGMeSrM59QhwSTLj2EEPkV2", a::flickr_base58)), bytes);
}

TEST(CryptoAddressBase58, EveryCharacterOutsideTheAlphabetIsRefused)
{
    for (const std::string_view bad : {"0", "O", "I", "l", " 2g", "2g ", "2 g", "2g\n", "+", "\x80", "\xff"})
        EXPECT_EQ(a::base58_decode(bad).unwrap_err(), errc::invalid_character) << bad;
    // XRPL's alphabet has no '0' or 'l' either, and '1' is a digit there, not a zero byte
    EXPECT_EQ(a::base58_decode("r0", a::xrpl_base58).unwrap_err(), errc::invalid_character);
    EXPECT_TRUE(a::base58_decode("1", a::xrpl_base58));
}

TEST(CryptoAddressBase58, CapsBoundTheInputAndTheOutput)
{
    std::array<std::uint8_t, 129> big{};
    big[0] = 0xff;
    EXPECT_TRUE(a::base58_encode(std::span<const std::uint8_t>(big).first(128)));
    EXPECT_EQ(a::base58_encode(big).unwrap_err(), errc::invalid_length);
    EXPECT_TRUE(a::base58_encode<129>(big));
    // A text longer than the cap's capacity is refused before any work
    const std::string long_text(a::base58_encoded_capacity(16) + 1, '2');
    EXPECT_EQ(a::base58_decode<16>(long_text).unwrap_err(), errc::invalid_length);
    // Text within the length cap whose value needs more bytes than the cap
    const std::string zs(a::base58_encoded_capacity(16), 'z');
    EXPECT_EQ(a::base58_decode<16>(zs).unwrap_err(), errc::invalid_length);
    // A caller's span that is too small
    std::array<char, 3> small{};
    const std::array<std::uint8_t, 8> eight{1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_EQ(a::base58_encode_to(eight, small).unwrap_err(), errc::invalid_length);
    std::array<std::uint8_t, 1> one{};
    EXPECT_EQ(a::base58_decode_to("2gx", one).unwrap_err(), errc::invalid_length);
}

TEST(CryptoAddressBase58, AllFfMaxLengthRoundTrips)
{
    std::array<std::uint8_t, 128> ff{};
    ff.fill(0xff);
    const auto t = a::base58_encode(ff);
    ASSERT_TRUE(t);
    EXPECT_LE(t->size(), a::base58_encoded_capacity(128));
    const auto back = a::base58_decode(text_of(*t));
    ASSERT_TRUE(back);
    EXPECT_EQ(bytes_of_vector(*back), std::vector<std::uint8_t>(ff.begin(), ff.end()));
}

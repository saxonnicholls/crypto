//
//  bech32_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Bech32 and bech32m against every valid and invalid string and segwit address of BIP-173 and BIP-350
// (tests/fixtures/address/bech32.txt and segwit.txt).
#include <snicholls/crypto/address/bech32.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace a = snicholls::crypto::address;
using snicholls::crypto::errc;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

namespace {
template <class V>
std::string text_of(const V& v) { return std::string(v.data(), v.size()); }
std::string lower(std::string s)
{
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
} // namespace

static_assert(a::bech32_decode("a12uel5l").is_ok());
static_assert(a::bech32_decode("a12uel5l")->variant == a::bech32_variant::bech32);
static_assert(a::bech32_decode("a1lqfn3a")->variant == a::bech32_variant::bech32m);
static_assert(a::bech32_decode("A1G7SGD8").is_err());

TEST(CryptoAddressBech32, BipStringVectors)
{
    const auto rows = read_fixture("address/bech32.txt");
    ASSERT_EQ(rows.size(), 40u);
    for (const auto& r : rows) {
        const auto raw = hex_bytes(r[2]);
        const std::string text(raw.begin(), raw.end());
        const auto variant = r[0] == "bech32" ? a::bech32_variant::bech32 : a::bech32_variant::bech32m;
        const auto d = a::bech32_decode(text);
        if (r[1] == "valid") {
            ASSERT_TRUE(d) << text;
            EXPECT_EQ(d->variant, variant) << text;   // a valid string of one variant is never valid as the other
            // Re-encoding gives the lower-case form back
            const auto e = a::bech32_encode(text_of(d->hrp), std::span<const std::uint8_t>(d->values.data(), d->values.size()), variant);
            ASSERT_TRUE(e) << text;
            EXPECT_EQ(text_of(*e), lower(text));
        } else {
            EXPECT_FALSE(d) << text;
        }
    }
}

TEST(CryptoAddressBech32, InvalidStringsFailForTheReasonTheBipGives)
{
    EXPECT_EQ(a::bech32_decode(std::string("\x20") + "1nwldj5").unwrap_err(), errc::invalid_character);
    EXPECT_EQ(a::bech32_decode(std::string("\x7f") + "1axkwrx").unwrap_err(), errc::invalid_character);
    EXPECT_EQ(a::bech32_decode("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx").unwrap_err(),
              errc::invalid_length);
    EXPECT_EQ(a::bech32_decode("pzry9x0s0muk").unwrap_err(), errc::invalid_hrp);
    EXPECT_EQ(a::bech32_decode("1pzry9x0s0muk").unwrap_err(), errc::invalid_hrp);
    EXPECT_EQ(a::bech32_decode("x1b4n0q5v").unwrap_err(), errc::invalid_character);
    EXPECT_EQ(a::bech32_decode("li1dgmt3").unwrap_err(), errc::invalid_length);
    EXPECT_EQ(a::bech32_decode("A1G7SGD8").unwrap_err(), errc::invalid_checksum);
    EXPECT_EQ(a::bech32_decode("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7").unwrap_err(), errc::non_canonical);
}

TEST(CryptoAddressBech32, SegwitVectorsUnderBip350)
{
    const auto rows = read_fixture("address/segwit.txt");
    ASSERT_EQ(rows.size(), 39u);
    int superseded = 0;
    for (const auto& r : rows) {
        const std::string& address = r[2];
        const std::string hrp = lower(address.substr(0, 2)) == "bc" ? "bc" : "tb";
        const auto w = a::segwit_decode(hrp, address);
        const bool bip173_v1_plus = r[0] == "bip173" && r[1] == "valid" && hex_bytes(r[3])[0] != 0;
        if (r[1] == "valid" && !bip173_v1_plus) {
            ASSERT_TRUE(w) << address;
            const auto spk = w->script_pubkey();
            EXPECT_EQ(to_hex(std::span<const std::uint8_t>(spk.data(), spk.size())), r[3]) << address;
            const auto again = a::segwit_encode(hrp, w->version, std::span<const std::uint8_t>(w->program.data(), w->program.size()));
            ASSERT_TRUE(again);
            EXPECT_EQ(text_of(*again), lower(address));
        } else {
            // BIP-173's v1+ addresses were bech32; BIP-350 requires bech32m for them, so they are now invalid
            superseded += bip173_v1_plus;
            EXPECT_FALSE(w) << address;
            if (bip173_v1_plus)
                EXPECT_EQ(w.unwrap_err(), errc::invalid_checksum) << address;
        }
    }
    EXPECT_EQ(superseded, 3);
}

TEST(CryptoAddressBech32, SegwitRulesEachWithItsError)
{
    EXPECT_EQ(a::segwit_decode("bc", "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty").unwrap_err(), errc::invalid_hrp);
    EXPECT_TRUE(a::segwit_decode("BC", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"));   // the HRP compares without case
    EXPECT_EQ(a::segwit_decode("tb", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap_err(), errc::invalid_hrp);
    EXPECT_EQ(a::segwit_decode("bc", "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2").unwrap_err(), errc::invalid_witness_version);
    EXPECT_EQ(a::segwit_decode("bc", "bc1pw5dgrnzv").unwrap_err(), errc::invalid_witness_program);
    EXPECT_EQ(a::segwit_decode("bc", "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P").unwrap_err(), errc::invalid_witness_program);
    EXPECT_EQ(a::segwit_decode("bc", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf").unwrap_err(), errc::non_canonical);
    EXPECT_EQ(a::segwit_decode("tb", "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j").unwrap_err(), errc::non_canonical);
    EXPECT_EQ(a::segwit_decode("bc", "bc1gmk9yu").unwrap_err(), errc::invalid_witness_program);
    EXPECT_EQ(a::segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh").unwrap_err(), errc::invalid_checksum);
    // Encoding refuses what decoding refuses
    const std::array<std::uint8_t, 20> p20{};
    const std::array<std::uint8_t, 41> p41{};
    EXPECT_EQ(a::segwit_encode("bc", 17, p20).unwrap_err(), errc::invalid_witness_version);
    EXPECT_EQ(a::segwit_encode("bc", 0, std::span<const std::uint8_t>(p20).first(19)).unwrap_err(), errc::invalid_witness_program);
    EXPECT_EQ(a::segwit_encode("bc", 1, p41).unwrap_err(), errc::invalid_witness_program);
    EXPECT_EQ(a::segwit_encode("bc", 1, std::span<const std::uint8_t>(p20).first(1)).unwrap_err(), errc::invalid_witness_program);
    EXPECT_TRUE(a::segwit_encode("bc", 16, std::span<const std::uint8_t>(p20).first(2)));
}

TEST(CryptoAddressBech32, GeneratorsP2wpkhAddress)
{
    // HASH160 of private key 1's compressed public key, the BIP-173 example's program
    const auto prog = hex_bytes("751e76e8199196d454941c45d1b3a323f1433bd6");
    EXPECT_EQ(text_of(*a::segwit_encode("bc", 0, prog)), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    // Taproot output of G's x (BIP-350's last valid vector)
    const auto x = hex_bytes("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    EXPECT_EQ(text_of(*a::segwit_encode("bc", 1, x)), "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
}

TEST(CryptoAddressBech32, LengthLimitAndItsOption)
{
    std::vector<std::uint8_t> values(80, 3);
    EXPECT_EQ(a::bech32_encode("lnbc", values, a::bech32_variant::bech32).unwrap_err(), errc::invalid_length);
    const auto longer = a::bech32_encode<200>("lnbc", values, a::bech32_variant::bech32);
    ASSERT_TRUE(longer);
    EXPECT_EQ(longer->size(), 4u + 1 + 80 + 6);
    EXPECT_EQ(a::bech32_decode(text_of(*longer)).unwrap_err(), errc::invalid_length);
    const auto back = a::bech32_decode<200>(text_of(*longer));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->values.size(), 80u);
}

TEST(CryptoAddressBech32, EncodeRejectsBadHrpAndValues)
{
    const std::array<std::uint8_t, 2> ok_values{1, 2}, bad_values{1, 32};
    EXPECT_EQ(a::bech32_encode("", ok_values, a::bech32_variant::bech32).unwrap_err(), errc::invalid_hrp);
    EXPECT_EQ(a::bech32_encode(std::string(84, 'a'), ok_values, a::bech32_variant::bech32).unwrap_err(), errc::invalid_hrp);
    EXPECT_EQ(a::bech32_encode("a b", ok_values, a::bech32_variant::bech32).unwrap_err(), errc::invalid_hrp);
    EXPECT_EQ(a::bech32_encode("ab", bad_values, a::bech32_variant::bech32).unwrap_err(), errc::invalid_character);
    EXPECT_EQ(text_of(*a::bech32_encode("A", {}, a::bech32_variant::bech32)), "a12uel5l");
}

TEST(CryptoAddressBech32, ConvertBitsPaddingRules)
{
    const std::array<std::uint8_t, 1> ff{0xff};
    const auto five = a::convert_bits<8, 5, true, 4>(ff);   // 11111 111(00)
    ASSERT_TRUE(five);
    EXPECT_EQ(five->size(), 2u);
    EXPECT_EQ((*five)[1], 0x1c);
    const auto back = a::convert_bits<5, 8, false, 4>(std::span<const std::uint8_t>(five->data(), five->size()));
    ASSERT_TRUE(back);
    EXPECT_EQ((*back)[0], 0xff);
    const std::array<std::uint8_t, 2> nonzero_pad{0x1f, 0x1d};
    EXPECT_EQ((a::convert_bits<5, 8, false, 4>(nonzero_pad).unwrap_err()), errc::non_canonical);
    const std::array<std::uint8_t, 3> too_much_pad{0x1f, 0x1c, 0x00};   // 15 bits: 7 left over
    EXPECT_EQ((a::convert_bits<5, 8, false, 4>(too_much_pad).unwrap_err()), errc::non_canonical);
    const std::array<std::uint8_t, 1> out_of_range{0x20};
    EXPECT_EQ((a::convert_bits<5, 8, false, 4>(out_of_range).unwrap_err()), errc::invalid_character);
    std::array<std::uint8_t, 5> five_bytes{};
    EXPECT_EQ((a::convert_bits<8, 5, true, 4>(five_bytes).unwrap_err()), errc::invalid_length);
}

TEST(CryptoAddressBech32, PolymodOfAValidStringIsItsConstant)
{
    const auto d = a::bech32_decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw");
    ASSERT_TRUE(d);
    std::vector<std::uint8_t> all(d->values.begin(), d->values.end());
    for (const char c : std::string_view("mqqqxw"))
        all.push_back(static_cast<std::uint8_t>(a::bech32_charset.find(c)));
    EXPECT_EQ(a::bech32_polymod("abcdef", all), 1u);
}

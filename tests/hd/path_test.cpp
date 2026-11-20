//
//  path_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/hd/path.hpp>

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <type_traits>

namespace hd = snicholls::crypto::hd;
using snicholls::crypto::errc;

namespace {
std::string text_of(const hd::derivation_path& p)
{
    std::array<char, hd::derivation_path::max_text_length> buf{};
    return std::string(buf.data(), p.format(buf));
}
} // namespace

static_assert(std::is_trivially_copyable_v<hd::derivation_path>);
static_assert(hd::hardened(44) == 0x8000002c && hd::is_hardened(hd::hardened(0)) && !hd::is_hardened(0x7fffffff));
static_assert(hd::derivation_path::parse("m")->empty());
static_assert(hd::derivation_path::parse("m/44'/60'/0'/0/0")->size() == 5);
static_assert((*hd::derivation_path::parse("m/44'/60'/0'/0/0"))[0] == hd::hardened(44));
static_assert(*hd::derivation_path::parse("m/44h/60H/0'/0/0") == *hd::bip44_path(hd::coin_type::ethereum, 0, 0, 0));
static_assert(!hd::derivation_path::parse("m/"));
static_assert(hd::derivation_path::parse("m/501'/0'")->all_hardened());

TEST(CryptoHdPath, ParsesAndFormatsTheStandardPaths)
{
    for (const char* t : {"m", "m/0", "m/0'", "m/44'/60'/0'/0/0", "m/84'/0'/0'/1/7", "m/2147483647'/2147483647",
                          "m/0'/1/2'/2/1000000000"}) {
        const auto p = hd::derivation_path::parse(t);
        ASSERT_TRUE(p) << t;
        EXPECT_EQ(text_of(*p), t);
    }
    EXPECT_EQ(text_of(*hd::derivation_path::parse("m/1h/2H")), "m/1'/2'");
}

TEST(CryptoHdPath, RejectsEverythingOutsideTheGrammar)
{
    for (const char* t : {"", "M", "M/0", "m0", "m/", "m//0", "m/0/", "/0", "m/ 0", "m/0 ", " m/0", "m/-1", "m/+1",
                          "m/01", "m/00", "m/2147483648", "m/4294967295", "m/99999999999", "m/1''", "m/1'h", "m/1x",
                          "m/0x10", "m/1/2'/", "m/1\\", "m\\1"}) {
        const auto p = hd::derivation_path::parse(t);
        ASSERT_FALSE(p) << t;
        EXPECT_EQ(p.unwrap_err(), errc::invalid_path) << t;
    }
}

TEST(CryptoHdPath, DepthIsLimitedToTheCapacity)
{
    std::string deep = "m";
    for (std::size_t i = 0; i < hd::derivation_path::max_depth; ++i)
        deep += "/4294967'";
    const auto p = hd::derivation_path::parse(deep);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->size(), hd::derivation_path::max_depth);
    EXPECT_EQ(text_of(*p), deep);
    EXPECT_FALSE(hd::derivation_path::parse(deep + "/1"));
    auto q = *p;
    EXPECT_FALSE(q.push_back(1));
    EXPECT_EQ(q, *p);
}

TEST(CryptoHdPath, AllHardened)
{
    EXPECT_TRUE(hd::derivation_path::parse("m")->all_hardened());
    EXPECT_TRUE(hd::derivation_path::parse("m/44'/501'/0'/0'")->all_hardened());
    EXPECT_FALSE(hd::derivation_path::parse("m/44'/501'/0'/0")->all_hardened());
}

TEST(CryptoHdPath, WalletPathsForEachPurpose)
{
    EXPECT_EQ(text_of(*hd::bip44_path(hd::coin_type::ethereum, 0, 0, 0)), "m/44'/60'/0'/0/0");
    EXPECT_EQ(text_of(*hd::bip44_path(hd::coin_type::tron, 1, 0, 5)), "m/44'/195'/1'/0/5");
    EXPECT_EQ(text_of(*hd::bip49_path(hd::coin_type::bitcoin, 0, 1, 0)), "m/49'/0'/0'/1/0");
    EXPECT_EQ(text_of(*hd::bip84_path(hd::coin_type::bitcoin, 0, 0, 0)), "m/84'/0'/0'/0/0");
    EXPECT_EQ(text_of(*hd::bip86_path(hd::coin_type::testnet, 0, 0, 0)), "m/86'/1'/0'/0/0");
    EXPECT_EQ(hd::coin_type::solana, 501u);
}

TEST(CryptoHdPath, WalletPathsRefuseBadComponents)
{
    EXPECT_EQ(hd::bip44_path(hd::coin_type::ethereum, 0, 2, 0).unwrap_err(), errc::invalid_path);
    EXPECT_EQ(hd::bip44_path(hd::hardened(60), 0, 0, 0).unwrap_err(), errc::invalid_path);   // never hardened twice
    EXPECT_EQ(hd::bip84_path(0, 0x80000000u, 0, 0).unwrap_err(), errc::invalid_path);
    EXPECT_EQ(hd::bip86_path(0, 0, 0, 0x80000000u).unwrap_err(), errc::invalid_path);
    EXPECT_EQ(hd::wallet_path(hd::hardened(44), 0, 0, 0, 0).unwrap_err(), errc::invalid_path);
}

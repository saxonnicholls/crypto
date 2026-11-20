//
//  error_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/error.hpp>

#include <gtest/gtest.h>

using snicholls::crypto::errc;

static_assert(snicholls::crypto::to_string(errc::invalid_signature) == "invalid_signature");
static_assert(noexcept(snicholls::crypto::to_string(errc::high_s)));

TEST(CryptoError, EveryValueHasItsOwnName)
{
    for (int v = 1; v <= static_cast<int>(errc::invalid_extended_key); ++v) {
        const auto name = snicholls::crypto::to_string(static_cast<errc>(v));
        EXPECT_NE(name, "unknown") << v;
        for (int w = 1; w < v; ++w)
            EXPECT_NE(name, snicholls::crypto::to_string(static_cast<errc>(w)));
    }
}

TEST(CryptoError, ValueOutsideTheEnumerationIsUnknown)
{
    EXPECT_EQ(snicholls::crypto::to_string(static_cast<errc>(0)), "unknown");
    EXPECT_EQ(snicholls::crypto::to_string(static_cast<errc>(200)), "unknown");
}

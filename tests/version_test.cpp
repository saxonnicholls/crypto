//
//  version_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/version.hpp>

#include <gtest/gtest.h>

#include <string>

SNICHOLLS_CRYPTO_REQUIRE_VERSION(0, 1, 0);

static_assert(snicholls::crypto::version() ==
              SNICHOLLS_CRYPTO_VERSION_CHECK(SNICHOLLS_CRYPTO_VERSION_MAJOR, SNICHOLLS_CRYPTO_VERSION_MINOR, SNICHOLLS_CRYPTO_VERSION_PATCH));
static_assert(noexcept(snicholls::crypto::version_string()));

TEST(CryptoVersion, StringIsMajorDotMinorDotPatch)
{
    const std::string expected = std::to_string(snicholls::crypto::version_major()) + "." +
                                 std::to_string(snicholls::crypto::version_minor()) + "." +
                                 std::to_string(snicholls::crypto::version_patch());
    EXPECT_EQ(snicholls::crypto::version_string(), expected);
    EXPECT_EQ(std::string(SNICHOLLS_CRYPTO_VERSION_STRING), expected);
}

TEST(CryptoVersion, EncodingOrdersVersions)
{
    EXPECT_LT(SNICHOLLS_CRYPTO_VERSION_CHECK(0, 1, 9), SNICHOLLS_CRYPTO_VERSION_CHECK(0, 2, 0));
    EXPECT_EQ(SNICHOLLS_CRYPTO_VERSION_CHECK(1, 2, 3), 10203);
}

//
//  version_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Which snicholls-crypto this program was compiled against, and a compile-time minimum.
#include <snicholls/crypto/version.hpp>

#include <cstdio>
#include <string_view>

//! [version]
SNICHOLLS_CRYPTO_REQUIRE_VERSION(0, 1, 0);   // stops the build against anything older

int main()
{
    std::printf("snicholls-crypto %s (encoded %d)\n", SNICHOLLS_CRYPTO_VERSION_STRING, snicholls::crypto::version());
#if SNICHOLLS_CRYPTO_VERSION >= SNICHOLLS_CRYPTO_VERSION_CHECK(0, 1, 0)
    std::printf("0.1.0 or newer: everything in this release is available\n");
#endif
    //! [version]
    return snicholls::crypto::version_string() == std::string_view(SNICHOLLS_CRYPTO_VERSION_STRING) ? 0 : 1;
}

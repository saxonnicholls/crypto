//
//  poly1305_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/poly1305.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

#include <string_view>

using snicholls::crypto::detail::poly1305;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::to_hex;

TEST(CryptoDetailPoly1305, Rfc8439Section252AndChunking)
{
    constexpr std::string_view s = "Cryptographic Forum Research Group";
    const std::span<const std::uint8_t> m(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    const auto key = hex<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    poly1305 whole(key);
    whole.update(m);
    EXPECT_EQ(to_hex(whole.finish()), "a8061dc1305136c6c22b8baf0c0127a9");
    // the same bytes in uneven pieces give the same tag
    poly1305 pieces(key);
    pieces.update(m.first(3));
    pieces.update(m.subspan(3, 17));
    pieces.update(m.subspan(20));
    EXPECT_EQ(to_hex(pieces.finish()), "a8061dc1305136c6c22b8baf0c0127a9");
    // RFC 8439 appendix A.3, test vector 2's key with no message: the tag is s
    poly1305 empty(hex<32>("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e"));
    EXPECT_EQ(to_hex(empty.finish()), "36e5f6b5c5e06070f0efca96227a863e");
}

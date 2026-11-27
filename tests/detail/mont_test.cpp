//
//  mont_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/mont.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::detail;
using snicholls::crypto::test::hex;

namespace {
// m = 2^383 + 31 on six limbs: odd, with the top limb set
constexpr limbs_n<6> m{31, 0, 0, 0, 0, 1ull << 63};
constexpr auto P = make_mont<6>(m);
constexpr limbs_n<6> to(std::uint64_t v) { return mont_to<6>({v, 0, 0, 0, 0, 0}, P); }
constexpr std::uint64_t from(const limbs_n<6>& a) { return mont_from<6>(a, P)[0]; }
} // namespace

// The arithmetic at six limbs, at compile time
static_assert(from(mont_mul<6>(to(6), to(7), P)) == 42);
static_assert(from(mont_add<6>(to(40), to(2), P)) == 42);
static_assert(from(mont_pow<6>(to(3), {5, 0, 0, 0, 0, 0}, P)) == 243);
// N = 4 is the same code as mont256.hpp's names
static_assert(from_be_n<4>(hex<32>("000000000000000000000000000000000000000000000000000000000000002a")) == limbs_n<4>{42, 0, 0, 0});
static_assert(to_be_n<6>(limbs_n<6>{1, 0, 0, 0, 0, 0})[47] == 1);

TEST(CryptoDetailMont, ReductionAtTheModulusOnSixLimbs)
{
    // (m - 1) + 1 = 0, (m - 1)^2 = 1, and 2 - 44 = m - 42
    limbs_n<6> m1 = m;
    m1[0] -= 1;
    const auto a = mont_to<6>(m1, P);
    EXPECT_EQ(mont_from<6>(mont_add<6>(a, to(1), P), P), (limbs_n<6>{}));
    EXPECT_EQ(mont_from<6>(mont_mul<6>(a, a, P), P), (limbs_n<6>{1, 0, 0, 0, 0, 0}));
    limbs_n<6> m42 = m;   // m - 42 = 2^383 - 11: 31 - 42 borrows through to the top limb
    m42[0] = 31ull - 42ull;
    m42[5] -= 1;
    for (std::size_t i = 1; i < 5; ++i)
        m42[i] = ~0ull;
    EXPECT_EQ(mont_from<6>(mont_sub<6>(to(2), to(44), P), P), m42);
    EXPECT_EQ(mont_reduce_once<6>(m, 0, m), (limbs_n<6>{}));
    // the masks and the selection
    EXPECT_EQ(mask_is_zero_n<6>(limbs_n<6>{}), ~0ull);
    EXPECT_EQ(mask_equal_n<6>(m, m1), 0u);
    EXPECT_EQ(select_n<6>(~0ull, m, m1), m);
}

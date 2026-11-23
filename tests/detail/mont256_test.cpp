//
//  mont256_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/mont256.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::detail;

namespace {
// m = 2^255 + 95: odd, with the top limb set
constexpr limbs4 m{95, 0, 0, 1ull << 63};
constexpr auto P = make_mont256(m);
constexpr limbs4 to(std::uint64_t v) { return mont256_to({v, 0, 0, 0}, P); }
constexpr std::uint64_t from(const limbs4& a) { return mont256_from(a, P)[0]; }
} // namespace

static_assert(from(mont256_mul(to(6), to(7), P)) == 42);
static_assert(from(mont256_add(to(40), to(2), P)) == 42);
static_assert(mont256_from(mont256_sub(to(2), to(44), P), P) == limbs4{95 - 42, 0, 0, 1ull << 63});   // m - 42
static_assert(from(mont256_pow(to(3), {5, 0, 0, 0}, P)) == 243);

TEST(CryptoDetailMont256, ReductionAtTheModulus)
{
    // (m - 1) + 1 = 0 and (m - 1)^2 = 1
    limbs4 m1 = m;
    m1[0] -= 1;
    const auto a = mont256_to(m1, P);
    EXPECT_EQ(mont256_from(mont256_add(a, to(1), P), P), (limbs4{0, 0, 0, 0}));
    EXPECT_EQ(mont256_from(mont256_mul(a, a, P), P), (limbs4{1, 0, 0, 0}));
    // 2 - 44 = m - 42
    limbs4 expected = m;
    expected[0] -= 42;
    EXPECT_EQ(mont256_from(mont256_sub(to(2), to(44), P), P), expected);
    EXPECT_EQ(mont256_reduce_once(m, 0, m), (limbs4{0, 0, 0, 0}));
}

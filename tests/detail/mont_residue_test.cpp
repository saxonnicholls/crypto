//
//  mont_residue_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
#include <snicholls/crypto/detail/mont_residue.hpp>
#include <snicholls/crypto/test/hex.hpp>
#include <gtest/gtest.h>

using namespace snicholls::crypto::detail;
using snicholls::crypto::test::hex;

namespace {
// The prime 2^127 - 1 (3 mod 4) on two limbs: the class at a size neither curve uses
struct m127 {
    static constexpr mont_params<2> value = make_mont<2>({~0ull, ~0ull >> 1});
    static constexpr const mont_params<2>& params() noexcept { return value; }
};
using r127 = mont_residue<2, m127>;
} // namespace

static_assert(r127::size_bytes == 16 && r127::limbs == 2);
static_assert(r127::from_u64(5).inverse() * r127::from_u64(5) == r127::from_u64(1));
static_assert(r127::from_u64(3) - r127::from_u64(5) + r127::from_u64(2) == r127{});
static_assert(!r127::from_bytes(hex<16>("7fffffffffffffffffffffffffffffff")).has_value());
static_assert(r127::modulus_bytes() == hex<16>("7fffffffffffffffffffffffffffffff"));

TEST(CryptoDetailMontResidue, RootsReductionAndSelection)
{
    std::uint64_t square = 0;
    const auto nine = r127::from_u64(9);
    EXPECT_EQ(nine.sqrt_ct(square).square(), nine);
    EXPECT_NE(square, 0u);
    (void)(-r127::from_u64(1)).sqrt_ct(square);
    EXPECT_EQ(square, 0u);
    // m + 5 reduced once is 5 (one subtraction suffices below 2 m, which every curve's 2^(64 N) is)
    EXPECT_EQ(r127::from_bytes_reduced(hex<16>("80000000000000000000000000000004")).to_bytes(), hex<16>("00000000000000000000000000000005"));
    EXPECT_EQ(r127::select(0, r127::from_u64(1), r127::from_u64(2)), r127::from_u64(2));
    EXPECT_TRUE(r127{}.is_zero());
    EXPECT_EQ(r127::from_u64(7).is_odd(), 1u);
    EXPECT_EQ(r127::from_u64(7).canonical()[0], 7u);
}

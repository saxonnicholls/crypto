//
//  secret_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/secret.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>

using snicholls::crypto::secret_bytes;

static_assert(!std::is_copy_constructible_v<secret_bytes<32>>);
static_assert(!std::is_copy_assignable_v<secret_bytes<32>>);
static_assert(std::is_nothrow_move_constructible_v<secret_bytes<32>>);
static_assert(std::is_nothrow_move_assignable_v<secret_bytes<32>>);
static_assert(sizeof(secret_bytes<32>) == 32);

// A secret built, moved and compared at compile time
static_assert([] {
    std::array<std::uint8_t, 4> raw{1, 2, 3, 4};
    secret_bytes<4> a(std::move(raw));
    secret_bytes<4> b = std::move(a);
    return b.reveal()[3] == 4 && a.reveal()[3] == 0 && raw[0] == 0 && b == b.clone();
}());

TEST(CryptoSecret, ConstructionFromAnArrayWipesTheArray)
{
    std::array<std::uint8_t, 3> raw{7, 8, 9};
    const secret_bytes<3> s(std::move(raw));
    EXPECT_EQ(raw, (std::array<std::uint8_t, 3>{}));
    EXPECT_EQ(s.reveal()[0], 7);
}

TEST(CryptoSecret, MoveWipesTheSource)
{
    const std::array<std::uint8_t, 2> raw{5, 6};
    secret_bytes<2> a{std::span<const std::uint8_t, 2>(raw)};
    secret_bytes<2> b;
    b = std::move(a);
    EXPECT_EQ(b.reveal()[1], 6);
    EXPECT_EQ(a.reveal()[0], 0);
    EXPECT_EQ(a.reveal()[1], 0);
}

TEST(CryptoSecret, CloneIsAnEqualIndependentCopy)
{
    const std::array<std::uint8_t, 2> raw{5, 6};
    secret_bytes<2> a{std::span<const std::uint8_t, 2>(raw)};
    const secret_bytes<2> b = a.clone();
    EXPECT_TRUE(a == b);
    a.wipe();
    EXPECT_FALSE(a == b);
    EXPECT_EQ(b.reveal()[0], 5);
}

TEST(CryptoSecret, DestructorWipesTheStorage)
{
    alignas(secret_bytes<4>) unsigned char storage[sizeof(secret_bytes<4>)];
    auto* s = new (storage) secret_bytes<4>();
    s->reveal_mutable()[0] = 0xaa;
    s->~secret_bytes<4>();
    for (const unsigned char c : storage)
        EXPECT_EQ(c, 0);
}

TEST(CryptoSecret, SecureWipeZeroesRawMemory)
{
    std::uint8_t raw[16];
    for (auto& b : raw)
        b = 0xff;
    snicholls::crypto::secure_wipe(raw, sizeof raw);
    for (const auto b : raw)
        EXPECT_EQ(b, 0);
}

//
//  ed25519_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>
#include <type_traits>
#include <vector>

namespace ed25519 = snicholls::crypto::ed25519;
using snicholls::crypto::errc;
using snicholls::crypto::test::bytes_of;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;

static_assert(!std::is_copy_constructible_v<ed25519::key_pair>);
static_assert(std::is_nothrow_move_constructible_v<ed25519::key_pair>);
// RFC 8032 TEST 1's public key, derived by the compiler
static_assert(ed25519::public_key_from_seed(hex<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).bytes ==
              hex<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));

namespace {
ed25519::signature to_signature(const std::vector<std::uint8_t>& b)
{
    ed25519::signature s;
    std::copy(b.begin(), b.end(), s.bytes.begin());
    return s;
}
} // namespace

TEST(CryptoEd25519, Rfc8032Section71)
{
    const auto rows = read_fixture("rfc8032_ed25519.txt");
    ASSERT_EQ(rows.size(), 5u);
    for (const auto& r : rows) {
        const auto seed = hex<32>(r[1]);
        const auto msg = hex_bytes(r[3]);
        const auto kp = ed25519::key_pair::from_seed(seed);
        EXPECT_EQ(to_hex(kp.public_key().bytes), r[2]) << r[0];
        const auto sig = kp.sign(msg);
        EXPECT_EQ(to_hex(sig.bytes), r[4]) << r[0];
        EXPECT_TRUE(ed25519::verify(kp.public_key(), msg, sig).is_ok()) << r[0];
    }
}

TEST(CryptoEd25519, Wycheproof)
{
    const auto rows = read_fixture("wycheproof/ed25519.txt");
    ASSERT_EQ(rows.size(), 210u);
    int valid = 0, invalid = 0, acceptable_accepted = 0, acceptable_rejected = 0;
    for (const auto& r : rows) {
        const std::string& result = r[1];
        const auto pk = hex_bytes(r[2]);
        const auto msg = hex_bytes(r[3]);
        const auto sig = hex_bytes(r[4]);
        bool ok = false;
        if (pk.size() == 32 && sig.size() == 64) {
            ed25519::public_key key;
            std::copy(pk.begin(), pk.end(), key.bytes.begin());
            ok = ed25519::verify(key, msg, to_signature(sig)).is_ok();
        }   // a signature of any other length cannot be passed as one: rejected by type
        if (result == "valid") {
            EXPECT_TRUE(ok) << "tcId " << r[0];
            ++valid;
        } else if (result == "invalid") {
            EXPECT_FALSE(ok) << "tcId " << r[0];
            ++invalid;
        } else {
            ++(ok ? acceptable_accepted : acceptable_rejected);
        }
    }
    EXPECT_EQ(valid + invalid + acceptable_accepted + acceptable_rejected, 210);
    RecordProperty("acceptable_accepted", acceptable_accepted);
    RecordProperty("acceptable_rejected", acceptable_rejected);
    std::printf("wycheproof ed25519: %d valid, %d invalid, acceptable %d accepted / %d rejected\n", valid, invalid,
                acceptable_accepted, acceptable_rejected);
}

TEST(CryptoEd25519, AnyChangeBreaksTheSignature)
{
    const auto kp = ed25519::key_pair::from_seed(hex<32>("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    const auto msg = bytes_of("attack at dawn");
    const auto sig = kp.sign(msg);
    ASSERT_TRUE(ed25519::verify(kp.public_key(), msg, sig).is_ok());
    EXPECT_EQ(ed25519::verify(kp.public_key(), bytes_of("attack at dusk"), sig).unwrap_err(), errc::invalid_signature);
    for (std::size_t i = 0; i < 64; i += 7) {
        auto bad = sig;
        bad.bytes[i] ^= 0x01;
        EXPECT_FALSE(ed25519::verify(kp.public_key(), msg, bad).is_ok()) << i;
    }
    const auto other = ed25519::key_pair::from_seed(hex<32>("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"));
    EXPECT_FALSE(ed25519::verify(other.public_key(), msg, sig).is_ok());
}

TEST(CryptoEd25519, SPlusTheOrderIsRejected)
{
    // S + L verifies under a lax check that reduces S; the canonical check refuses it
    const auto kp = ed25519::key_pair::from_seed(hex<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    auto sig = kp.sign({});
    const auto order = hex<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    unsigned carry = 0;
    for (std::size_t i = 0; i < 32; ++i) {
        const unsigned v = sig.bytes[32 + i] + order[i] + carry;
        sig.bytes[32 + i] = static_cast<std::uint8_t>(v);
        carry = v >> 8;
    }
    ASSERT_EQ(carry, 0u);
    EXPECT_EQ(ed25519::verify(kp.public_key(), {}, sig).unwrap_err(), errc::invalid_signature);
}

TEST(CryptoEd25519, UndecodablePublicKeyIsReportedAsSuch)
{
    ed25519::public_key bad{hex<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")};   // y = p
    EXPECT_EQ(ed25519::verify(bad, {}, ed25519::signature{}).unwrap_err(), errc::invalid_public_key);
}

TEST(CryptoEd25519, SmallOrderKeyAndRAreAcceptedWhenTheEquationHolds)
{
    // A = identity, R = identity, S = 0: [0]B = R + [k]A holds for every message. Cofactorless verifiers that do not
    // screen small-order points (Go, this library) accept it; libsodium's strict mode would not.
    ed25519::public_key identity{hex<32>("0100000000000000000000000000000000000000000000000000000000000000")};
    ed25519::signature sig;
    sig.bytes[0] = 1;
    EXPECT_TRUE(ed25519::verify(identity, bytes_of("anything"), sig).is_ok());
    // The same R written non-canonically (y = p + 1) never matches the computed encoding
    const auto non_canonical_r = hex<32>("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    std::copy(non_canonical_r.begin(), non_canonical_r.end(), sig.bytes.begin());
    EXPECT_FALSE(ed25519::verify(identity, bytes_of("anything"), sig).is_ok());
}

TEST(CryptoEd25519, KeyPairOwnsAndWipesItsSeed)
{
    std::array<std::uint8_t, 32> raw = hex<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const auto expected = raw;
    auto kp = ed25519::key_pair::from_seed(snicholls::crypto::secret_bytes<32>(std::move(raw)));
    EXPECT_EQ(raw, (std::array<std::uint8_t, 32>{}));
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), kp.seed().reveal().begin()));
    auto moved = std::move(kp);
    EXPECT_EQ(to_hex(moved.public_key().bytes), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
}

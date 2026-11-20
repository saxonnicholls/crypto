//
//  ecdsa_test.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/test/fixtures.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <gtest/gtest.h>

#include <map>
#include <optional>
#include <string>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::errc;
using snicholls::crypto::test::bytes_of;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;
using snicholls::crypto::test::read_fixture;
using snicholls::crypto::test::to_hex;
namespace d = snicholls::crypto::detail;

namespace {
constexpr auto one = hex<32>("0000000000000000000000000000000000000000000000000000000000000001");

template <std::size_t N>
std::array<std::uint8_t, N> arr(const std::string& h)
{
    const auto v = hex_bytes(h);
    std::array<std::uint8_t, N> a{};
    std::copy(v.begin(), v.end(), a.begin());
    return a;
}

// A signature with s replaced by n - s
signature flip_s(signature sig)
{
    sig.s = (-*scalar::from_bytes(sig.s)).to_bytes();
    return sig;
}
} // namespace

// A whole RFC 6979 signature, computed by the compiler: key 1, SHA-256("Satoshi Nakamoto")
static_assert(sign(private_key::from_bytes(one).unwrap(),
                   hex<32>("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"))
                  .sig.r == hex<32>("934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"));

TEST(CryptoSecp256k1Ecdsa, Rfc6979SignaturesRecoveryIdsAndKeys)
{
    int rows = 0;
    for (const auto& f : read_fixture("rfc6979_secp256k1.txt")) {
        const auto key = private_key::from_bytes(arr<32>(f[0])).unwrap();
        const auto hash = arr<32>(f[1]);
        const auto sig = sign(key, hash);
        EXPECT_EQ(to_hex(sig.sig.r), f[2]);
        EXPECT_EQ(to_hex(sig.sig.s), f[3]);
        EXPECT_EQ(std::to_string(sig.recovery_id), f[4]);
        const auto pub = key.public_key();
        EXPECT_EQ(to_hex(pub.compressed()), f[5]);
        EXPECT_TRUE(verify(pub, hash, sig.sig, high_s::reject));
        EXPECT_EQ(recover(hash, sig.sig, sig.recovery_id).unwrap(), pub);
        EXPECT_FALSE(sig.sig.s == flip_s(sig.sig).s);
        ++rows;
    }
    EXPECT_EQ(rows, 16);
}

TEST(CryptoSecp256k1Ecdsa, HighSVerifiesOnlyWhenAccepted)
{
    const auto key = private_key::from_bytes(one).unwrap();
    const auto hash = d::sha256::hash(bytes_of("high s"));
    const auto sig = sign(key, hash);
    EXPECT_FALSE(scalar::from_bytes(sig.sig.s)->is_high());
    const auto high = flip_s(sig.sig);
    EXPECT_TRUE(verify(key.public_key(), hash, high, high_s::accept));
    EXPECT_EQ(verify(key.public_key(), hash, high, high_s::reject).unwrap_err(), errc::high_s);
    // The flipped signature recovers the same key with the other parity
    EXPECT_EQ(recover(hash, high, sig.recovery_id ^ 1).unwrap(), key.public_key());
    EXPECT_EQ(recover(hash, high, sig.recovery_id ^ 1, high_s::reject).unwrap_err(), errc::high_s);
}

TEST(CryptoSecp256k1Ecdsa, OutOfRangeComponentsAreInvalid)
{
    const auto key = private_key::from_bytes(one).unwrap();
    const auto hash = d::sha256::hash(bytes_of("range"));
    const auto good = sign(key, hash).sig;
    const auto n = scalar::order_bytes();
    const std::array<std::uint8_t, 32> zero{};
    for (const auto& bad : {signature{zero, good.s}, signature{good.r, zero}, signature{n, good.s}, signature{good.r, n}}) {
        EXPECT_EQ(verify(key.public_key(), hash, bad).unwrap_err(), errc::invalid_signature);
        EXPECT_EQ(recover(hash, bad, 0).unwrap_err(), errc::invalid_signature);
    }
    // Wrong message, wrong key
    EXPECT_EQ(verify(key.public_key(), d::sha256::hash(bytes_of("other")), good).unwrap_err(), errc::invalid_signature);
    const auto other = private_key::from_bytes(hex<32>("0000000000000000000000000000000000000000000000000000000000000002")).unwrap();
    EXPECT_EQ(verify(other.public_key(), hash, good).unwrap_err(), errc::invalid_signature);
}

TEST(CryptoSecp256k1Ecdsa, RecoveryEdgeCases)
{
    const auto key = private_key::from_bytes(one).unwrap();
    const auto hash = d::sha256::hash(bytes_of("recover"));
    const auto sig = sign(key, hash);
    EXPECT_EQ(recover(hash, sig.sig, 4).unwrap_err(), errc::invalid_recovery_id);
    // Ids 2 and 3 ask for x = r + n, which is at or above p for every r above p - n (almost every r)
    EXPECT_EQ(recover(hash, sig.sig, 2).unwrap_err(), errc::recovery_failed);
    // An id of 2 with a tiny r gives x = r + n < p: recovery goes ahead to whatever key that point implies
    signature tiny = sig.sig;
    tiny.r = hex<32>("0000000000000000000000000000000000000000000000000000000000000001");
    const auto r2 = recover(hash, tiny, 2);
    EXPECT_TRUE(r2 || r2.unwrap_err() == errc::recovery_failed);
    // r = 5: x = 5 is not on the curve
    signature off = sig.sig;
    off.r = hex<32>("0000000000000000000000000000000000000000000000000000000000000005");
    EXPECT_EQ(recover(hash, off, 0).unwrap_err(), errc::recovery_failed);
    // The wrong parity recovers a different key, never an error
    EXPECT_NE(recover(hash, sig.sig, sig.recovery_id ^ 1).unwrap(), key.public_key());
}

TEST(CryptoSecp256k1Ecdsa, EthereumVIsTwentySevenOrTwentyEight)
{
    const auto key = private_key::from_bytes(hex<32>("4646464646464646464646464646464646464646464646464646464646464646")).unwrap();
    const auto hash = d::sha256::hash(bytes_of("ecrecover"));
    const auto sig = sign(key, hash);
    auto rsv = sig.ethereum();
    EXPECT_EQ(rsv[64], 27 + sig.recovery_id);
    EXPECT_EQ(recover_ethereum(hash, rsv).unwrap(), key.public_key());
    for (const std::uint8_t v : {0, 1, 26, 29, 30, 255}) {
        rsv[64] = v;
        EXPECT_EQ(recover_ethereum(hash, rsv).unwrap_err(), errc::invalid_recovery_id) << int(v);
    }
}

TEST(CryptoSecp256k1Ecdsa, ExtraEntropyChangesTheSignatureNotItsValidity)
{
    const auto key = private_key::from_bytes(one).unwrap();
    const auto hash = d::sha256::hash(bytes_of("extra"));
    const auto extra = hex<32>("00000000000000000000000000000000000000000000000000000000000000ff");
    const auto a = sign(key, hash), b = sign(key, hash, extra);
    EXPECT_FALSE(a.sig == b.sig);
    EXPECT_TRUE(verify(key.public_key(), hash, b.sig, high_s::reject));
    EXPECT_EQ(sign(key, hash, extra), b);   // still deterministic
}

TEST(CryptoSecp256k1Ecdsa, DerRoundTripAndStrictness)
{
    const auto key = private_key::from_bytes(one).unwrap();
    const auto sig = sign(key, d::sha256::hash(bytes_of("der"))).sig;
    const auto der = sig.der();
    EXPECT_EQ(signature::from_der(der).unwrap(), sig);
    // A minimal encoding of small values
    signature small{hex<32>("0000000000000000000000000000000000000000000000000000000000000001"),
                    hex<32>("0000000000000000000000000000000000000000000000000000000000000080")};
    EXPECT_EQ(to_hex(small.der()), "3007020101020200" "80");
    EXPECT_EQ(signature::from_der(small.der()).unwrap(), small);
    // Rejected: a trailing byte, padding, a negative integer, a wrong total length
    auto bytes = std::vector<std::uint8_t>(der.begin(), der.end());
    auto extended = bytes;
    extended.push_back(0);
    EXPECT_FALSE(signature::from_der(extended));
    EXPECT_FALSE(signature::from_der(hex_bytes("300802020001020200" "80")));   // 0x0001 is padded
    EXPECT_FALSE(signature::from_der(hex_bytes("3006020181020101")));           // r is negative
    EXPECT_FALSE(signature::from_der(hex_bytes("3007020101020101")));           // total length disagrees
    EXPECT_FALSE(signature::from_der({}));
}

namespace {
struct wycheproof_counts {
    int valid_accepted = 0, invalid_rejected = 0, wrong = 0;
};

// Runs a converted Wycheproof ECDSA file; der: signatures are DER, else 64-byte P1363
wycheproof_counts run_wycheproof(const std::string& file, bool der, high_s policy)
{
    wycheproof_counts c;
    std::optional<public_key> key;
    for (const auto& f : read_fixture(file)) {
        if (f[0] == "key") {
            key = public_key::parse(hex_bytes(f[2])).unwrap();
            continue;
        }
        const auto msg = hex_bytes(f[2]);
        const auto sig_bytes = hex_bytes(f[3]);
        const auto hash = d::sha256::hash(msg);
        bool accepted = false;
        if (der) {
            if (const auto sig = signature::from_der(sig_bytes))
                accepted = static_cast<bool>(verify(*key, hash, *sig, policy));
        } else if (sig_bytes.size() == 64) {
            accepted = static_cast<bool>(verify(*key, hash, signature::from_compact(std::span<const std::uint8_t, 64>(sig_bytes.data(), 64)), policy));
        }
        if (f[1] == "valid" && accepted)
            ++c.valid_accepted;
        else if (f[1] == "invalid" && !accepted)
            ++c.invalid_rejected;
        else {
            ++c.wrong;
            ADD_FAILURE() << file << " tcId " << f[0] << " (" << f[1] << ") was " << (accepted ? "accepted" : "rejected");
        }
    }
    return c;
}
} // namespace

TEST(CryptoSecp256k1Ecdsa, WycheproofDer)
{
    const auto c = run_wycheproof("wycheproof/ecdsa_secp256k1_sha256.txt", true, high_s::accept);
    EXPECT_EQ(c.wrong, 0);
    EXPECT_EQ(c.valid_accepted, 168);
    EXPECT_EQ(c.invalid_rejected, 308);
}

TEST(CryptoSecp256k1Ecdsa, WycheproofP1363)
{
    const auto c = run_wycheproof("wycheproof/ecdsa_secp256k1_sha256_p1363.txt", false, high_s::accept);
    EXPECT_EQ(c.wrong, 0);
    EXPECT_EQ(c.valid_accepted, 167);
    EXPECT_EQ(c.invalid_rejected, 85);
}

TEST(CryptoSecp256k1Ecdsa, WycheproofBitcoinRequiresLowS)
{
    const auto c = run_wycheproof("wycheproof/ecdsa_secp256k1_sha256_bitcoin.txt", true, high_s::reject);
    EXPECT_EQ(c.wrong, 0);
    EXPECT_EQ(c.valid_accepted, 162);
    EXPECT_EQ(c.invalid_rejected, 302);
}

TEST(CryptoSecp256k1Ecdsa, WycheproofSignaturesRecoverTheirKey)
{
    // Every valid signature recovers its public key under one of the four ids
    std::optional<public_key> key;
    int recovered = 0;
    for (const auto& f : read_fixture("wycheproof/ecdsa_secp256k1_sha256_p1363.txt")) {
        if (f[0] == "key") {
            key = public_key::parse(hex_bytes(f[2])).unwrap();
            continue;
        }
        if (f[1] != "valid")
            continue;
        const auto hash = d::sha256::hash(hex_bytes(f[2]));
        const auto sig = signature::from_compact(arr<64>(f[3]));
        bool found = false;
        for (std::uint8_t id = 0; id < 4 && !found; ++id) {
            const auto r = recover(hash, sig, id);
            found = r && *r == *key;
        }
        EXPECT_TRUE(found) << "tcId " << f[0];
        recovered += found;
    }
    EXPECT_EQ(recovered, 167);
}

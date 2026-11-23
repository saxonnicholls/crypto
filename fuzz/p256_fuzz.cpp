//
//  p256_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of P-256 against OpenSSL: key validity and public keys; this library's RFC 6979 signatures
//  verified by OpenSSL (whose signing nonces are random); then a signature made adversarial (r or s replaced by 0,
//  n - 1, n, n + 1, p, 2^256 - 1, by n - s, or bits flipped) verified by both; and arbitrary bytes as SEC1.
//
//  The stated rule: verification and key parsing agree both ways, except that OpenSSL reads SEC1's hybrid form
//  (0x06, 0x07), which this library refuses.
//
#include "support/fuzz_support.hpp"

#include <snicholls/crypto/p256/ecdsa.hpp>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

namespace f = snicholls::crypto::fuzz;
namespace p256 = snicholls::crypto::p256;

namespace {

// P-256's n, p, and the adversarial values
std::array<std::uint8_t, 32> edge(std::uint8_t which)
{
    static const char* table[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    };
    const char* h = table[which % 7];
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 32; ++i) {
        auto v = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        out[i] = static_cast<std::uint8_t>(v(h[2 * i]) << 4 | v(h[2 * i + 1]));
    }
    return out;
}

EC_POINT* openssl_point(const EC_GROUP* g, std::span<const std::uint8_t> b)
{
    EC_POINT* p = EC_POINT_new(g);
    if (EC_POINT_oct2point(g, p, b.data(), b.size(), nullptr) != 1) {
        EC_POINT_free(p);
        return nullptr;
    }
    return p;
}

bool openssl_verify(std::span<const std::uint8_t> pub, const std::array<std::uint8_t, 32>& h, const std::array<std::uint8_t, 64>& rs)
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* p = openssl_point(EC_KEY_get0_group(key), pub);
    bool ok = p && EC_KEY_set_public_key(key, p) == 1;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_bin2bn(rs.data(), 32, nullptr), BN_bin2bn(rs.data() + 32, 32, nullptr));
    ok = ok && ECDSA_do_verify(h.data(), 32, sig, key) == 1;
    ECDSA_SIG_free(sig);
    EC_POINT_free(p);
    EC_KEY_free(key);
    return ok;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("p256", data, size);
    const char* T = "p256";
    f::input in(data, size);
    const std::uint8_t mode = in.byte();

    if ((mode & 3) == 3) {   // arbitrary bytes as SEC1
        const auto b = in.rest();
        const auto ours = p256::public_key::parse(b);
        EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        EC_POINT* p = openssl_point(g, b);
        const bool theirs = p != nullptr && !EC_POINT_is_at_infinity(g, p);
        const bool hybrid = !b.empty() && (b[0] == 6 || b[0] == 7);
        if (static_cast<bool>(ours) != theirs && !(hybrid && theirs && !ours))
            f::divergence(T, "SEC1 " + f::hex(b));
        if (ours && theirs) {
            std::array<std::uint8_t, 33> c{};
            EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED, c.data(), c.size(), nullptr);
            if (c != ours->compressed())
                f::divergence(T, "SEC1 read differently: " + f::hex(b));
        }
        EC_POINT_free(p);
        EC_GROUP_free(g);
        return 0;
    }

    auto sk = in.take<32>();
    if (mode & 4)
        sk = edge(in.byte());
    const auto h = in.take<32>();
    const auto key = p256::private_key::from_bytes(sk);
    BIGNUM* d = BN_bin2bn(sk.data(), 32, nullptr);
    BIGNUM* order = BN_bin2bn(edge(3).data(), 32, nullptr);
    const bool theirs = !BN_is_zero(d) && BN_cmp(d, order) < 0;
    BN_free(d);
    BN_free(order);
    if (static_cast<bool>(key) != theirs)
        f::divergence(T, "key validity " + f::hex(sk));
    if (!key)
        return 0;
    const auto pub = key->public_key();
    const auto sig = p256::sign(*key, h);
    if (!openssl_verify(pub.uncompressed(), h, sig.jose()))
        f::divergence(T, "OpenSSL does not verify our signature: key " + f::hex(sk) + " hash " + f::hex(h));

    // An adversarial signature
    auto adv = sig;
    if (mode & 8)
        adv.r = edge(in.byte());
    if (mode & 16)
        adv.s = edge(in.byte());
    if (mode & 32) {   // n - s
        const auto n = edge(3);
        int borrow = 0;
        for (int i = 31; i >= 0; --i) {
            const int v = n[i] - adv.s[i] - borrow;
            borrow = v < 0;
            adv.s[i] = static_cast<std::uint8_t>(v + (borrow ? 256 : 0));
        }
    }
    if (mode & 64) {
        const std::uint8_t at = in.byte();
        (at & 0x80 ? adv.s : adv.r)[at & 31] ^= static_cast<std::uint8_t>(1u << (in.byte() & 7));
    }
    const bool ours_ok = static_cast<bool>(p256::verify(pub, h, adv));
    if (ours_ok != openssl_verify(pub.compressed(), h, adv.jose()))
        f::divergence(T, "verify " + f::hex(adv.jose()) + " key " + f::hex(pub.compressed()) + " hash " + f::hex(h));
    return 0;
}

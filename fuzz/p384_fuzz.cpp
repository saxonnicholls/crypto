//
//  p384_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of P-384 against OpenSSL: key validity and public keys byte for byte; a signature made by
//  OpenSSL (its nonces random) verified here; then that signature made adversarial (r or s replaced by 0, 1,
//  n - 1, n, n + 1, p, 2^384 - 1, by n - s, or bits flipped) verified by both; ECDH with a second key (the shared
//  secret byte for byte against OpenSSL's d Q); and arbitrary bytes as SEC1.
//
//  The stated rule: verification, key validity and SEC1 parsing agree both ways, except that OpenSSL reads SEC1's
//  hybrid form (0x06, 0x07), which this library refuses.
//
#include "support/fuzz_support.hpp"

#include <snicholls/crypto/p384/ecdh.hpp>
#include <snicholls/crypto/p384/ecdsa.hpp>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <algorithm>

namespace f = snicholls::crypto::fuzz;
namespace p384 = snicholls::crypto::p384;

namespace {

// P-384's n, p, and the adversarial values
std::array<std::uint8_t, 48> edge(std::uint8_t which)
{
    static const char* table[] = {
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    };
    const char* h = table[which % 7];
    std::array<std::uint8_t, 48> out{};
    for (std::size_t i = 0; i < 48; ++i) {
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

bool openssl_verify(std::span<const std::uint8_t> pub, const std::array<std::uint8_t, 48>& h, const std::array<std::uint8_t, 96>& rs)
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_POINT* p = openssl_point(EC_KEY_get0_group(key), pub);
    bool ok = p && EC_KEY_set_public_key(key, p) == 1;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_bin2bn(rs.data(), 48, nullptr), BN_bin2bn(rs.data() + 48, 48, nullptr));
    ok = ok && ECDSA_do_verify(h.data(), 48, sig, key) == 1;
    ECDSA_SIG_free(sig);
    EC_POINT_free(p);
    EC_KEY_free(key);
    return ok;
}

// OpenSSL's signature of a hash with key d (a random nonce), as r || s
std::array<std::uint8_t, 96> openssl_sign(const std::array<std::uint8_t, 48>& d, const std::array<std::uint8_t, 48>& h)
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp384r1);
    BIGNUM* k = BN_bin2bn(d.data(), 48, nullptr);
    EC_KEY_set_private_key(key, k);
    EC_POINT* q = EC_POINT_new(EC_KEY_get0_group(key));
    EC_POINT_mul(EC_KEY_get0_group(key), q, k, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(key, q);
    ECDSA_SIG* sig = ECDSA_do_sign(h.data(), 48, key);
    std::array<std::uint8_t, 96> out{};
    if (sig) {
        BN_bn2binpad(ECDSA_SIG_get0_r(sig), out.data(), 48);
        BN_bn2binpad(ECDSA_SIG_get0_s(sig), out.data() + 48, 48);
    }
    ECDSA_SIG_free(sig);
    EC_POINT_free(q);
    BN_free(k);
    EC_KEY_free(key);
    return out;
}

// OpenSSL's d G (uncompressed) and d Q (its x-coordinate)
std::array<std::uint8_t, 97> openssl_public(const std::array<std::uint8_t, 48>& d)
{
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_POINT* r = EC_POINT_new(g);
    BIGNUM* k = BN_bin2bn(d.data(), 48, nullptr);
    std::array<std::uint8_t, 97> out{};
    if (EC_POINT_mul(g, r, k, nullptr, nullptr, nullptr) == 1)
        EC_POINT_point2oct(g, r, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), nullptr);
    BN_free(k);
    EC_POINT_free(r);
    EC_GROUP_free(g);
    return out;
}

std::array<std::uint8_t, 48> openssl_ecdh(const std::array<std::uint8_t, 48>& d, std::span<const std::uint8_t> pub)
{
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_POINT* q = openssl_point(g, pub);
    EC_POINT* r = EC_POINT_new(g);
    BIGNUM* k = BN_bin2bn(d.data(), 48, nullptr);
    BIGNUM* x = BN_new();
    std::array<std::uint8_t, 48> out{};
    if (q && EC_POINT_mul(g, r, nullptr, q, k, nullptr) == 1 && EC_POINT_get_affine_coordinates(g, r, x, nullptr, nullptr) == 1)
        BN_bn2binpad(x, out.data(), 48);
    BN_free(x);
    BN_free(k);
    EC_POINT_free(r);
    EC_POINT_free(q);
    EC_GROUP_free(g);
    return out;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("p384", data, size);
    const char* T = "p384";
    f::input in(data, size);
    const std::uint8_t mode = in.byte();

    if ((mode & 3) == 3) {   // arbitrary bytes as SEC1
        const auto b = in.rest();
        const auto ours = p384::public_key::parse(b);
        EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp384r1);
        EC_POINT* p = openssl_point(g, b);
        const bool theirs = p != nullptr && !EC_POINT_is_at_infinity(g, p);
        const bool hybrid = !b.empty() && (b[0] == 6 || b[0] == 7);
        if (static_cast<bool>(ours) != theirs && !(hybrid && theirs && !ours))
            f::divergence(T, "SEC1 " + f::hex(b));
        if (ours && theirs) {
            std::array<std::uint8_t, 49> c{};
            EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED, c.data(), c.size(), nullptr);
            if (c != ours->compressed())
                f::divergence(T, "SEC1 read differently: " + f::hex(b));
        }
        EC_POINT_free(p);
        EC_GROUP_free(g);
        return 0;
    }

    auto sk = in.take<48>();
    if (mode & 4)
        sk = edge(in.byte());
    const auto h = in.take<48>();
    const auto key = p384::private_key::from_bytes(sk);
    BIGNUM* d = BN_bin2bn(sk.data(), 48, nullptr);
    BIGNUM* order = BN_bin2bn(edge(3).data(), 48, nullptr);
    const bool theirs = !BN_is_zero(d) && BN_cmp(d, order) < 0;
    BN_free(d);
    BN_free(order);
    if (static_cast<bool>(key) != theirs)
        f::divergence(T, "key validity " + f::hex(sk));
    if (!key)
        return 0;
    const auto pub = key->public_key();
    if (pub.uncompressed() != openssl_public(sk))
        f::divergence(T, "public key differs from OpenSSL's: key " + f::hex(sk));

    // ECDH with a second key (when its bytes are a key), both ways
    if (const auto peer = p384::private_key::from_bytes(in.take<48>())) {
        const auto z = p384::shared_secret(*key, peer->public_key());
        const auto zz = p384::shared_secret(*peer, pub);
        if (!z || !zz || !(z.unwrap() == zz.unwrap()))
            f::divergence(T, "ECDH does not agree both ways: key " + f::hex(sk));
        else if (!std::equal(z.unwrap().reveal().begin(), z.unwrap().reveal().end(), openssl_ecdh(sk, peer->public_key().compressed()).begin()))
            f::divergence(T, "ECDH differs from OpenSSL's: key " + f::hex(sk));
    }

    // OpenSSL's signature, verified here; then made adversarial and verified by both
    const auto rs = openssl_sign(sk, h);
    const auto sig = p384::signature::from_jose(rs);
    if (!p384::verify(pub, h, sig))
        f::divergence(T, "OpenSSL's signature does not verify here: key " + f::hex(sk) + " hash " + f::hex(h));
    auto adv = sig;
    if (mode & 8)
        adv.r = edge(in.byte());
    if (mode & 16)
        adv.s = edge(in.byte());
    if (mode & 32) {   // n - s
        const auto n = edge(3);
        int borrow = 0;
        for (int i = 47; i >= 0; --i) {
            const int v = n[i] - adv.s[i] - borrow;
            borrow = v < 0;
            adv.s[i] = static_cast<std::uint8_t>(v + (borrow ? 256 : 0));
        }
    }
    if (mode & 64) {
        const std::uint8_t at = in.byte();
        (at & 0x80 ? adv.s : adv.r)[at % 48] ^= static_cast<std::uint8_t>(1u << (in.byte() & 7));
    }
    const bool ours_ok = static_cast<bool>(p384::verify(pub, h, adv));
    if (ours_ok != openssl_verify(pub.compressed(), h, adv.jose()))
        f::divergence(T, "verify " + f::hex(adv.jose()) + " key " + f::hex(pub.compressed()) + " hash " + f::hex(h));
    return 0;
}

//
//  openssl_oracle.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  OpenSSL as a fuzz oracle: ECDSA verification on secp256k1 (textbook: either s), whether a DER signature is
//  canonical (OpenSSL's own check: it parses and must re-encode to the same bytes), Ed25519 and X25519.
//  Test-only; the low-level EC_KEY interface is used for its directness (deprecated in OpenSSL 3, still present).
//

#ifndef snicholls_crypto_fuzz_openssl_oracle_hpp
#define snicholls_crypto_fuzz_openssl_oracle_hpp

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

namespace snicholls::crypto::fuzz::openssl {

inline bool ecdsa_verify(const std::array<std::uint8_t, 65>& pub, const std::array<std::uint8_t, 32>& h,
                         const std::array<std::uint8_t, 64>& rs)
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_POINT* p = EC_POINT_new(EC_KEY_get0_group(key));
    bool ok = EC_POINT_oct2point(EC_KEY_get0_group(key), p, pub.data(), pub.size(), nullptr) == 1 &&
              EC_KEY_set_public_key(key, p) == 1;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_bin2bn(rs.data(), 32, nullptr), BN_bin2bn(rs.data() + 32, 32, nullptr));
    ok = ok && ECDSA_do_verify(h.data(), 32, sig, key) == 1;
    ECDSA_SIG_free(sig);
    EC_POINT_free(p);
    EC_KEY_free(key);
    return ok;
}

inline bool der_is_canonical(std::span<const std::uint8_t> der)
{
    const unsigned char* p = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    if (!sig)
        return false;
    unsigned char* out = nullptr;
    const int n = i2d_ECDSA_SIG(sig, &out);
    const bool same = n == static_cast<int>(der.size()) && p == der.data() + der.size() &&
                      std::equal(der.begin(), der.end(), out);
    OPENSSL_free(out);
    ECDSA_SIG_free(sig);
    return same;
}

inline std::optional<std::array<std::uint8_t, 64>> ed25519_sign(const std::array<std::uint8_t, 32>& seed,
                                                                 std::span<const std::uint8_t> m,
                                                                 std::array<std::uint8_t, 32>& pub)
{
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), 32);
    std::size_t pn = 32;
    EVP_PKEY_get_raw_public_key(k, pub.data(), &pn);
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    std::array<std::uint8_t, 64> sig{};
    std::size_t n = 64;
    const bool ok = EVP_DigestSignInit(c, nullptr, nullptr, nullptr, k) == 1 &&
                    EVP_DigestSign(c, sig.data(), &n, m.data(), m.size()) == 1;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    if (!ok)
        return std::nullopt;
    return sig;
}

inline bool ed25519_verify(const std::array<std::uint8_t, 32>& pub, std::span<const std::uint8_t> m,
                           const std::array<std::uint8_t, 64>& sig)
{
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), 32);
    if (!k)
        return false;
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    const bool ok = EVP_DigestVerifyInit(c, nullptr, nullptr, nullptr, k) == 1 &&
                    EVP_DigestVerify(c, sig.data(), 64, m.data(), m.size()) == 1;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    return ok;
}

inline std::optional<std::array<std::uint8_t, 32>> x25519(const std::array<std::uint8_t, 32>& k,
                                                          const std::array<std::uint8_t, 32>& u)
{
    EVP_PKEY* a = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, k.data(), 32);
    EVP_PKEY* b = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, u.data(), 32);
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(a, nullptr);
    std::array<std::uint8_t, 32> out{};
    std::size_t n = 32;
    const bool ok = c && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, b) == 1 &&
                    EVP_PKEY_derive(c, out.data(), &n) == 1;
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    if (!ok)
        return std::nullopt;
    return out;
}

} // namespace snicholls::crypto::fuzz::openssl

#endif /* snicholls_crypto_fuzz_openssl_oracle_hpp */

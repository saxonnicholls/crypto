//
//  rsa_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of RSA verification against OpenSSL: PKCS#1 v1.5 and PSS with SHA-256 over Wycheproof's
//  2048-, 3072- and 4096-bit keys (read from tests/fixtures/wycheproof/), on signatures and messages from the seed
//  corpus, mutated; and arbitrary bytes as a SubjectPublicKeyInfo. A verdict that differs aborts with the case.
//
//  The stated rules: verification must agree both ways. For key parsing, what this library reads OpenSSL must read
//  to the same modulus and exponent; OpenSSL may read keys this library refuses only outside its limits (a modulus
//  outside 2048 to 4096 bits, an exponent above 64 bits) or by its own leniency: OpenSSL 3.0 reads an INTEGER whose
//  top bit is set (negative in DER) as its unsigned magnitude, which this library and OpenSSL 4.0 refuse; and it
//  accepts rsaEncryption parameters other than the NULL RFC 3279 requires, and an even modulus. A bare RSAPublicKey, which from_spki_der
//  also reads, is compared with OpenSSL's d2i_RSAPublicKey.
//
#include "support/fuzz_support.hpp"

#include <snicholls/crypto/rsa/rsa.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace f = snicholls::crypto::fuzz;
namespace rsa = snicholls::crypto::rsa;

namespace {

std::vector<std::uint8_t> unhex(const std::string& h)
{
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}

// The SubjectPublicKeyInfo of each Wycheproof key size
const std::vector<std::vector<std::uint8_t>>& keys()
{
    static const std::vector<std::vector<std::uint8_t>> k = [] {
        std::vector<std::vector<std::uint8_t>> out;
        for (const char* name : {"rsa_pkcs1_2048_sha256.txt", "rsa_pkcs1_3072_sha256.txt", "rsa_pkcs1_4096_sha256.txt"}) {
            std::ifstream in(std::string(SNICHOLLS_CRYPTO_SOURCE_DIR) + "/tests/fixtures/wycheproof/" + name);
            for (std::string line; std::getline(in, line);)
                if (line.rfind("key - ", 0) == 0) {
                    std::istringstream fields(line.substr(6));
                    std::string spki;
                    fields >> spki;
                    out.push_back(unhex(spki));
                    break;
                }
        }
        if (out.size() != 3)
            std::abort();
        return out;
    }();
    return k;
}

// Whether the modulus or exponent INTEGER of a SubjectPublicKeyInfo has its top bit set (a negative DER INTEGER)
bool integer_sign_bit_set(std::span<const std::uint8_t> der)
{
    using rsa::detail::der_reader;
    der_reader outer(der);
    const auto seq = outer.next(0x30);
    if (!seq)
        return false;
    der_reader in(*seq);
    if (!in.next(0x30))
        return false;
    const auto bits = in.next(0x03);
    if (!bits || bits->empty())
        return false;
    der_reader key(bits->subspan(1));
    const auto pub = key.next(0x30);
    if (!pub)
        return false;
    der_reader ints(*pub);
    for (int i = 0; i < 2; ++i) {
        const auto v = ints.next(0x02);
        if (v && !v->empty() && ((*v)[0] & 0x80))
            return true;
    }
    return false;
}

// Whether a SubjectPublicKeyInfo's AlgorithmIdentifier is rsaEncryption with NULL parameters (or the input is a bare
// RSAPublicKey, which has none)
bool null_parameters(std::span<const std::uint8_t> der)
{
    using rsa::detail::der_reader;
    der_reader outer(der);
    const auto seq = outer.next(0x30);
    if (!seq)
        return true;
    der_reader in(*seq);
    const auto alg = in.next(0x30);
    if (!alg)
        return true;
    der_reader a(*alg);
    if (!a.next(0x06))
        return true;
    const auto null = a.next(0x05);
    return null && null->empty() && a.done();
}

bool openssl_verify(const std::vector<std::uint8_t>& spki, std::span<const std::uint8_t> m, std::span<const std::uint8_t> sig,
                    int salt /* -1: PKCS#1 v1.5 */)
{
    const unsigned char* p = spki.data();
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size()));
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pc = nullptr;
    bool ok = key && EVP_DigestVerifyInit(c, &pc, EVP_sha256(), nullptr, key) == 1;
    if (ok && salt >= 0)
        ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1 && EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, salt) == 1 &&
             EVP_PKEY_CTX_set_rsa_mgf1_md(pc, EVP_sha256()) == 1;
    ok = ok && EVP_DigestVerify(c, sig.data(), sig.size(), m.data(), m.size()) == 1;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(key);
    return ok;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("rsa", data, size);
    const char* T = "rsa";
    f::input in(data, size);
    const std::uint8_t mode = in.byte();

    if ((mode & 3) == 3) {   // arbitrary bytes as a SubjectPublicKeyInfo
        const auto der = in.rest();
        const auto ours = rsa::public_key::from_spki_der(der);
        const unsigned char* p = der.data();
        EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
        bool theirs = key && EVP_PKEY_base_id(key) == EVP_PKEY_RSA && p == der.data() + der.size();
        if (!key) {
            // from_spki_der also reads a bare RSAPublicKey, as documented: OpenSSL reads that with d2i_RSAPublicKey
            const unsigned char* q = der.data();
            if (RSA* r = d2i_RSAPublicKey(nullptr, &q, static_cast<long>(der.size()))) {
                if (q == der.data() + der.size()) {
                    key = EVP_PKEY_new();
                    EVP_PKEY_assign_RSA(key, r);
                    theirs = true;
                } else {
                    RSA_free(r);
                }
            }
        }
        if (ours && !theirs)
            f::divergence(T, "SPKI read here, not by OpenSSL: " + f::hex(der));
        if (ours && theirs) {
            BIGNUM* e = nullptr;
            EVP_PKEY_get_bn_param(key, "e", &e);
            const bool same = e && BN_get_word(e) == ours->exponent() && EVP_PKEY_get_bits(key) == static_cast<int>(ours->modulus_bits());
            BN_free(e);
            if (!same)
                f::divergence(T, "SPKI read differently: " + f::hex(der));
        }
        if (!ours && theirs) {
            const int bits = EVP_PKEY_get_bits(key);
            BIGNUM* e = nullptr;
            EVP_PKEY_get_bn_param(key, "e", &e);
            // OpenSSL 3.0's rule, found by this target: it reads an INTEGER with its top bit set (negative in DER) as the
            // unsigned magnitude; this library refuses it (and so does OpenSSL 4.0, through cryptography). Seen here
            // in the DER itself, since OpenSSL keeps no sign to ask about
            const bool negative = integer_sign_bit_set(der);
            // OpenSSL 3.0's rule: rsaEncryption's parameters need not be the NULL RFC 3279 requires
            const bool parameters = !null_parameters(der);
            // OpenSSL 3.0's rule: an even modulus is read as a key (no RSA modulus is even)
            BIGNUM* n = nullptr;
            EVP_PKEY_get_bn_param(key, "n", &n);
            const bool even = n && !BN_is_odd(n);
            BN_free(n);
            const bool outside = negative || parameters || even || bits < 2048 || bits > 4096 || !e || BN_num_bits(e) > 64 || !BN_is_odd(e) || BN_is_one(e);
            BN_free(e);
            // a bare RSAPublicKey is not a SubjectPublicKeyInfo; that is the only other difference
            if (!outside)
                f::divergence(T, "SPKI refused here for no stated reason: " + f::hex(der));
        }
        EVP_PKEY_free(key);
        return 0;
    }

    const auto& spki = keys()[in.byte() % 3];
    const auto key = rsa::public_key::from_spki_der(spki).unwrap();
    const std::size_t k = key.modulus_bytes();
    auto m = in.take_upto(64);
    auto sig = in.rest();
    if (mode & 4)
        sig.resize(k);   // the right length, zero-padded or cut
    const bool pss = mode & 1;
    const int salt = pss ? (mode >> 3) % 4 == 0 ? 32 : (mode >> 3) % 4 == 1 ? 0 : (mode >> 3) % 4 == 2 ? 20 : 64 : -1;
    const bool ours = pss ? static_cast<bool>(rsa::verify_pss_sha256(key, m, sig, static_cast<std::size_t>(salt)))
                          : static_cast<bool>(rsa::verify_pkcs1v15_sha256(key, m, sig));
    const bool theirs = openssl_verify(spki, m, sig, salt);
    if (ours != theirs)
        f::divergence(T, std::string(pss ? "PSS (salt " + std::to_string(salt) + ")" : "PKCS#1 v1.5") + " verdict, ours " +
                             (ours ? "valid" : "invalid") + ": key " + std::to_string(key.modulus_bits()) + " message " +
                             f::hex(m) + " signature " + f::hex(sig));
    return 0;
}

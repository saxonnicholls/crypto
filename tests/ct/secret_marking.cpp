//
//  secret_marking.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The constant-time check, in the style of ctgrind: every secret input (private keys, seeds, nonces' auxiliary
//  data, mnemonic entropy and text, X25519 secrets) is marked undefined for Valgrind's memcheck, and every secret
//  path of the library runs on it. Memcheck reports any conditional jump or memory address that depends on an
//  undefined byte, so a branch or a table index on a secret fails the run. The results the library deliberately
//  reveals go through ct::declassify, which this program maps to VALGRIND_MAKE_MEM_DEFINED; outputs (signatures,
//  public keys) are declassified here before they are used.
//
//      valgrind --error-exitcode=1 ./snicholls_crypto_ct_secret_marking            every secret path; must pass
//      valgrind --error-exitcode=1 ./snicholls_crypto_ct_secret_marking --control  a deliberate leak; must FAIL
//
//  Not covered, by design: the base58 codec on xprv text and BIP-39 text rendering's caller-side copies (documented
//  as variable time or the caller's), and verification (public data).
//

#include <valgrind/memcheck.h>

#define SNICHOLLS_CRYPTO_DECLASSIFY(pointer, size) VALGRIND_MAKE_MEM_DEFINED(pointer, size)

#include <snicholls/crypto/aead/aes128_gcm.hpp>
#include <snicholls/crypto/aead/aes256_gcm.hpp>
#include <snicholls/crypto/aead/aes_key_wrap.hpp>
#include <snicholls/crypto/aead/chacha20_poly1305.hpp>
#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/hd/slip10.hpp>
#include <snicholls/crypto/jose/ecdh_es.hpp>
#include <snicholls/crypto/p256/ecdh.hpp>
#include <snicholls/crypto/p256/ecdsa.hpp>
#include <snicholls/crypto/p384/ecdh.hpp>
#include <snicholls/crypto/p384/ecdsa.hpp>
#include <snicholls/crypto/rsa/sign.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/secp256k1/schnorr.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

template <class T>
void mark_secret(T& x)
{
    VALGRIND_MAKE_MEM_UNDEFINED(&x, sizeof x);
}

template <class T>
void make_public(T& x)
{
    VALGRIND_MAKE_MEM_DEFINED(&x, sizeof x);
}

int failures = 0;

void check(bool ok, const char* what)
{
    std::printf("  %-44s %s\n", what, ok ? "ok" : "WRONG");
    failures += !ok;
}

std::array<std::uint8_t, 32> bytes32(std::uint8_t first)
{
    std::array<std::uint8_t, 32> a{};
    for (std::size_t i = 0; i < 32; ++i)
        a[i] = static_cast<std::uint8_t>(first + 7 * i);
    a[0] = 0x3a;   // below n, for secp256k1
    return a;
}

void secp256k1_paths()
{
    using namespace snicholls::crypto::secp256k1;
    auto key_bytes = bytes32(1);
    mark_secret(key_bytes);
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    auto pub = key.public_key();
    make_public(pub);
    check(public_key::parse(pub.compressed()).is_ok(), "secp256k1 public key");

    std::array<std::uint8_t, 32> hash{};
    hash[0] = 1;
    auto sig = sign(key, hash);
    make_public(sig);
    check(static_cast<bool>(verify(pub, hash, sig.sig)), "ECDSA sign (RFC 6979, low-S)");

    auto aux = bytes32(9);
    mark_secret(aux);
    auto xonly = xonly_public_key_of(key);
    auto ssig = schnorr_sign(key, hash, aux);
    make_public(xonly);
    make_public(ssig);
    check(static_cast<bool>(schnorr_verify(xonly, hash, ssig)), "BIP-340 sign");
}

void aead_paths()
{
    namespace aead = snicholls::crypto::aead;
    auto key = bytes32(5);
    std::array<std::uint8_t, 100> msg{};
    for (std::size_t i = 0; i < msg.size(); ++i)
        msg[i] = static_cast<std::uint8_t>(i * 13);
    mark_secret(key);
    mark_secret(msg);
    std::array<std::uint8_t, 24> nonce{};
    std::array<std::uint8_t, 100> ct{}, back{};
    auto tag = aead::xchacha20_poly1305_seal(key, nonce, {}, msg, ct).unwrap();
    make_public(ct);
    make_public(tag);
    const bool opened = aead::xchacha20_poly1305_open(key, nonce, {}, ct, tag, back).is_ok();
    make_public(back);
    make_public(msg);
    check(opened && back == msg, "XChaCha20-Poly1305 seal and open");

    std::array<std::uint8_t, 12> n12{};
    mark_secret(msg);
    auto gtag = aead::aes256_gcm_seal(key, n12, {}, msg, ct).unwrap();
    make_public(ct);
    make_public(gtag);
    const bool gopened = aead::aes256_gcm_open(key, n12, {}, ct, gtag, back).is_ok();
    make_public(back);
    make_public(msg);
    check(gopened && back == msg, "AES-256-GCM seal and open (the computed S-box)");

    auto key16 = std::span<const std::uint8_t, 16>(key.data(), 16);
    mark_secret(msg);
    auto g128 = aead::aes128_gcm_seal(key16, n12, {}, msg, ct).unwrap();
    make_public(ct);
    make_public(g128);
    const bool g128_opened = aead::aes128_gcm_open(key16, n12, {}, ct, g128, back).is_ok();
    make_public(back);
    make_public(msg);
    check(g128_opened && back == msg, "AES-128-GCM seal and open");

    std::array<std::uint8_t, 32> cek{};
    for (std::size_t i = 0; i < cek.size(); ++i)
        cek[i] = static_cast<std::uint8_t>(i);
    mark_secret(cek);
    std::array<std::uint8_t, 40> wrapped{};
    std::array<std::uint8_t, 32> unwrapped{};
    (void)aead::aes256_key_wrap(key, cek, wrapped);
    make_public(wrapped);
    const bool uw = aead::aes256_key_unwrap(key, wrapped, unwrapped).is_ok();
    make_public(unwrapped);
    make_public(cek);
    check(uw && unwrapped == cek, "AES-256 key wrap and unwrap");
}

void p256_paths()
{
    namespace p256 = snicholls::crypto::p256;
    auto key_bytes = bytes32(3);   // 0x3a... is below P-256's n too
    mark_secret(key_bytes);
    const auto key = p256::private_key::from_bytes(key_bytes).unwrap();
    auto pub = key.public_key();
    make_public(pub);
    check(p256::public_key::parse(pub.compressed()).is_ok(), "P-256 public key");

    std::array<std::uint8_t, 32> hash{};
    hash[0] = 1;
    auto sig = p256::sign(key, hash);
    make_public(sig);
    check(static_cast<bool>(p256::verify(pub, hash, sig)), "P-256 ECDSA sign (RFC 6979)");
}

// P-256 ECDH and JOSE's ECDH-ES on both curves: the private keys secret, the peers' keys public
// P-384: a private key's validity, its public key and ECDH, the keys secret, the peers' keys public
void p384_paths()
{
    namespace p384 = snicholls::crypto::p384;
    std::array<std::uint8_t, 48> a{}, b{};
    for (std::size_t i = 0; i < 48; ++i) {
        a[i] = static_cast<std::uint8_t>(0x3a + 7 * i);
        b[i] = static_cast<std::uint8_t>(0x29 + 11 * i);
    }
    a[0] = b[0] = 0x3a;   // below n
    mark_secret(a);
    mark_secret(b);
    const auto ka = p384::private_key::from_bytes(a).unwrap(), kb = p384::private_key::from_bytes(b).unwrap();
    auto pa = ka.public_key(), pb = kb.public_key();
    make_public(pa);
    make_public(pb);
    check(p384::public_key::parse(pa.compressed()).is_ok(), "P-384 public key");
    auto za = p384::shared_secret(ka, pb).unwrap(), zb = p384::shared_secret(kb, pa).unwrap();
    auto equal = za == zb;
    make_public(equal);
    check(equal, "P-384 ECDH shared secret");
}

void jose_paths()
{
    using namespace snicholls::crypto;
    auto a = bytes32(17), b = bytes32(19);
    mark_secret(a);
    mark_secret(b);
    const auto ka = p256::private_key::from_bytes(a).unwrap(), kb = p256::private_key::from_bytes(b).unwrap();
    auto pa = ka.public_key(), pb = kb.public_key();
    make_public(pa);
    make_public(pb);
    auto za = p256::shared_secret(ka, pb).unwrap(), zb = p256::shared_secret(kb, pa).unwrap();
    auto equal = za == zb;
    make_public(equal);
    check(equal, "P-256 ECDH shared secret");

    const std::array<std::uint8_t, 5> apu{'A', 'l', 'i', 'c', 'e'};
    auto ja = jose::ecdh_es_p256<32>(ka, pb, "ECDH-ES+A256KW", apu).unwrap(), jb = jose::ecdh_es_p256<32>(kb, pa, "ECDH-ES+A256KW", apu).unwrap();
    equal = ja == jb;
    make_public(equal);
    check(equal, "JOSE ECDH-ES on P-256 (Concat KDF)");

    const secret_bytes<32> sa{std::span<const std::uint8_t, 32>(a)}, sb{std::span<const std::uint8_t, 32>(b)};
    auto xa = x25519::public_key_from_secret(sa), xb = x25519::public_key_from_secret(sb);
    make_public(xa);
    make_public(xb);
    auto ea = jose::ecdh_es_x25519<64>(sa, xb, "A256CBC-HS512").unwrap(), eb = jose::ecdh_es_x25519<64>(sb, xa, "A256CBC-HS512").unwrap();
    equal = ea == eb;
    make_public(equal);
    check(equal, "JOSE ECDH-ES on X25519, 64 bytes");
}

// RSA signing: p, q, dP, dQ and qInv secret (Wycheproof's published 2048-bit test key); n, e and the message public.
// Reading the key runs its checks and its consistency signature, so both paths are under memcheck
void rsa_paths()
{
    namespace rsa = snicholls::crypto::rsa;
    static std::uint8_t n[] = {162, 180, 81, 160, 125, 10, 165, 249, 110, 69, 86, 113, 81, 53, 80, 81, 74, 138, 91, 70, 46, 190, 247, 23, 9, 79, 161, 254, 232, 34, 36, 230, 55, 249, 116, 109, 63, 124, 175, 211, 24, 120, 216, 3, 37, 182, 239, 90, 23, 0, 246, 89, 3, 180, 105, 66, 158, 137, 214, 234, 200, 132, 80, 151, 181, 171, 57, 49, 137, 219, 146, 81, 46, 216, 167, 113, 26, 18, 83, 250, 205, 32, 247, 156, 21, 232, 36, 127, 61, 62, 66, 228, 110, 72, 201, 142, 37, 74, 47, 233, 118, 83, 19, 160, 62, 255, 143, 23, 225, 160, 41, 57, 122, 31, 162, 106, 141, 206, 38, 244, 144, 237, 129, 41, 150, 21, 217, 129, 76, 34, 218, 97, 4, 40, 224, 156, 125, 150, 88, 89, 66, 102, 245, 192, 33, 208, 252, 236, 160, 141, 148, 90, 18, 190, 130, 222, 77, 30, 206, 107, 76, 3, 20, 91, 93, 52, 149, 212, 237, 84, 17, 235, 135, 141, 175, 5, 253, 122, 252, 62, 9, 173, 160, 241, 18, 100, 34, 245, 144, 151, 90, 25, 105, 129, 111, 72, 105, 139, 203, 186, 27, 77, 156, 174, 121, 212, 96, 216, 249, 248, 94, 121, 117, 0, 93, 155, 194, 44, 78, 90, 192, 247, 193, 164, 93, 18, 86, 154, 98, 128, 125, 59, 154, 2, 229, 165, 48, 231, 115, 6, 111, 69, 61, 31, 91, 76, 46, 156, 247, 130, 2, 131, 247, 66, 185, 213};
    static std::uint8_t e[] = {1, 0, 1};
    static std::uint8_t p[] = {220, 67, 16, 80, 247, 130, 232, 148, 251, 82, 72, 36, 125, 152, 203, 125, 88, 184, 209, 226, 79, 59, 85, 208, 65, 197, 110, 77, 224, 134, 176, 213, 187, 2, 139, 218, 66, 238, 181, 210, 52, 213, 104, 30, 88, 9, 212, 21, 230, 162, 137, 173, 76, 251, 247, 143, 151, 143, 108, 53, 129, 79, 80, 238, 191, 241, 197, 184, 10, 105, 247, 136, 232, 30, 107, 171, 93, 218, 167, 131, 105, 214, 89, 209, 67, 236, 111, 23, 231, 152, 19, 165, 117, 207, 173, 156, 86, 145, 86, 185, 1, 19, 226, 233, 17, 10, 217, 231, 180, 138, 28, 147, 72, 166, 230, 83, 50, 17, 145, 41, 14, 163, 108, 251, 58, 91, 24, 241};
    static std::uint8_t q[] = {189, 26, 129, 231, 151, 127, 152, 152, 18, 34, 115, 174, 50, 34, 181, 152, 234, 95, 177, 158, 180, 234, 188, 56, 48, 138, 94, 50, 25, 102, 3, 178, 229, 0, 255, 183, 159, 91, 136, 104, 22, 97, 29, 235, 196, 114, 250, 196, 85, 68, 7, 11, 235, 5, 124, 148, 19, 120, 166, 134, 138, 243, 183, 160, 61, 63, 152, 128, 236, 71, 213, 224, 137, 185, 79, 189, 229, 66, 171, 169, 174, 141, 114, 197, 112, 136, 215, 171, 245, 177, 49, 243, 144, 152, 247, 188, 22, 15, 144, 83, 106, 188, 148, 146, 253, 78, 6, 243, 237, 114, 153, 212, 185, 123, 176, 54, 119, 32, 125, 149, 102, 159, 20, 12, 251, 194, 15, 37};
    static std::uint8_t dp[] = {169, 75, 82, 139, 40, 242, 145, 89, 145, 33, 217, 25, 82, 255, 209, 199, 242, 29, 124, 20, 121, 217, 157, 71, 136, 133, 251, 22, 24, 112, 238, 18, 24, 191, 8, 71, 38, 18, 219, 229, 73, 126, 141, 156, 101, 6, 136, 224, 156, 120, 105, 97, 174, 62, 44, 53, 77, 196, 138, 227, 69, 20, 117, 156, 76, 35, 196, 88, 132, 136, 150, 29, 192, 107, 65, 78, 97, 192, 225, 231, 251, 189, 41, 35, 211, 21, 50, 254, 40, 159, 150, 218, 34, 7, 17, 229, 140, 20, 1, 152, 8, 224, 4, 20, 39, 105, 51, 187, 7, 228, 239, 185, 180, 169, 179, 118, 86, 145, 114, 5, 32, 159, 51, 240, 149, 21, 215, 193};
    static std::uint8_t dq[] = {58, 240, 231, 42, 147, 58, 239, 9, 255, 37, 3, 223, 120, 186, 254, 213, 49, 192, 47, 241, 162, 188, 67, 124, 84, 12, 220, 189, 74, 211, 84, 53, 207, 81, 23, 99, 89, 101, 67, 72, 6, 41, 177, 20, 202, 127, 120, 15, 247, 239, 163, 46, 160, 203, 110, 0, 13, 109, 158, 161, 242, 239, 113, 253, 156, 249, 148, 132, 34, 161, 101, 85, 126, 55, 231, 85, 237, 254, 112, 217, 11, 146, 5, 2, 235, 71, 139, 201, 138, 99, 247, 136, 206, 58, 15, 133, 109, 110, 222, 114, 81, 163, 131, 191, 168, 250, 72, 10, 129, 169, 37, 175, 123, 60, 197, 56, 196, 186, 184, 201, 247, 89, 127, 251, 104, 1, 29, 141};
    static std::uint8_t qinv[] = {38, 64, 251, 251, 207, 239, 177, 99, 238, 122, 135, 182, 72, 58, 102, 238, 65, 249, 86, 217, 15, 168, 167, 147, 155, 252, 4, 46, 224, 146, 75, 27, 121, 147, 208, 68, 95, 117, 141, 81, 147, 62, 133, 23, 156, 3, 32, 176, 201, 104, 180, 138, 145, 195, 139, 91, 233, 35, 225, 9, 124, 12, 86, 47, 136, 212, 34, 148, 182, 162, 117, 155, 175, 165, 66, 138, 116, 241, 39, 8, 116, 228, 95, 111, 204, 96, 242, 22, 2, 222, 94, 204, 209, 67, 207, 49, 36, 31, 89, 33, 181, 173, 57, 131, 251, 84, 239, 23, 190, 59, 40, 83, 103, 229, 12, 153, 156, 103, 36, 123, 85, 47, 228, 191, 206, 148, 95, 123};
    mark_secret(p);
    mark_secret(q);
    mark_secret(dp);
    mark_secret(dq);
    mark_secret(qinv);
    auto key = rsa::private_key::from_components(n, e, p, q, dp, dq, qinv);
    check(key.is_ok(), "RSA private key (checks, consistency signature)");
    if (!key.is_ok())
        return;
    const std::array<std::uint8_t, 5> msg{1, 2, 3, 4, 5};
    std::array<std::uint8_t, 256> sig{};
    const bool signed_ok = rsa::sign_pkcs1v15_sha256(*key, msg, sig).is_ok();
    check(signed_ok && rsa::verify_pkcs1v15_sha256(key->public_key(), msg, sig).is_ok(), "RSA PKCS#1 v1.5 sign (CRT, fixed window)");
}

void hd_paths()
{
    using namespace snicholls::crypto::hd;
    std::array<std::uint8_t, 64> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<std::uint8_t>(i * 3 + 1);
    mark_secret(seed);
    const auto m = extended_private_key::from_seed(seed).unwrap();
    const auto hard = m.derive_child(hardened(44)).unwrap();
    const auto soft = hard.derive_child(0).unwrap();
    auto pub = soft.public_key();
    make_public(pub);
    auto fp = hard.fingerprint();
    make_public(fp);
    check(pub.parent == fp, "BIP-32 hardened and non-hardened CKDpriv");

    const auto s = slip10_ed25519_key::from_seed(seed).unwrap();
    const auto child = s.derive(derivation_path::parse("m/44'/501'/0'/0'").unwrap()).unwrap();
    auto spub = child.public_key();
    make_public(spub);
    check(spub.bytes != std::array<std::uint8_t, 32>{}, "SLIP-10 Ed25519 derivation");
}

void curve25519_paths()
{
    using namespace snicholls::crypto;
    auto seed = bytes32(5);
    mark_secret(seed);
    const auto kp = ed25519::key_pair::from_seed(std::span<const std::uint8_t, 32>(seed));
    const std::array<std::uint8_t, 5> msg{1, 2, 3, 4, 5};
    auto sig = kp.sign(msg);
    auto pub = kp.public_key();
    make_public(sig);
    make_public(pub);
    check(static_cast<bool>(ed25519::verify(pub, msg, sig)), "Ed25519 key pair and sign");

    auto a = bytes32(11), b = bytes32(13);
    mark_secret(a);
    mark_secret(b);
    const secret_bytes<32> sa{std::span<const std::uint8_t, 32>(a)}, sb{std::span<const std::uint8_t, 32>(b)};
    auto pa = x25519::public_key_from_secret(sa), pb = x25519::public_key_from_secret(sb);
    make_public(pa);
    make_public(pb);
    auto ka = x25519::shared_secret(sa, pb).unwrap(), kb = x25519::shared_secret(sb, pa).unwrap();
    auto equal = ka == kb;
    make_public(equal);
    check(equal, "X25519 public keys and shared secret");
}

void bip39_paths()
{
    using namespace snicholls::crypto::bip39;
    std::array<std::uint8_t, 32> entropy{};
    for (std::size_t i = 0; i < entropy.size(); ++i)
        entropy[i] = static_cast<std::uint8_t>(0x5a ^ (i * 29));
    mark_secret(entropy);
    const auto words = from_entropy(entropy).unwrap();
    std::array<char, max_text_length> text{};
    std::size_t n = words.to_text(text);
    make_public(n);   // the text's length is public (it is what a person types), as the library documents
    const auto parsed = parse(std::string_view(text.data(), n)).unwrap();
    auto same = parsed == words;
    make_public(same);
    check(same, "BIP-39 entropy to text and back");
    auto seed = to_seed(parsed, "TREZOR").unwrap();
    auto first = seed.reveal()[0];
    make_public(first);
    check(true, "BIP-39 seed (PBKDF2-HMAC-SHA512)");
}

// The negative control: a table lookup and a branch on a secret, which memcheck must report
__attribute__((noinline)) int leaky(std::uint8_t secret)
{
    static const int table[256] = {1};
    if (secret > 128)
        return table[secret];
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc > 1 && std::strcmp(argv[1], "--control") == 0) {
        std::uint8_t s = 200;
        mark_secret(s);
        const int r = leaky(s);
        std::printf("control: %d (memcheck must have reported the branch and the index above)\n", r == 0);
        return 0;
    }
    std::printf("secret marking: every secret input undefined for memcheck\n");
    secp256k1_paths();
    p256_paths();
    aead_paths();
    p384_paths();
    jose_paths();
    rsa_paths();
    hd_paths();
    curve25519_paths();
    bip39_paths();
    std::printf("%s\n", failures == 0 ? "all paths ran" : "results wrong");
    return failures == 0 ? 0 : 2;
}

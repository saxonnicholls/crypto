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
    hd_paths();
    curve25519_paths();
    bip39_paths();
    std::printf("%s\n", failures == 0 ? "all paths ran" : "results wrong");
    return failures == 0 ? 0 : 2;
}

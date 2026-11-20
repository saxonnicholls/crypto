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

#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/hd/slip10.hpp>
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
    hd_paths();
    curve25519_paths();
    bip39_paths();
    std::printf("%s\n", failures == 0 ? "all paths ran" : "results wrong");
    return failures == 0 ? 0 : 2;
}

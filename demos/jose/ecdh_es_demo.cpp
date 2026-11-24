//
//  ecdh_es_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// JOSE's ECDH-ES: RFC 7518 appendix C's key on P-256 (A128GCM, "Alice" and "Bob"), then a JWE recipient's work for
// ECDH-ES+A256KW on X25519: the key-encryption key from the epk, the CEK unwrapped, the content opened.
#include <snicholls/crypto/aead/aes256_gcm.hpp>
#include <snicholls/crypto/aead/aes_key_wrap.hpp>
#include <snicholls/crypto/jose/ecdh_es.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <array>
#include <cstdio>
#include <string>
#include <string_view>

int main()
{
    using namespace snicholls::crypto;
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    //! [ecdh_es]
    // RFC 7518 appendix C: Bob, the recipient, derives the A128GCM key from Alice's epk ("apu": "QWxpY2U", "Alice";
    // "apv": "Qm9i", "Bob"). The keys are the RFC's published test keys
    const auto bob = p256::private_key::from_bytes(hex<32>("5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc")).unwrap();
    const auto epk = p256::private_key::from_bytes(hex<32>("d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a")).unwrap().public_key();
    const std::array<std::uint8_t, 5> apu{'A', 'l', 'i', 'c', 'e'};
    const std::array<std::uint8_t, 3> apv{'B', 'o', 'b'};
    auto cek = jose::ecdh_es_p256<16>(bob, epk, "A128GCM", apu, apv);   // "alg": "ECDH-ES": the algorithm is enc

    // ECDH-ES+A256KW on X25519 (RFC 7748's test secrets): the sender wraps a CEK and encrypts, the recipient
    // derives the same key-encryption key (the algorithm is alg), unwraps and opens
    const secret_bytes<32> ephemeral(hex<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const secret_bytes<32> recipient(hex<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    const auto kek_sender = jose::ecdh_es_x25519<32>(ephemeral, x25519::public_key_from_secret(recipient), "ECDH-ES+A256KW").unwrap();
    const auto content_key = hex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto iv = hex<12>("000000000000000000000001");
    constexpr std::string_view header = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00ifQ";   // the protected header, as sent
    const std::span<const std::uint8_t> aad(reinterpret_cast<const std::uint8_t*>(header.data()), header.size());
    const std::array<std::uint8_t, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 40> encrypted_key{};
    std::array<std::uint8_t, 5> ciphertext{};
    const bool wrapped = aead::aes256_key_wrap(kek_sender.reveal(), content_key, encrypted_key).is_ok();
    const auto tag = aead::aes256_gcm_seal(content_key, iv, aad, message, ciphertext).unwrap();

    const auto kek = jose::ecdh_es_x25519<32>(recipient, x25519::public_key_from_secret(ephemeral), "ECDH-ES+A256KW").unwrap();
    std::array<std::uint8_t, 32> unwrapped{};
    std::array<std::uint8_t, 5> opened{};
    const bool ok = aead::aes256_key_unwrap(kek.reveal(), encrypted_key, unwrapped).is_ok() &&
                    aead::aes256_gcm_open(unwrapped, iv, aad, ciphertext, tag, opened).is_ok();
    //! [ecdh_es]
    const std::string k = cek.is_ok() ? to_hex(cek.unwrap().reveal()) : std::string();
    std::printf("RFC 7518 appendix C key %s\nECDH-ES+A256KW on X25519: wrapped %s, opened %s (\"%.*s\")\n", k.c_str(),
                wrapped ? "yes" : "no", ok ? "yes" : "no", static_cast<int>(opened.size()), reinterpret_cast<const char*>(opened.data()));
    secure_wipe(unwrapped);
    return k == "56aa8deaf8236d205c2228cd71a7101a" && wrapped && ok && opened == message ? 0 : 1;
}

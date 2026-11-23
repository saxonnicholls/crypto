//
//  rsa_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// RSA verification: Wycheproof's published 2048-bit test key read from its SubjectPublicKeyInfo and from its JWK-style
// components, an RS256 (PKCS#1 v1.5) and a PS256 (PSS) signature over the empty message verified, and a tampered
// signature refused.
#include <snicholls/crypto/rsa/rsa.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <span>
#include <string>
#include <vector>

int main()
{
    using snicholls::crypto::test::hex_bytes;
    auto view = [](const std::vector<std::uint8_t>& v) { return std::span<const std::uint8_t>(v.data(), v.size()); };
    const auto spki = hex_bytes(
        "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a2b451a07d0aa5f96e455671513550"
        "514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac88450"
        "97b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029"
        "397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece"
        "6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460"
        "d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9"
        "d50203010001");
    const auto n = hex_bytes(
        "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a"
        "1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e"
        "254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c0"
        "21d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a19"
        "69816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e77306"
        "6f453d1f5b4c2e9cf7820283f742b9d5");
    const auto e = hex_bytes(
        "010001");
    const auto rs256 = hex_bytes(
        "840f5dac53106dd1f9c57219224cf51289290c42f20466875ba8e830ac5690e541536fcc8ab03b731f82bf66d83f194e"
        "7e180b3963ec7a2f3f7904a7ce49aed47da4d4b79421eaf937d301b3e696169297b797c32c076a12be4de0b58e003c51"
        "23051a84a10c62f8dac2f42a8640008eb3c7cccd6760ff5b51b689763922582845f048fb8150e5a7a6ca2eccc7bdc853"
        "49ad5b26c52137a79fa3fe5c29ab5cd7615013219c1941b6708e9c3c23feff5febaf0c8ebca5750b54e3e6e99a3e876b"
        "396f27860b7f3ec4e9191703c6332d944f6f69751167680c79c4f6b57f1cc8755d24b6ec158ccdbacdb23107a33cb6b3"
        "32516c13274d1f9dccc21dced869e486");
    const auto ps256 = hex_bytes(
        "4f01e0c12b08625ecac89a69231906edf826380f37c959a96690d046316d68ffce9d5c471694fcebfc6b455348646892"
        "56e4fc81c78e583f675d0c94b449647451e81beff01a11a516d5e5ce3f1a910437cb8a3a5096b19fb15f4524a35b23d8"
        "9cdba12cf5b71aac1047b28c562df7c5542c34ce23a182cf7e0e231934b17294799d44877a1d68ef1b8f073619b7618e"
        "6b7c22db20030d98cf591ffc3d4da5f58613ecd5ecfc3b40a1d02f40891ca43695cd4c088b05a8054c89c595a47e2748"
        "16f35384226f74459ee63e25a1bfc03c360490552ec38343f8ace502f065303b00bc0ec320711b211fde92e57feb9013"
        "c3609342495ec0d7cabdec21e54acc38");
    //! [rsa]
    namespace rsa = snicholls::crypto::rsa;
    const auto key = rsa::public_key::from_spki_der(view(spki)).unwrap();        // a PEM "PUBLIC KEY", base64-decoded
    const auto same = rsa::public_key::from_components(view(n), view(e));        // a JWK's n and e, base64url-decoded
    const std::span<const std::uint8_t> message{};                               // for a JWS: "header.payload"
    const auto pkcs1 = rsa::verify_pkcs1v15_sha256(key, message, view(rs256));   // RS256
    const auto pss_ok = rsa::verify_pss_sha256(key, message, view(ps256));       // PS256, salt length 32
    auto tampered = rs256;
    tampered[100] ^= 1;
    const auto refused = rsa::verify_pkcs1v15_sha256(key, message, view(tampered));  // errc::invalid_signature
    //! [rsa]
    std::printf("key: %zu bits, e = %llu (from components: %s)\nRS256: %s\nPS256: %s\ntampered RS256: %s\n",
                key.modulus_bits(), static_cast<unsigned long long>(key.exponent()), same.is_ok() ? "same key" : "refused",
                pkcs1.is_ok() ? "valid" : "invalid", pss_ok.is_ok() ? "valid" : "invalid",
                refused.is_ok() ? "valid" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str());
    return key.modulus_bits() == 2048 && key.exponent() == 65537 && same.is_ok() && pkcs1.is_ok() && pss_ok.is_ok() &&
                   !refused.is_ok()
               ? 0
               : 1;
}

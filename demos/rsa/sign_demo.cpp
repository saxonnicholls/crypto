//
//  sign_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// RSA signing: Wycheproof's published 2048-bit test key read from its PKCS#8 DER, a message signed with RS256
// (PKCS#1 v1.5, deterministic: the bytes Wycheproof records), the signature verified, and a damaged key refused.
#include <snicholls/crypto/rsa/sign.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <span>
#include <string>
#include <vector>

int main()
{
    using snicholls::crypto::test::hex_bytes;
    using snicholls::crypto::test::to_hex;
    // A published test key (Wycheproof rsa_pkcs1_2048_sig_gen_test.json): never a key that protects anything
    auto pkcs8 = hex_bytes(
        "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a2b451a07d0aa5f96e45"
        "5671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89"
        "d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff"
        "8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be"
        "82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d"
        "9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf782"
        "0283f742b9d50203010001028201007627eef3567b2a27268e52053ecd31c3a7172ccb9ddcee819b306a5b3c66b7573c"
        "a4fa88efc6f3c4a00bfa0ae7139f64543a4dac3d05823f6ff477cfcec84fe2ac7a68b17204b390232e110310c4e899c4"
        "e7c10967db4acde042dbbf19dbe00b4b4741de1020aaaaffb5054c797c9f136f7d93ac3fc8caff6654242d7821ebee51"
        "7bf537f44366a0fdd45ae05b9909c2e6cc1ed9281eff4399f76c96b96233ec29ae0bbf0d752b234fc197389f51050aa1"
        "acd01c074c3ac8fbdb9ea8b651a95995e8db4ad5c43b6c8673e5a126e7ee94b8dff4c5afc01259bc8da76950bae6f8ba"
        "e715f50985b0d6f66d04c6fef3b700720eecdcdf171bb7b1ecbe7289c467c102818100dc431050f782e894fb5248247d"
        "98cb7d58b8d1e24f3b55d041c56e4de086b0d5bb028bda42eeb5d234d5681e5809d415e6a289ad4cfbf78f978f6c3581"
        "4f50eebff1c5b80a69f788e81e6bab5ddaa78369d659d143ec6f17e79813a575cfad9c569156b90113e2e9110ad9e7b4"
        "8a1c9348a6e653321191290ea36cfb3a5b18f102818100bd1a81e7977f9898122273ae3222b598ea5fb19eb4eabc3830"
        "8a5e32196603b2e500ffb79f5b886816611debc472fac45544070beb057c941378a6868af3b7a03d3f9880ec47d5e089"
        "b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc160f90536abc9492fd4e06f3ed7299d4b97bb03677207d9566"
        "9f140cfbc20f2502818100a94b528b28f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee1218bf084726"
        "12dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c4c23c4588488961dc06b414e61c0e1e7fbbd2923d3"
        "1532fe289f96da220711e58c14019808e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c10281803af0"
        "e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435cf511763596543480629b114ca7f780ff7ef"
        "a32ea0cb6e000d6d9ea1f2ef71fd9cf9948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f856d6e"
        "de7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d0281802640fbfbcfefb163ee7a87b6483a66"
        "ee41f956d90fa8a7939bfc042ee0924b1b7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c56"
        "2f88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf31241f5921b5ad3983fb54ef17be3b28"
        "5367e50c999c67247b552fe4bfce945f7b");
    const auto message = hex_bytes("0000000000000000000000000000000000000000");
    const std::string expected =
        "8a1b220cb2ab415dc760eb7f5bb10335a3cca269d7dbbf7d0962ba79f9cf7b43a5fc09c99a1584f07403473d6c189a83"
        "6897a5b6f8ea9fa22d601e6ba5f7411fe27c638b81b1a22363583a80fce8c7df3e40fb51bd0e60d0a6653f79f3bcb7ec"
        "3e9dc14cfb5b31ab1735bca692d50ac03f979dda92747c6430f8045efa3513ba6e0ce3e9e35570e1c30c8ebe589b4419"
        "2e1344ca83dfa576fc6fdc7bf1cd7cee875b001c8c02ce8d602769e4bd9d241c4857182a0089a8b67644e73eef105c55"
        "0efa47a40874289395ac0c4e02fd4ba98e130a4c2d1b95521c6af4a002ac3bdc6e52122ae4c08cc3da1c896e059acbdd"
        "ec574ac0432f6103dd97273d8803c102";
    //! [rsa_sign]
    namespace rsa = snicholls::crypto::rsa;
    // The DER of an unencrypted "PRIVATE KEY" (PEM's base64 decoded by the caller, into memory the caller wipes)
    auto key = rsa::private_key::from_pkcs8_der(pkcs8);   // checked, and proved by a signature, before it is a key
    std::vector<std::uint8_t> signature(key ? key->modulus_bytes() : 0);
    const bool signed_ok = key && rsa::sign_pkcs1v15_sha256(*key, message, signature).is_ok();   // RS256
    const bool verifies = signed_ok && rsa::verify_pkcs1v15_sha256(key->public_key(), message, signature).is_ok();
    // One bit of the key changed: refused when it is read, never a key that signs wrongly
    auto damaged = pkcs8;
    damaged[damaged.size() - 5] ^= 1;
    const auto refused = rsa::private_key::from_pkcs8_der(damaged);   // errc::invalid_private_key
    //! [rsa_sign]
    snicholls::crypto::secure_wipe(pkcs8.data(), pkcs8.size());
    snicholls::crypto::secure_wipe(damaged.data(), damaged.size());
    const bool same = to_hex(std::span<const std::uint8_t>(signature)) == expected;
    std::printf("RS256 signature (%zu bytes) %s...\nmatches Wycheproof: %s; verifies: %s; damaged key: %s\n", signature.size(),
                to_hex(std::span<const std::uint8_t>(signature)).substr(0, 32).c_str(), same ? "yes" : "no", verifies ? "yes" : "no",
                refused.is_ok() ? "accepted" : std::string(snicholls::crypto::to_string(refused.unwrap_err())).c_str());
    return signed_ok && same && verifies && !refused.is_ok() ? 0 : 1;
}

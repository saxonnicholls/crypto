//
//  ecdh_es.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief JOSE's ECDH-ES key agreement (RFC 7518 4.6, RFC 8037 for X25519): the key a JWE's content or key-wrapping
/// key comes from, on X25519 or P-256.
/// \ingroup jose
///
/// \overview
/// A JWE with `"alg": "ECDH-ES"` or `"ECDH-ES+A256KW"` carries the sender's ephemeral public key (`epk`). Both sides
/// compute the ECDH shared secret Z and put it through the Concat KDF (SHA-256, NIST SP 800-56A) with an OtherInfo
/// built from the header, which gives:
///
/// - for direct key agreement (`"alg": "ECDH-ES"`), the content encryption key itself: the algorithm in the
///   OtherInfo is the `enc` value (`"A256GCM"`) and the key is as long as `enc` needs;
/// - for key agreement with key wrapping (`"alg": "ECDH-ES+A256KW"`), the key-encryption key: the algorithm is the
///   `alg` value and the key is the wrap's (32 bytes for A256KW), which unwraps the JWE's encrypted key
///   (`aead/aes_key_wrap.hpp`) to the content encryption key.
///
/// | Algorithm in the OtherInfo | N, bytes |
/// |---|---|
/// | `A128GCM`, `ECDH-ES+A128KW` | 16 |
/// | `A192GCM`, `ECDH-ES+A192KW` | 24 |
/// | `A256GCM`, `ECDH-ES+A256KW`, `A128CBC-HS256` | 32 |
/// | `A192CBC-HS384` | 48 |
/// | `A256CBC-HS512` | 64 |
///
/// `apu` and `apv` are the header's values base64url-decoded (empty when absent). The functions:
///
/// - `ecdh_es_x25519<N>(own secret, peer's key, algorithm, apu, apv)`: X25519 (`"crv": "X25519"`, RFC 8037).
/// - `ecdh_es_p256<N>(own key, peer's key, algorithm, apu, apv)`: P-256 (`"crv": "P-256"`).
/// - `ecdh_es_kdf<N>(z, algorithm, apu, apv)`: the KDF alone, for a shared secret computed elsewhere.
///
/// The recipient passes its static private key and the `epk`; the sender passes a fresh ephemeral private key and
/// the recipient's public key, and puts the ephemeral public key in the header. The JOSE text (base64url, JSON) is
/// the caller's: this header takes and returns bytes.
///
/// \relations
/// - `curve25519/x25519.hpp`, `p256/ecdh.hpp`: the shared secrets; core's `hash/kdf.hpp`: `jwa_concat_kdf`.
/// - `aead/aes256_gcm.hpp` (A256GCM content encryption, with the ASCII of the protected header as the associated
///   data) and `aead/aes_key_wrap.hpp` (A256KW).
/// - Group: \ref jose.
///
/// \impls
/// One: core's `jwa_concat_kdf` with SHA-256, its hash states wiped (`detail/hashes.hpp`).
///
/// \contracts
/// - Constant time in the private key, the shared secret and the derived key; the peer's key, the algorithm, `apu`
///   and `apv` are public (their lengths and values decide only how much is hashed). Revealed on purpose
///   (`ct::declassify`): that X25519 gave the all-zero secret, or that d Q on P-256 is the identity (both errors).
/// - The derived key is in `secret_bytes<N>`; Z and every hash state are wiped.
/// - `constexpr`, `noexcept`, no allocation.
///
/// \errors
/// `ecdh_es_x25519`: `errc::small_order` when the peer's key has small order (the all-zero shared secret: refuse
/// the JWE). `ecdh_es_p256`: `errc::invalid_public_key` when the peer's point is not on the curve. `ecdh_es_kdf`
/// cannot fail.
///
/// \examples
/// \snippet jose/ecdh_es_demo.cpp ecdh_es
///
/// \perf
/// One X25519 or P-256 scalar multiplication and, for N up to 32, one SHA-256 block or two. See BENCHMARKS.md,
/// `benchmarks/jose/ecdh_es_benchmark.cpp`.
///
/// \testing
/// `tests/jose/ecdh_es_test.cpp`: RFC 7518 appendix C (P-256, A128GCM, "Alice" and "Bob", byte for byte), RFC 8037
/// appendix A.6 (X25519's shared secret), and complete JWEs, ECDH-ES and ECDH-ES+A256KW with A256GCM on both curves,
/// made by an independent JOSE library and decrypted here (`tests/jose/ecdh_es_oracles_test.cpp`). The secret paths
/// are in the Valgrind check (`tests/ct/secret_marking.cpp`). `demos/jose/ecdh_es_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`, `<string_view>`; core's `result.hpp` and `hash/kdf.hpp`.
///
/// \gotchas
/// - The algorithm is `enc` for direct agreement and `alg` with key wrapping: the wrong one gives a wrong key, and the
///   JWE then fails authentication, not decoding.
/// - N must be the length the algorithm needs (the table): it is in the OtherInfo, so a longer key is not a prefix
///   of a shorter one's derivation.
/// - The sender's ephemeral key must be fresh for every JWE, from a system random source; this library takes it, it
///   does not make it.
/// - Check the `epk`'s curve against the recipient's key before calling: X25519 bytes on P-256 do not decode, but a
///   P-256 key is not refused by X25519.
///
/// \status
/// Experimental (0.5).

#ifndef snicholls_crypto_jose_ecdh_es_hpp
#define snicholls_crypto_jose_ecdh_es_hpp

#include <snicholls/core/result.hpp>
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/p256/ecdh.hpp>
#include <snicholls/crypto/p256/ecdsa.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

/// \brief JOSE (JWE, RFC 7516 and 7518): the key agreement.
namespace snicholls::crypto::jose {

/// \brief JOSE's Concat KDF (RFC 7518 4.6.2, SHA-256): an N-byte key from a shared secret and the header's fields.
/// \ingroup jose
/// \tparam N The key length in bytes, 16 to 64 (see the file's table).
/// \param z The ECDH shared secret (secret).
/// \param algorithm The `enc` value for `"alg": "ECDH-ES"`, else the `alg` value (`"ECDH-ES+A256KW"`).
/// \param apu The `apu` header value, base64url-decoded; empty when absent.
/// \param apv The `apv` header value, base64url-decoded; empty when absent.
/// \return The key.
template <std::size_t N>
[[nodiscard]] constexpr secret_bytes<N> ecdh_es_kdf(std::span<const std::uint8_t> z, std::string_view algorithm,
                                                    std::span<const std::uint8_t> apu = {},
                                                    std::span<const std::uint8_t> apv = {}) noexcept
{
    static_assert(N >= 16 && N <= 64, "JOSE's keys are 16 to 64 bytes");
    return secret_bytes<N>(crypto::detail::jwa_concat_kdf_sha256<N>(z, algorithm, apu, apv));
}

/// \brief ECDH-ES on X25519 (RFC 8037): the shared secret with the peer, then the Concat KDF.
/// \ingroup jose
/// \tparam N The key length in bytes, 16 to 64.
/// \param secret Our X25519 secret (the recipient's static key, or the sender's ephemeral key).
/// \param peer The peer's public key (the `epk`, or the recipient's key).
/// \param algorithm The `enc` value for `"alg": "ECDH-ES"`, else the `alg` value.
/// \param apu The `apu` header value, base64url-decoded; empty when absent.
/// \param apv The `apv` header value, base64url-decoded; empty when absent.
/// \return The key, or `errc::small_order`.
template <std::size_t N>
[[nodiscard]] constexpr result<secret_bytes<N>, errc> ecdh_es_x25519(const secret_bytes<32>& secret, const x25519::public_key& peer,
                                                                     std::string_view algorithm, std::span<const std::uint8_t> apu = {},
                                                                     std::span<const std::uint8_t> apv = {}) noexcept
{
    auto z = x25519::shared_secret(secret, peer);
    if (!z)
        return err(z.unwrap_err());
    return ok(ecdh_es_kdf<N>(z->reveal(), algorithm, apu, apv));
}

/// \brief ECDH-ES on P-256 (RFC 7518 4.6): the shared secret with the peer, then the Concat KDF.
/// \ingroup jose
/// \tparam N The key length in bytes, 16 to 64.
/// \param key Our P-256 private key (the recipient's static key, or the sender's ephemeral key).
/// \param peer The peer's public key (the `epk`, or the recipient's key).
/// \param algorithm The `enc` value for `"alg": "ECDH-ES"`, else the `alg` value.
/// \param apu The `apu` header value, base64url-decoded; empty when absent.
/// \param apv The `apv` header value, base64url-decoded; empty when absent.
/// \return The key, or `errc::invalid_public_key`.
template <std::size_t N>
[[nodiscard]] constexpr result<secret_bytes<N>, errc> ecdh_es_p256(const p256::private_key& key, const p256::public_key& peer,
                                                                   std::string_view algorithm, std::span<const std::uint8_t> apu = {},
                                                                   std::span<const std::uint8_t> apv = {}) noexcept
{
    auto z = p256::shared_secret(key, peer);
    if (!z)
        return err(z.unwrap_err());
    return ok(ecdh_es_kdf<N>(z->reveal(), algorithm, apu, apv));
}

} // namespace snicholls::crypto::jose

#endif /* snicholls_crypto_jose_ecdh_es_hpp */

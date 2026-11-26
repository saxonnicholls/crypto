# Changelog

## 0.5.0 (2026-11-24)

JWE's key agreement. Pins snicholls-core at v0.23.1 and requires it (the Concat KDF). Experimental and not
independently audited.

- ECDH on P-256 (`p256/ecdh.hpp`): `shared_secret(private_key, public_key)`, the x-coordinate of d Q, constant time
  in the key; the peer's point is checked to be on the curve again before it is multiplied, so a `public_key` built
  from an unchecked point (an invalid-curve attack) is refused.
- JOSE's ECDH-ES (`jose/ecdh_es.hpp`, RFC 7518 4.6, RFC 8037): `ecdh_es_x25519<N>`, `ecdh_es_p256<N>` and
  `ecdh_es_kdf<N>`, the content encryption key for `"alg": "ECDH-ES"` or the key-encryption key for
  `"ECDH-ES+A256KW"`, through core's `jwa_concat_kdf` with SHA-256, its hash states wiped. With `aead/` this is a
  JWE recipient's whole cryptography (A256GCM, A256KW); the JOSE text is the caller's.
- Tests: RFC 7518 appendix C byte for byte (also as a `static_assert`), RFC 8037 A.6, all 355 Wycheproof
  `ecdh_secp256r1_ecpoint` cases; oracle fixtures of keys against OpenSSL and cryptography's ConcatKDFHash, and of
  whole JWEs made by jose and opened by cryptography, opened and remade here; the secret paths in the Valgrind check.
- AES-128-GCM (`aead/aes128_gcm.hpp`): TLS 1.3's mandatory TLS_AES_128_GCM_SHA256 and JOSE's A128GCM. AES is now
  one template over the key size (`detail::aes_cipher<16>` and `<32>`), so both share the same table-free,
  constant-time code; AES-256-GCM is unchanged. Tests: FIPS 197 C.1 and the GCM specification's test cases 1 to 4
  (also as `static_assert`s), every Wycheproof AES-128 case with a 96-bit nonce, oracle fixtures from OpenSSL and
  Node's crypto, the secret path in the Valgrind check.
- RSA verification with SHA-384 and SHA-512: `verify_pkcs1v15_sha384` / `_sha512` and `verify_pss_sha384` /
  `_sha512` (MGF1 on the same hash, salt the hash's length by default), with prehashed forms: RS384, RS512, PS384,
  PS512, X.509's sha384WithRSAEncryption and TLS's rsa_pss_rsae_sha384 / _sha512. PKCS#1 v1.5 and PSS are now
  one implementation over the hash. Every Wycheproof case for 2048, 3072 and 4096 bits.
- The README's "Future directions": key generation and key formats (PKCS#8, SPKI, PEM), and RSA signing.

## 0.4.1 (2026-11-24)

- Poly1305 (ChaCha20-Poly1305, XChaCha20-Poly1305): the final reduction's choice goes through `ct::select`. Clang 21
  at -O2 compiled the masked choice into a conditional on the accumulator, which Valgrind's secret-marking check
  reported; the result was correct, but the rule is no conditional on secret data. Clean under every compiler of
  the Ubuntu gate.
- Tests: the Wycheproof ChaCha20-Poly1305 and XChaCha20-Poly1305 fixtures wrote an empty tag without its "-", so 18
  lines each were a field short and the test read past them (undefined behaviour that passed on macOS and failed
  on Linux). The converter writes the placeholder; the tests refuse a short line.

## 0.4.0 (2026-11-24)

Authenticated encryption, the single include, and snicholls-core v0.23.0 (required at 0.17.0 or later).
Experimental and not independently audited.

- The single include (the family's rule, tooling v0.2.1): `snicholls_crypto.hpp`, crypto with core expanded in it,
  generated and compiled alone in every build, checked complete (`check.single_include`), never committed; each
  release tag attaches it to the GitHub release. `make single-include` writes it for any commit.
- secp256k1's DER now uses `detail/ecdsa_der.hpp`, as P-256's does: one encoder and one strict decoder.
- MSVC: the tests' braced lists of byte values are `std::initializer_list<std::uint8_t>` (C4244).

- ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 (`aead/chacha20_poly1305.hpp`): authenticated encryption
  with associated data, constant time in the key and the data, a constant-time tag check, output zeroed when the
  tag does not verify; in-place use; `constexpr`, no allocation. ChaCha20, HChaCha20 and Poly1305 in `detail/`.
  `errc::authentication_failed`. Keys from a secret: core's `hkdf`.
- AES-256-GCM (`aead/aes256_gcm.hpp`, JWE's A256GCM) and AES-256 key wrap (`aead/aes_key_wrap.hpp`, RFC 3394,
  A256KW): AES-256 without tables (`detail/aes.hpp`: the S-box computed as the GF(2^8) inverse and the affine map,
  no memory index on a secret) and a masked GHASH. Slower than AES-NI, constant time.
- Tests: RFC 8439 and the XChaCha draft's vectors; FIPS 197, the GCM specification and RFC 3394; all 640
  Wycheproof ChaCha20-Poly1305 and XChaCha20-Poly1305 cases, its AES-256-GCM (96-bit nonces) and AES-256 key-wrap
  cases; oracle fixtures from OpenSSL, libsodium and Node's crypto; a fuzz target against libsodium; the secret
  paths in the Valgrind check.

## 0.3.0 (2026-11-24)

P-256 (ES256). Pins snicholls-core at v0.22.0. Experimental and not independently audited.

- P-256 (`p256/`): the field and scalars in Montgomery form on four 64-bit limbs (`detail/mont256.hpp`, constant
  time), points with Renes, Costello and Batina's complete addition for a = -3, keys and SEC1, ECDSA with SHA-256
  (ES256) with RFC 6979 nonces, constant time in the key and the nonce, verification, JOSE's r || s and DER
  (`detail/ecdsa_der.hpp`). `constexpr` throughout: an RFC 6979 signature is a `static_assert`.
- Tests: RFC 6979 A.2.5 (P-256, SHA-256) byte for byte; every Wycheproof `ecdsa_secp256r1_sha256` case, DER and
  P1363; oracle fixtures from OpenSSL, noble-curves, RustCrypto's p256 and Node's crypto; the secret paths in the
  Valgrind check; a fuzz target against OpenSSL.

## 0.2.0 (2026-11-24)

RSA signature verification, and snicholls-core v0.22.0 (required at 0.17.0 or later). Experimental and not
independently audited: not for securing funds yet.

- RSA signature verification (`rsa/rsa.hpp`): RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256 and MGF1-SHA-256
  (JOSE's RS256 and PS256), with keys from components (a JWK's `n` and `e`), a SubjectPublicKeyInfo or an
  RSAPublicKey in strict DER, moduli of 2048 to 4096 bits. Verification only, variable time on public data, no
  allocation, `constexpr` (a whole RS256 verification is a `static_assert`). Montgomery arithmetic for a public
  modulus in `detail/montgomery.hpp`.
- Tests: every Wycheproof RSA PKCS#1 v1.5 and PSS SHA-256 case for 2048, 3072 and 4096 bits (1,203), each key read
  three ways; oracle fixtures from OpenSSL, Node's crypto and RustCrypto's rsa; a fuzz target against OpenSSL.

## 0.1.1 (2026-11-23)

Build fixes for the compilers of CI's first run; no change in behaviour. Pins snicholls-core at v0.21.0 and
requires 0.17.0 or later.

- Clang 21 with libstdc++ 15: the demos and benchmarks get the constexpr step limits the tests had
  (`snicholls_crypto_constexpr_limits`); libstdc++ 15 checks its assertions in constant evaluation, and a field
  inversion then exceeds Clang's default. `secp256k1/field.hpp` says which flags a consumer needs to evaluate an
  inversion or a multiplication at compile time.
- GCC 15 with AVX2 code: `signature::der()` appends each integer straight from r and s instead of copying
  intermediate vectors, which GCC reported as a false `-Wstringop-overflow`; a new test covers the 8- and 72-byte
  encodings.
- GCC 13 on aarch64: base58 decoding's reversal is bounded by the buffer as well as the length, silencing a false
  `-Wstringop-overflow`.
- MSVC: `secp256k1::sign` and `schnorr_sign` retry without `continue` (C3615), and `convert_bits` no longer shifts
  a byte by 8 (C4333).
- The local gate: `make ubuntu` adds Clang 21 (Release, Debug, ASan+UBSan) and GCC 15 at `-march=x86-64-v3` in the
  Ubuntu 26.04 image, built with GNU Make as CI builds them, and `UBUNTU_FLAGS=--arm64` adds ARM64 GCC 13; the
  images' apt caches are their own and locked. The Valgrind secret-marking check now also runs under GCC 15 and
  Clang 21.

## 0.1.0 (2026-11-23)

First release. Experimental and not independently audited: not for securing funds yet (SECURITY.md). Pins
snicholls-core at v0.21.0 and requires 0.17.0 or later.

- secp256k1: field and scalar arithmetic (4 x 64-bit limbs, constant time), complete projective addition,
  fixed-window multiplication; keys and SEC1; RFC 6979 nonces; ECDSA with low-S and the recovery id, verification
  with either high-S policy, public-key recovery and Ethereum's `ecrecover`, strict DER; BIP-340 Schnorr.
- Curve25519: Ed25519 (RFC 8032) and X25519 (RFC 7748).
- BIP-39 (English, constant-time word lookup, NFKD left to the caller for non-ASCII passphrases), derivation paths,
  BIP-32 with xprv / xpub, SLIP-10 for Ed25519.
- Address encodings: base58 with any alphabet, base58check, bech32 / bech32m, segwit addresses.
- `constant_time.hpp` (with `ct::declassify`), `secret_bytes<N>`, `errc`.
- Evidence: Wycheproof, RFC, BIP and SLIP vectors; the Valgrind secret-marking check; a dudect-style timing test.
- Other implementations: 26,109 cases from 25 pinned oracle libraries (libsecp256k1, k256, noble, ethers,
  OpenSSL, libsodium, dalek, python-mnemonic, bitcoinjs and others) replayed on every build and regenerated by
  `make oracles`; differential fuzzing against libsecp256k1, libsodium, OpenSSL and the oracles (`fuzz/`); a
  Cryptofuzz module.
- The scaffold: CMake with core's and crypto's diamond rules, the mirror, version and public-name checks, Doxygen
  with warnings as errors, the Ubuntu gate in Docker; CI on core's pattern with the documentation published to
  GitHub Pages; SECURITY.md.

# snicholls-crypto

Elliptic curves, signatures and wallet key derivation, header-only C++20, constant-time wherever a secret is
involved. Part of the snicholls libraries; it depends on snicholls-core and nothing else.

> **Status: experimental (0.3.0). Not independently audited. Do not use it to secure funds yet.**
> Scrutiny is welcome: report vulnerabilities privately as SECURITY.md describes.

**Documentation:** every public entity is documented in Doxygen, with the design, guarantees, errors, examples
(compiled from the demos), performance and known issues of each header. Build it with `make docs` and open
`build-docs/docs/html/index.html`. Once the repository is public, CI will publish it at
<https://saxonnicholls.github.io/crypto/>, as core's is at <https://saxonnicholls.github.io/core/>: the newest
release at the root, every version under `/vX.Y.Z/`, the latest `main` under `/main/`.

| Area | Headers | What |
|---|---|---|
| shared | `constant_time.hpp`, `secret.hpp`, `error.hpp` | masks and selections, `ct::declassify`; `secret_bytes<N>` (wiped, move-only, `reveal()`); `errc` |
| `secp256k1/` | `field`, `scalar`, `point`, `keys`, `rfc6979`, `ecdsa`, `schnorr` | keys and SEC1; ECDSA with RFC 6979, low-S and the recovery id; verification (high-S accepted or rejected); recovery and Ethereum's `ecrecover`; strict DER; BIP-340 |
| `aead/` | `chacha20_poly1305`, `aes256_gcm`, `aes_key_wrap` | ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305 (random 24-byte nonces), AES-256-GCM (JWE's A256GCM; AES without tables) and AES-256 key wrap (RFC 3394, A256KW): constant time, constant-time tag checks, nothing released before the tag verifies |
| `p256/` | `field`, `scalar`, `point`, `ecdsa` | P-256 (secp256r1): keys and SEC1, ECDSA with SHA-256 (ES256) with RFC 6979 nonces in constant time, verification, JOSE r \|\| s and DER |
| `rsa/` | `rsa` | RSA signature verification only: RSASSA-PKCS1-v1_5 and PSS with SHA-256 (RS256, PS256), keys from JWK `n` / `e`, SubjectPublicKeyInfo or RSAPublicKey, 2048 to 4096 bits |
| `curve25519/` | `field`, `scalar`, `edwards`, `ed25519`, `x25519` | Ed25519 (RFC 8032, cofactorless verification with S < L) and X25519 (RFC 7748, refusing the all-zero secret) |
| `bip39/` | `wordlist`, `mnemonic` | entropy to words and back, constant-time word lookup, the seed (PBKDF2-HMAC-SHA512) |
| `hd/` | `path`, `bip32`, `slip10` | derivation paths and BIP-44/49/84/86; BIP-32 with xprv / xpub (tprv, yprv, zprv); SLIP-10 for Ed25519, hardened only |
| `address/` | `base58`, `base58check`, `bech32` | base58 with any alphabet (Bitcoin, XRPL, Flickr), base58check, bech32 / bech32m and segwit addresses |

Everything is `constexpr` (a whole RFC 6979 signature is a `static_assert` in the tests; evaluating one at compile
time needs a raised step limit, `secp256k1/field.hpp` says which), allocation-free, and returns
`snicholls::result<V, errc>` where it can fail. The hashes are core's (`hash/`); core is pinned at v0.22.0 and
required at 0.17.0 or later.

    #include <snicholls/crypto/hd/bip32.hpp>
    #include <snicholls/crypto/bip39/mnemonic.hpp>
    #include <snicholls/crypto/secp256k1/ecdsa.hpp>

    auto words = snicholls::crypto::bip39::parse("abandon abandon ... about");          // canonical text only
    auto seed  = snicholls::crypto::bip39::to_seed(*words, "passphrase");               // secret_bytes<64>
    auto key   = snicholls::crypto::hd::extended_private_key::from_seed(seed->reveal())
                     ->derive(snicholls::crypto::hd::derivation_path::parse("m/44'/60'/0'/0/0").unwrap());
    auto sig   = snicholls::crypto::secp256k1::sign(key->private_key(), hash);          // r, s, recovery id

Every header's documentation has a compiled example (`demos/`), and `make demos` runs them all.

## Test vectors

All from the standards or their reference suites; each fixture records its source, revision, SHA-256 and licence in
`tests/fixtures/README.md`.

| Source | Cases | Result |
|---|---|---|
| Wycheproof `ecdsa_secp256k1_sha256` (DER), `_p1363`, `_bitcoin` (low-S) | 476, 252, 464 | all as expected |
| Wycheproof `chacha20_poly1305_test.json`, `xchacha20_poly1305_test.json`; RFC 8439 2.3.2, 2.4.2, 2.5.2, 2.8.2; the XChaCha draft | 325, 315; 5 | all as expected (sealed and opened) |
| Wycheproof `aes_gcm_test.json` (AES-256, 128-bit tags), `aes_wrap_test.json` (256-bit KEK); FIPS 197 C.3; the GCM specification's test cases 13 and 15; RFC 3394 4.6 | 105, 68; 4 | all as expected for 96-bit nonces (other nonce lengths not offered); the one "acceptable" 8-byte key wrap refused, stated |
| Wycheproof `ecdsa_secp256r1_sha256` (DER), `_p1363`; RFC 6979 A.2.5 (P-256, SHA-256) | 484, 262; 2 | all as expected |
| Wycheproof `rsa_signature_{2048,3072,4096}_sha256`, `rsa_pss_{2048,3072,4096}_sha256_mgf1_32`, `rsa_pss_2048_sha256_mgf1_0` | 776, 324, 103 | all as expected (3 "acceptable" DigestInfos without NULL refused, stated) |
| Wycheproof `ed25519_test.json`, `x25519_test.json` | 210, 518 | all as expected (29 "acceptable" small-order keys accepted, stated) |
| RFC 6979 A.2.5 (P-256 nonces), secp256k1 RFC 6979 signatures | 2 + 16 | pass |
| RFC 8032 section 7.1, RFC 7748 sections 5.2 and 6.1 (1 and 1,000 iterations; 1,000,000 as a disabled test) | 5, 5 | pass |
| BIP-340 `test-vectors.csv` | 19 | pass |
| BIP-32 vectors 1 to 5 (17 chains both ways, 16 invalid keys); SLIP-10 secp256k1 and ed25519 | 33, 24 | pass |
| Trezor's BIP-39 `vectors.json` (English, "TREZOR"), with their BIP-32 master keys | 24 | pass |
| BIP-173, BIP-350 (strings and addresses); Bitcoin Core `base58_encode_decode.json`; XRPL addresses | 79, 14, 3 | pass |

## Testing against other implementations

Beyond the standards' vectors, the library is compared with other implementations in two ways, both test-only:
nothing below is included or linked by the library.

**Fixtures from pinned oracles** (`tests/fixtures/oracles/`, 19 fixtures, 26,109 cases): generated from fixed seeds
by `scripts/generate_oracle_fixtures.py` in `docker/oracles` (the base image by digest; Python 3.12.3 with a hashed
`requirements.txt`, Node 26.13.1 with `package-lock.json`, Rust 1.100.0 with `Cargo.lock`), replayed by the
`*_oracles_test.cpp` tests on every build, and regenerated and compared byte for byte by `make oracles` and CI.
Deterministic answers agree byte for byte with every oracle. Where implementations follow different rules, each
oracle's rule is stated and every one of its verdicts checked, never decided by a vote; the differences found are
listed in `tests/fixtures/README.md`.

| Oracle | Pinned | Compared |
|---|---|---|
| libsecp256k1 through coincurve | 21.0.0 | keys, ECDSA (RFC 6979, low-S, recovery id), verification, recovery, SEC1 and DER parsing, BIP-340 |
| libsecp256k1 through rust-secp256k1 | 0.33.1 (secp256k1-sys 0.14.1) | the same |
| k256 (RustCrypto) | 0.14.0 | the same |
| `@noble/secp256k1` (what ethers and viem build on) | 3.2.0 | keys, ECDSA, verification, recovery, SEC1, BIP-340 |
| ethers | 6.17.0 | keys, ECDSA, recovery, Ethereum ecrecover and addresses, BIP-39, BIP-32 (HDNodeWallet) |
| OpenSSL, through Python cryptography 50.0.2 | 4.0.3 | ECDSA on secp256k1 (its RFC 6979 mode, s compared after low-S normalisation) and verification, DER, Ed25519, X25519 |
| libsodium, through PyNaCl 1.6.2 | bundled (1.0.19 or later) | Ed25519, X25519 |
| OpenSSL (through cryptography), Node's crypto, RustCrypto's rsa | 4.0.3, Node 26.13.1 (OpenSSL 3.5.9), 0.10.0 | RSA: PKCS#1 v1.5 signatures byte for byte, verdicts on mutated signatures and malformed encodings, PSS at salt lengths 0, 20, 32 and 64, SubjectPublicKeyInfo |
| OpenSSL (through cryptography), `@noble/curves` `p256`, RustCrypto's p256, Node's crypto | 4.0.3, 2.4.0, 0.14.0, Node 26.13.1 (OpenSSL 3.5.9) | P-256: keys, RFC 6979 ES256 signatures byte for byte, verification of mutated and out-of-range signatures (Node: the message, uncompressed keys), SEC1 parsing |
| OpenSSL (through cryptography), libsodium (PyNaCl), Node's crypto | 4.0.3, bundled, Node 26.13.1 (OpenSSL 3.5.9) | ChaCha20-Poly1305 and AES-256-GCM seal byte for byte and open of sealed and tampered messages; XChaCha20-Poly1305 against libsodium; a fuzz target against libsodium and OpenSSL |
| ed25519-dalek, x25519-dalek | 3.0.0, 3.0.0 | Ed25519 (`verify` and `verify_strict`), X25519 |
| `@noble/curves` | 2.4.0 | Ed25519 (RFC 8032 and ZIP-215 modes), X25519 |
| python-mnemonic (Trezor's BIP-39 reference) | 0.21 | BIP-39 words, entropy, seeds, non-canonical text |
| `@scure/bip39`, bip39 crate | 2.4.0, 3.0.0 | the same |
| SLIP-10 reference (python slip10) | 1.1.0 | BIP-32 and SLIP-10 Ed25519 |
| bitcoinjs: bip32, bitcoinjs-lib, bs58check | 5.0.1, 7.0.5, 4.0.0 | BIP-32, P2PKH, P2SH-P2WPKH, P2WPKH and P2TR addresses, base58check, segwit |
| bip32 crate | 0.6.0 | BIP-32 along BIP-44, 49, 84 and 86 paths and random ones |
| ed25519-hd-key, slip10_ed25519 | 2.0.0, 0.1.3 | SLIP-10 Ed25519 |
| BIP-173 / BIP-350 reference code (Python) | sipa/bech32 `7a7d7ab1` | segwit addresses, both ways |
| python base58, bs58, bech32 crate | 2.1.1, 0.5.1, 0.12.0 | base58check, segwit |

**Differential fuzzing** (`fuzz/`, `make fuzz`): libFuzzer targets compare the library with libsecp256k1 0.8.0,
libsodium 1.0.22 and OpenSSL 3.0 on random and adversarial input (scalars at 0, n - 1, n and n + 1, points off
the curve, high-S and malleable signatures, invalid DER, small-order points in every encoding, bad checksums,
malformed paths and mnemonics), the Python and Rust oracles joining through the same JSON-lines processes. CI runs
each target briefly on every push and for an hour nightly; a divergence fails with a minimised reproducer, committed
as a regression test. `fuzz/cryptofuzz/` is a [Cryptofuzz](https://github.com/MozillaSecurity/cryptofuzz) module,
ready for OSS-Fuzz once the repository is public.

Earlier, from a scratch folder and not part of the repository's tests: 19,566 comparisons with an earlier in-house
implementation (secp256k1 keys, ECDSA and recovery, BIP-32, SLIP-10, Ed25519, BIP-39) and 57,334 on the address
codecs, agreeing except on empty base58 input, which the reference refuses and Bitcoin Core's vectors require; and
4,000 random cases against `@noble/curves` 1.6.0 and `@scure/bip32` 1.5.0, with no disagreement.

## Constant time

What is secret: private keys, nonces, seeds, chain codes, mnemonic entropy and words, X25519 secrets, and anything
derived from them. Every path on them avoids secret-dependent branches and memory indices (CLAUDE.md, "Design
rules"); the few results revealed on purpose go through `ct::declassify` (`grep declassify` lists them all: key and
mnemonic validity, retries of probability below 2^-127, the published recovery id, a mnemonic's text length).

Evidence:

1. **Valgrind secret marking** (`tests/ct/secret_marking.cpp`, CTest `ct.secret_marking`, run by `make ubuntu`):
   every secret input is marked undefined for memcheck, which then reports any branch or address that depends on
   it. Clean for secp256k1 keys, ECDSA, BIP-340, BIP-32 (hardened and non-hardened), SLIP-10, Ed25519, X25519 and
   BIP-39 (entropy, text, seed), with GCC 13 and Clang 18 at -O0, -O2 and -O3, GCC 15 at -O3 with AVX2 and Clang 21
   at -O0 and -O3, on x86-64. A control function that leaks on purpose is reported in every build
   (`ct.secret_marking.control`). The check earlier found a loop in `bip39::mnemonic::to_text` that GCC -O3 rewrote
   around a secret offset; it is fixed.
2. **Timing** (`benchmarks/ct/timing.cpp`, dudect-style: fixed against random secrets, Welch's t after cropping):
   at 20,000 samples per operation, |t| stays below 2.2 for the secp256k1 public key, ECDSA, Ed25519, X25519 and
   BIP-32 (4.5 would be evidence of a leak). The same statistic on a variable-time double-and-add gives |t| = 539.

Limits: Valgrind sees the binaries it ran, for those compilers, flags and one architecture (x86-64), not every
build a consumer makes; it cannot see timing differences inside instructions (a variable-latency multiplier on some
processors). The timing test measures wall-clock time on a shared machine, so a small |t| is not proof. Not covered
by design: verification and recovery (public data, variable time, documented), the base58 decoder on `xprv` / WIF
text (variable time, documented), and a mnemonic's text length, which reaches PBKDF2's timing (about four or five
bits of the words; documented in `bip39/mnemonic.hpp`).

## Performance

Release, AppleClang 17, Intel Xeon W-3245 at 3.2 GHz, 2026-11-20, a loaded machine (BENCHMARKS.md has every row):

| Operation | Time |
|---|---:|
| secp256k1 public key / ECDSA sign / verify / recover | 139 / 171 / 200 / 199 us |
| BIP-340 sign / verify | 263 / 175 us |
| Ed25519 sign / verify, X25519 | 79 / 110 / 64 us |
| BIP-32 child (hardened or not), m/44'/60'/0'/0/0 from a seed | 132 us, 676 us |
| BIP-39 seed (2048 PBKDF2 iterations) | 1.74 ms |
| base58check of an xprv, encode / decode | 7.5 / 3.8 us |

These are several times slower than libsecp256k1 and libsodium, which use wider limbs with lazy reduction,
precomputed tables for the base point and faster inversions; the forms here are the shortest that are constant time.

## Building

    git submodule update --init
    make test-werror     # every test, demo and boundary check, warnings as errors
    make docs            # Doxygen, warnings as errors; open build-docs/docs/html/index.html
    make check           # version, mirror, nothing private
    make ubuntu          # the same on Ubuntu in Docker, with sanitizers and the Valgrind constant-time check
    make oracles         # the oracle fixtures regenerated in docker/oracles and compared, then replayed
    make fuzz            # the differential fuzz harness, 30 seconds a target
    make benchmarks      # rewrites BENCHMARKS.md

The design rules, the layout and the contract every change keeps are in CLAUDE.md.

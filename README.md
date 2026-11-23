# snicholls-crypto

Elliptic curves, signatures and wallet key derivation, header-only C++20, constant-time wherever a secret is
involved. Part of the snicholls libraries; it depends on snicholls-core and nothing else.

Status: experimental (0.1, unreleased).

**Documentation:** every public entity is documented in Doxygen, with the design, guarantees, errors, examples
(compiled from the demos), performance and known issues of each header. Build it with `make docs` and open
`build-docs/docs/html/index.html`. Once the repository is public, CI will publish it at
<https://saxonnicholls.github.io/crypto/>, as core's is at <https://saxonnicholls.github.io/core/>: the newest
release at the root, every version under `/vX.Y.Z/`, the latest `main` under `/main/`.

| Area | Headers | What |
|---|---|---|
| shared | `constant_time.hpp`, `secret.hpp`, `error.hpp` | masks and selections, `ct::declassify`; `secret_bytes<N>` (wiped, move-only, `reveal()`); `errc` |
| `secp256k1/` | `field`, `scalar`, `point`, `keys`, `rfc6979`, `ecdsa`, `schnorr` | keys and SEC1; ECDSA with RFC 6979, low-S and the recovery id; verification (high-S accepted or rejected); recovery and Ethereum's `ecrecover`; strict DER; BIP-340 |
| `curve25519/` | `field`, `scalar`, `edwards`, `ed25519`, `x25519` | Ed25519 (RFC 8032, cofactorless verification with S < L) and X25519 (RFC 7748, refusing the all-zero secret) |
| `bip39/` | `wordlist`, `mnemonic` | entropy to words and back, constant-time word lookup, the seed (PBKDF2-HMAC-SHA512) |
| `hd/` | `path`, `bip32`, `slip10` | derivation paths and BIP-44/49/84/86; BIP-32 with xprv / xpub (tprv, yprv, zprv); SLIP-10 for Ed25519, hardened only |
| `address/` | `base58`, `base58check`, `bech32` | base58 with any alphabet (Bitcoin, XRPL, Flickr), base58check, bech32 / bech32m and segwit addresses |

Everything is `constexpr` (a whole RFC 6979 signature is a `static_assert` in the tests), allocation-free, and
returns `snicholls::result<V, errc>` where it can fail. The hashes are core's (`hash/`); core is pinned for now at a
development commit of its feature/hashes branch, to become v0.17.0.

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
| Wycheproof `ed25519_test.json`, `x25519_test.json` | 210, 518 | all as expected (29 "acceptable" small-order keys accepted, stated) |
| RFC 6979 A.2.5 (P-256 nonces), secp256k1 RFC 6979 signatures | 2 + 16 | pass |
| RFC 8032 section 7.1, RFC 7748 sections 5.2 and 6.1 (1 and 1,000 iterations; 1,000,000 as a disabled test) | 5, 5 | pass |
| BIP-340 `test-vectors.csv` | 19 | pass |
| BIP-32 vectors 1 to 5 (17 chains both ways, 16 invalid keys); SLIP-10 secp256k1 and ed25519 | 33, 24 | pass |
| Trezor's BIP-39 `vectors.json` (English, "TREZOR"), with their BIP-32 master keys | 24 | pass |
| BIP-173, BIP-350 (strings and addresses); Bitcoin Core `base58_encode_decode.json`; XRPL addresses | 79, 14, 3 | pass |

## Cross-checks

Run from a scratch folder, not part of the repository's tests:

- **Against an earlier in-house implementation** (copies of its functions compiled in a scratch folder):
  19,566 comparisons on a seeded random corpus (secp256k1 public keys, ECDSA r, s and recovery ids, its verifier on
  our signatures and our recovery of its keys, BIP-32 private keys and chain codes on random paths, SLIP-10, Ed25519
  public keys and signatures, BIP-39 words both ways and seeds with random ASCII passphrases): no disagreement.
  The address codecs were compared on 57,334 cases, agreeing except on empty input, which the reference refuses and
  Bitcoin Core's vectors require.
- **Against `@noble/curves` 1.6.0 and `@scure/bip32` 1.5.0**: 4,000 random cases (BIP-340 signing, ECDSA with
  recovery, X25519, BIP-32 on random paths), no disagreement.

## Constant time

What is secret: private keys, nonces, seeds, chain codes, mnemonic entropy and words, X25519 secrets, and anything
derived from them. Every path on them avoids secret-dependent branches and memory indices (CLAUDE.md, "Design
rules"); the few results revealed on purpose go through `ct::declassify` (`grep declassify` lists them all: key and
mnemonic validity, retries of probability below 2^-127, the published recovery id, a mnemonic's text length).

Evidence:

1. **Valgrind secret marking** (`tests/ct/secret_marking.cpp`, CTest `ct.secret_marking`, run by `make ubuntu`):
   every secret input is marked undefined for memcheck, which then reports any branch or address that depends on
   it. Clean for secp256k1 keys, ECDSA, BIP-340, BIP-32 (hardened and non-hardened), SLIP-10, Ed25519, X25519 and
   BIP-39 (entropy, text, seed), with GCC 13 and Clang 18 at -O0, -O2 and -O3 on x86-64. A control function that
   leaks on purpose is reported in every build (`ct.secret_marking.control`). The check earlier found a loop in
   `bip39::mnemonic::to_text` that GCC -O3 rewrote around a secret offset; it is fixed.
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
    make benchmarks      # rewrites BENCHMARKS.md

The design rules, the layout and the contract every change keeps are in CLAUDE.md.

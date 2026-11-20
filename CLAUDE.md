# snicholls-crypto

Header-only C++20 library of elliptic curves, signatures and wallet key derivation for the snicholls libraries:
secp256k1 (ECDSA with RFC 6979 nonces, low-S, public-key recovery, BIP-340 Schnorr), Ed25519 and X25519, BIP-39
mnemonics, BIP-32 and SLIP-10 derivation, and the BIP-44 family of paths. It pins snicholls-core and nothing else.
Namespace `snicholls::crypto`, include root `<snicholls/crypto/...>`, CMake target `snicholls::crypto`.

Signing code holds private keys, so it lives here, apart from core: one place where every secret-dependent path is
constant-time and reviewed together. Hashes, MACs and KDFs are core's (constexpr, no secrets of their own to protect
beyond wiping); byte codecs (base58, bech32, hex) belong to the codec libraries or to the caller.

## Authorship and commits

This library is the author's own work. Commits are authored by the repository owner and carry **no AI attribution**:
no `Co-Authored-By` trailers, no "Generated with" lines, in commit messages, pull request descriptions, file headers,
README, CHANGELOG or this file. Every source file starts with the banner

    //
    //  <name>.hpp
    //  snicholls-crypto
    //
    //  Copyright 2010-2026 Saxon Herschel Nicholls
    //

It may become public: no file and no commit names a private repository, product, person, credential or local path.
`scripts/check_public.py` (run by `make check`) refuses the known private names and absolute home paths.

## Design rules (MUST)

1. **Every operation on secret data is constant-time.** A private key, a nonce, a seed, a chain code, a mnemonic's
   entropy and anything derived from them never decides a branch, a loop bound or a memory index. Conditions become
   masks (`constant_time.hpp`: `mask_*`, `select`, `conditional_swap`); table lookups scan every entry; scalar
   multiplication is a 4-bit fixed window over complete addition formulas (secp256k1) or a Montgomery ladder /
   fixed window with constant-time selection (Curve25519); inversions are Fermat with a public exponent.
2. **Secrets are wiped.** Key material lives in `secret_bytes<N>` (wiped on destruction, moves wipe the source, copies
   only by `clone()`, reached by `reveal()`) or in a type that wipes in its destructor. Intermediates on the stack are
   wiped with `secure_wipe` before returning.
3. **Public-data paths may be variable time, and say so.** Verification, public-key recovery, decoding a public key or
   a signature: their inputs are public. Each such function says "variable time; public data only" in its
   documentation, and none of them is ever called with a secret.
4. **constexpr where it does not conflict with constant time.** Field and scalar arithmetic, point arithmetic, the
   hashes, derivation and signing are `constexpr`: constant-time code is ordinary arithmetic, and the barriers
   (`ct::value_barrier`, `secure_wipe`) become plain operations in a constant expression. What is not `constexpr`
   says why in its documentation.
5. **No allocation.** Fixed-size arrays and spans in, `std::array` out. A message to sign is a
   `std::span<const std::uint8_t>`, hashed in a stream.
6. **Results, not exceptions.** Anything that can fail on its input returns `snicholls::result<V, errc>`
   (`error.hpp`, one enumeration for the library). Nothing throws.
7. **No dependency beyond core.** Address formats and text codecs (base58check, bech32, EIP-55) are left to callers
   or to the codec libraries; where a standard format needs one (BIP-32's `xprv` / `xpub`), the codec is a parameter.
8. **Strict input.** Non-canonical encodings are rejected, never repaired: a mnemonic that is not lower-case words
   separated by single spaces, a path component with a leading zero, a non-hardened index where only hardened is
   defined (never silently hardened), an `s` above n / 2 where only low-S is accepted.

What is constant-time and what is not is listed per header in its **Guarantees** section; the evidence (the
Valgrind secret-marking check and the timing test) and its limits are in README.md, "Constant time".

## Layout

- `include/snicholls/crypto/<name>.hpp` for the shared pieces (`version`, `error`, `constant_time`, `secret`),
  `include/snicholls/crypto/<area>/<name>.hpp` for the algorithms. `crypto.hpp` is the umbrella (applications only).
- Areas: `secp256k1/` (`field`, `scalar`, `point`, `keys`, `ecdsa`, `schnorr`; `snicholls::crypto::secp256k1`),
  `curve25519/` (`field`, `scalar`, `edwards`, `ed25519`, `x25519`; `snicholls::crypto::ed25519`,
  `snicholls::crypto::x25519`), `bip39/` (`wordlist`, `mnemonic`; `snicholls::crypto::bip39`), `hd/` (`path`,
  `bip32`, `slip10`, `extended_key`; `snicholls::crypto::hd`).
- `detail/` holds internals (`snicholls::crypto::detail` and `<area>::detail`): tested, not demonstrated, not
  documented by Doxygen. `detail/hashes.hpp` is **interim**: see "Waiting on other libraries".
- `tests/`, `demos/` and `benchmarks/` mirror `include/snicholls/crypto/`. `tests/fixtures/` holds the official test
  vectors, each with its provenance in `tests/fixtures/README.md`. `tests/support/` holds test-only helpers.
- Header guards are named, `snicholls_crypto_<path>_hpp`. Macros carry the `SNICHOLLS_CRYPTO_` prefix.

## Versioning and the diamond (MUST)

Semantic versioning; a release is a tag `vX.Y.Z` on a commit where every gate is green. The version is in
`include/snicholls/crypto/version.hpp`, `project(... VERSION)` and the tag; `scripts/check_version.py` compares them.

Crypto takes part in two diamonds, each with core's three rules (first copy wins, `*_require(<minimum>)`,
`*_assert_single_version()`), implemented in `CMakeLists.txt` and `cmake/SnichollsCryptoRequire.cmake` and tested by
`tests/cmake/diamond_test.cmake`:

- **Core's.** Crypto pins core as a submodule at `third_party/core`, by tag (now `v0.16.0`), and adds it in
  `CMakeLists.txt`; when the top-level project added core first, core skips crypto's copy. Crypto states its minimum
  with `snicholls_core_require(...)`. A pin moves only in a commit of its own,
  `third_party: bump core vX.Y.Z -> vA.B.C`, with every test green; a development pin on an untagged core commit is
  marked as such in its commit message and is replaced by the tag before crypto is released.
- **Its own.** A consumer adds crypto after core:

      add_subdirectory(third_party/core EXCLUDE_FROM_ALL)
      add_subdirectory(third_party/crypto EXCLUDE_FROM_ALL)
      snicholls_core_require(0.16.0)
      snicholls_crypto_require(0.1.0)
      target_link_libraries(my_target PRIVATE snicholls::crypto)
      # last lines of the top-level CMakeLists.txt:
      snicholls_core_assert_single_version()
      snicholls_crypto_assert_single_version()

## Tests (MUST)

Every public entity has tests; a change without tests is not done. GoogleTest (`third_party/googletest`, `v1.18.0`).

- `<area>/<name>.hpp` has `tests/<area>/<name>_test.cpp`, listed in `tests/CMakeLists.txt`;
  `scripts/check_mirror.py` enforces it both ways.
- **Official vectors first**: RFC 6979, RFC 8032, RFC 7748, BIP-32 (vectors 1 to 5), SLIP-10, BIP-39 (Trezor's
  `vectors.json`), BIP-340, and Wycheproof (Apache-2.0) for ECDSA, EdDSA and X25519. Each fixture records where it
  came from and the SHA-256 of the file it was converted from (`tests/fixtures/README.md`); fixtures are converted
  by `scripts/generate_fixtures.py` and never edited by hand.
- Edge cases in the style of libsecp256k1's tests: the point at infinity, r = 0, s = 0, r or s at or above n, high-S,
  invalid and off-curve points, x-coordinates at or above p, small-order Curve25519 points, non-canonical encodings.
- Compile-time facilities are tested at compile time (`static_assert` over field identities, the group law, hashes).
- Test names `TEST(<Unit><Aspect>, <BehaviourInPlainWords>)`. CTest labels: `unit`, `demo`, `boundary`, `docs`,
  `benchmark`, `ct` (the Valgrind secret-marking check, where Valgrind is installed).

## Demos (MUST)

Every public header has `demos/<area>/<name>_demo.cpp`, registered with `snicholls_crypto_add_demo(...)`, exercising
every public function, printing what it does and exiting non-zero if the result is not what it documents. Regions
marked `//! [tag]` are pulled into the documentation with `\snippet`. Demos use only published test keys (the
standards' vectors), never a key that could hold funds.

## Benchmarks (MUST)

Anything with a run-time cost (sign, verify, recover, derive, the mnemonic seed) has a Google Benchmark group
(`third_party/benchmark`, `v1.9.5`, `-DSNICHOLLS_CRYPTO_BUILD_BENCHMARKS=ON`). Each benchmark first checks the
operation against an official vector and refuses to run if it disagrees. Constant-time and variable-time forms of
the same arithmetic are timed side by side where both exist. Only Release numbers mean anything; a smoke run of each
is a CTest (label `benchmark`). `benchmarks/ct/` holds the informational timing test (fixed against random secrets,
Welch's t), which is evidence, not proof.

## Documentation (MUST) - Doxygen

Every public entity is documented with Doxygen; warnings are errors (`docs/Doxyfile.in`). Each header, class or major
function in the family's twelve sections, through the aliases: `\brief`, `\overview`, `\relations`, `\impls`,
`\contracts` (thread safety, exception safety, complexity, **which inputs are secret and whether the path is
constant-time**), `\errors`, `\examples` (a `\snippet` from a compiled demo), `\perf`, `\testing`, `\deps`,
`\gotchas`, `\status`. Members: `\brief`, `\param`, `\tparam`, `\return`. Build: `make docs`.

## Build and gates

    make test            # configure, build, every CTest
    make test-werror     # warnings are errors
    make asan            # Address + UB sanitizers
    make docs            # Doxygen, warnings are errors
    make check           # check_version.py, check_mirror.py, check_public.py
    make ubuntu          # Ubuntu 24.04 (GCC 13, Clang 18, Valgrind, Doxygen) and 26.04 (GCC 15) in Docker
    make demos           # build and run every demo with its output shown (scripts/run_demos.sh)
    make benchmarks      # every benchmark in Release; rewrites BENCHMARKS.md

**The local gate is macOS plus Ubuntu-in-Docker**: `make test-werror`, `make docs`, `make check` on the Mac and
`make ubuntu` before a change is done. `.github/workflows/ci.yml` runs the same legs when the repository is hosted.
Docker is shared with other projects: never stop a container or remove an image this repository did not create.

## The family

Crypto is a member of the snicholls family and keeps its rules (core's CLAUDE.md, "The family"): one function in one
place, pins point down, one core version, the same contract in every repository, nothing moved without an order.
In particular a helper that belongs to core (hex digits, a hash) is never added here; it is proposed to core, and a
test-only stand-in, if one is unavoidable, is marked as such and deleted when core has it.

## Waiting on other libraries

- **Hashes (core 0.17.0).** SHA-256, SHA-512, HMAC, PBKDF2-HMAC-SHA512 and RIPEMD-160 are in
  `detail/hashes.hpp` until core releases its own; then that file becomes aliases of core's (or is deleted) in one
  commit with every vector still passing. RIPEMD-160 is proposed to core (HASH160 for BIP-32 fingerprints).
- **base58check.** BIP-32's `xprv` / `xpub` text is produced and parsed through a codec the caller passes
  (`hd/extended_key.hpp`); the tests use a test-only base58check. No codec library is pinned.
- **NFKD.** BIP-39 seeds hash the NFKD form of the mnemonic and passphrase. English mnemonics are ASCII and need
  none; a non-ASCII passphrase is refused (`errc::non_canonical`) unless the caller states it is already NFKD.
  Core's Unicode tables have canonical decomposition (NFD) only; compatibility decomposition would lift the limit.
- **Hex.** `tests/support/snicholls/crypto/test/hex.hpp` is test-only, until core has a hex codec.

## Naming

Boost / standard library style, as core: lower_snake for namespaces, types, functions and variables; CamelCase
template parameters; `SNICHOLLS_CRYPTO_` macros. `noexcept` is accurate.

## Dependencies

| Dependency | Path | Pinned to | Used by |
|---|---|---|---|
| snicholls-core | `third_party/core` | `v0.16.0` | the library |
| GoogleTest | `third_party/googletest` | `v1.18.0` | tests only |
| Google Benchmark | `third_party/benchmark` | `v1.9.5` | benchmarks only |

Pin release tags, HTTPS URLs, `shallow = true`; never edit a file inside a submodule; one bump per commit.

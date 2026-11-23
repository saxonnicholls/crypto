# The Cryptofuzz module

A [Cryptofuzz](https://github.com/MozillaSecurity/cryptofuzz) module for this library, so Cryptofuzz's differential
driver compares it with every other module it is built with: here libsecp256k1's, and on OSS-Fuzz potentially all
of Cryptofuzz's secp256k1 and Ed25519 implementations.

| Operation | secp256k1 | Ed25519 |
|---|---|---|
| `ECC_PrivateToPublic` | yes | yes (the seed) |
| `ECC_ValidatePubkey` | yes | - |
| `ECDSA_Sign` | RFC 6979 nonces only (no caller-chosen nonce); digest NULL or SHA-256 | yes |
| `ECDSA_Verify` | textbook (either s), as Cryptofuzz's other modules | RFC 8032, cofactorless |
| `ECDSA_Recover` | ids 0 to 3, high-S accepted | - |
| `Schnorr_Sign` | BIP-340 nonce (aux_rand = 32 zero bytes, which is what libsecp256k1 means by none); digest NULL or SHA-256 | - |
| `Schnorr_Verify` | BIP-340, digest NULL | - |

Not offered, so answered "not supported": a caller-chosen nonce (this library has no such interface), X25519 (not
yet wired: its key conventions in Cryptofuzz's `ECDH_Derive` are still to be checked against another module), and
every other curve and digest. `fuzz/secp256k1_schnorr_fuzz.cpp` covers BIP-340 with arbitrary aux_rand.

## Building and running it locally

`build.sh` builds Cryptofuzz with this module and libsecp256k1's, written the way OSS-Fuzz runs a build script
(`$SRC`, `$OUT`, `$CC`, `$CXX`, `$CFLAGS`, `$CXXFLAGS`, `$LIB_FUZZING_ENGINE`) with defaults for a local run. It
registers the module in Cryptofuzz's `entry.cpp` and `gen_repository.py` (idempotently) and limits the run to the
operations above with `extra_options.h`.

    mkdir -p src && cd src
    git clone https://github.com/MozillaSecurity/cryptofuzz.git && git -C cryptofuzz checkout 6f1e4970288ecaf8d2fa34643fb4b19fa0adc626
    curl -fsSLO https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.7.0.tar.gz   # SHA-256 073d1906...7cd00
    mkdir secp256k1 && tar -xzf v0.7.0.tar.gz -C secp256k1 --strip-components=1
    git clone --recursive <this repository> snicholls-crypto
    cd .. && SRC=$PWD/src OUT=$PWD/out src/snicholls-crypto/fuzz/cryptofuzz/build.sh
    out/cryptofuzz-snicholls-crypto -max_total_time=600

It needs Clang and Boost's headers. libsecp256k1 is v0.7.0 here because Cryptofuzz's secp256k1 module (at the
commit above) uses an internal function v0.8.0 renamed. CI's nightly workflow runs this for an hour
(`.github/workflows/fuzz-nightly.yml`). Locally, on 2026-11-23: 65,589 executions in three minutes with no difference;
of the first 3,000 operations the module answered 2,475 and libsecp256k1 1,690, every one of the seven
operations above among them.

## Submitting to OSS-Fuzz (not done: the repository must be public first)

OSS-Fuzz accepts projects that are open source and widely used or critical; a new, unaudited library is judged on
its use. There are two routes; the first is the usual one for a cryptographic library.

1. **A module in Cryptofuzz's own OSS-Fuzz project.** Open a pull request on MozillaSecurity/cryptofuzz adding
   `modules/snicholls-crypto/` (`module.h`, `module.cpp`, `Makefile` from here), the two registrations `build.sh`
   makes in `entry.cpp` and `gen_repository.py`, and a `docs/snicholls-crypto.md` with the build steps. Then a
   pull request on google/oss-fuzz to `projects/cryptofuzz/`: the `Dockerfile` clones this repository with its
   submodules, and `build.sh` builds the module wherever it builds secp256k1's. The bugs found go to Cryptofuzz's
   maintainers and are forwarded.
2. **This library's own OSS-Fuzz project.** `oss-fuzz/` here holds the three files a project needs
   (`project.yaml`, `Dockerfile`, `build.sh`), building Cryptofuzz with this module beside libsecp256k1's. Copy
   them to `projects/snicholls-crypto/` in a fork of google/oss-fuzz, fill in `primary_contact` and
   `auto_ccs` in `project.yaml` (an address that may receive embargoed reports), test with
   `python infra/helper.py build_fuzzers snicholls-crypto` and `check_build`, and open the pull request. The
   reports are then this repository's to fix, under OSS-Fuzz's 90-day disclosure deadline.

Either way, decide the security contact first (SECURITY.md names GitHub security advisories) and keep the module's
operations in step with the library's.

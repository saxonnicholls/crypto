# Differential fuzzing

libFuzzer targets that compare this library with other implementations on random and adversarial input. Test-only:
built with `-DSNICHOLLS_CRYPTO_BUILD_FUZZ=ON`, linking libsecp256k1, libsodium and OpenSSL from the oracle image
(`docker/oracles`: libsecp256k1 0.8.0 and libsodium 1.0.22 from their release tarballs by SHA-256, OpenSSL 3.0
from Ubuntu 24.04). The `snicholls::crypto` target never links them.

    fuzz/run.sh                  every target for 30 seconds (CI, on every push)
    fuzz/run.sh 3600             every target for an hour (.github/workflows/fuzz-nightly.yml)
    fuzz/run.sh 600 ed25519      one target

| Target | Compared with | What it feeds |
|---|---|---|
| `secp256k1_ecdsa` | libsecp256k1, OpenSSL | keys (with 0, 1, n - 1, n, n + 1, p, 2^256 - 1 substituted), public keys, RFC 6979 signatures and recovery ids byte for byte; signatures made adversarial (r or s replaced by those values, high-S, bits flipped) verified under both high-S policies and recovered with every id |
| `secp256k1_parse` | libsecp256k1, OpenSSL | arbitrary bytes as SEC1 public keys, DER signatures and BIP-340 x-only keys |
| `secp256k1_schnorr` | libsecp256k1 | BIP-340 signatures byte for byte with the same aux_rand over any message length; adversarial verification (r >= p, s >= n, another key, bits flipped) |
| `ed25519` | libsodium, OpenSSL | keys and signatures byte for byte; verification with every small-order point in every encoding as A or R, S = 0, S + L, bits flipped, arbitrary keys |
| `x25519` | libsodium, OpenSSL | arbitrary scalars; u small-order, at or above p, with bit 255 set; the all-zero result refused by all |
| `p384` | OpenSSL | keys (with 0, 1, n - 1, n, n + 1, p, 2^384 - 1 substituted) and public keys byte for byte; ECDH both ways and against OpenSSL's d Q; OpenSSL's signatures verified, then made adversarial (r or s replaced, n - s, bits flipped) and verified by both; arbitrary bytes as SEC1 (OpenSSL's hybrid form the stated difference) |
| `text` | python base58, the BIP-173 / BIP-350 reference, python-mnemonic, the bip32 crate | base58check, segwit addresses, mnemonics and derivation paths, through the JSON-lines oracles of `scripts/oracles/` |

Where implementations follow different rules, a difference is allowed only as the stated rule
(`tests/fixtures/README.md`, "Other implementations"): libsecp256k1 reads SEC1's hybrid keys and reads a negative
or overflowing DER integer as zero; libsodium refuses small-order Ed25519 points; OpenSSL decodes non-canonical
Ed25519 keys. This library reads only canonical mnemonics and paths, so the text target checks one direction: what
it reads, the oracle reads alike. Anything else aborts with the case printed.

## A divergence

`fuzz/run.sh` replays the committed regressions first, then fuzzes from a seed corpus built from the oracle
fixtures (`fuzz/make_corpus.py`). On a divergence it minimises the input (`-minimize_crash`) into
`fuzz/regressions/<target>/<hash>` (the only place it writes in the checkout), prints the case, and fails; CI keeps
the reproducer as an artifact. Commit the reproducer with the fix: the CTest `fuzz.<target>.regressions` (label
`fuzz`) replays every file under `fuzz/regressions/<target>/` on each fuzz build, so a divergence once found stays
found. If the divergence is in the oracle, write its rule down where the others are, with the reproducer.

The flow is itself tested: `SNICHOLLS_CRYPTO_FUZZ_CONTROL=1 fuzz/run.sh 10 x25519` plants a divergence (an input
starting `DIVERGE`), which must be found, minimised to its seven bytes and reported; its reproducer goes to the
container's scratch space, not here. The CTests `fuzz.<target>.control` check the report on every fuzz build.

## Cryptofuzz

`fuzz/cryptofuzz/` is a module for [Cryptofuzz](https://github.com/MozillaSecurity/cryptofuzz), ready for OSS-Fuzz
once the repository is public: see its README.

# Changelog

## Unreleased (0.1.0)

First version. Pins snicholls-core at a development commit of its feature/hashes branch (to become v0.17.0).

- secp256k1: field and scalar arithmetic (4 x 64-bit limbs, constant time), complete projective addition,
  fixed-window multiplication; keys and SEC1; RFC 6979 nonces; ECDSA with low-S and the recovery id, verification
  with either high-S policy, public-key recovery and Ethereum's `ecrecover`, strict DER; BIP-340 Schnorr.
- Curve25519: Ed25519 (RFC 8032) and X25519 (RFC 7748).
- BIP-39 (English, constant-time word lookup, NFKD left to the caller for non-ASCII passphrases), derivation paths,
  BIP-32 with xprv / xpub, SLIP-10 for Ed25519.
- Address encodings: base58 with any alphabet, base58check, bech32 / bech32m, segwit addresses.
- `constant_time.hpp` (with `ct::declassify`), `secret_bytes<N>`, `errc`.
- Evidence: Wycheproof, RFC, BIP and SLIP vectors; the Valgrind secret-marking check; a dudect-style timing test.
- The scaffold: CMake with core's and crypto's diamond rules, the mirror, version and public-name checks, Doxygen
  with warnings as errors, the Ubuntu gate in Docker.

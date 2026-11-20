# Test fixtures

Official test vectors, read by the tests at run time. Each file is converted from its source by a script in
`scripts/` and never edited by hand; the source's SHA-256 is recorded here and in the file's header, so a
conversion can be checked against a fresh download.

## Wycheproof (`wycheproof/`)

Project Wycheproof, <https://github.com/C2SP/wycheproof>, licensed under the Apache License 2.0. Downloaded from
`testvectors_v1/` at commit `65ca494727a52944c204441c860b039e6786b99b` (2026-11-20) and converted by
`scripts/generate_wycheproof_fixtures.py --source <download dir> --commit <sha>`.

| Fixture | Source file | Source SHA-256 | Tests |
|---|---|---|---|
| `wycheproof/ed25519.txt` | `ed25519_test.json` | `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` | 210 |
| `wycheproof/x25519.txt` | `x25519_test.json` | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` | 518 |
| `wycheproof/ecdsa_secp256k1_sha256.txt` | `ecdsa_secp256k1_sha256_test.json` (DER) | `43db761c0a2eae71fb0755d355d5130e28ce64a5b07846cf27e7072082597a81` | 476 |
| `wycheproof/ecdsa_secp256k1_sha256_p1363.txt` | `ecdsa_secp256k1_sha256_p1363_test.json` | `7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2` | 252 |
| `wycheproof/ecdsa_secp256k1_sha256_bitcoin.txt` | `ecdsa_secp256k1_sha256_bitcoin_test.json` (DER, low-S) | `d3729ce83ff9740c45e74921009a4061eff6c09185b8dd1225ccd06ac57048a4` | 464 |

Each line is `tcId result field ...` in hex, `-` for an empty field. `result` is Wycheproof's: `valid` must be
accepted, `invalid` must be rejected, `acceptable` may go either way (each test states what this library does).
`x25519.txt` and the two DER ECDSA files are each about 105 KB: plain hex, one case per line, kept whole. The ECDSA
files give each group's public key once, on a `key - <uncompressed SEC1 key>` line before its tests.

## RFC vectors

RFC 7748 (sections 5.2 and 6.1) vectors are short and are written into the tests
themselves, with the section they come from.

| Fixture | Source | Source SHA-256 |
|---|---|---|
| `rfc8032_ed25519.txt` | RFC 8032 section 7.1, <https://www.rfc-editor.org/rfc/rfc8032.txt>, converted by `scripts/generate_wycheproof_fixtures.py --rfc8032` (TEST 1024's message is 1,023 bytes) | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` |

## secp256k1

| Fixture | Source | Source SHA-256 | Licence |
|---|---|---|---|
| `bip340.txt` | BIP-340's `test-vectors.csv`, <https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0340/test-vectors.csv>, converted by `scripts/generate_wycheproof_fixtures.py --bip340` (19 vectors) | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` | BSD-2-Clause (BIP-340) |
| `rfc6979_secp256k1.txt` | RFC 6979 signatures over secp256k1 with SHA-256 and low-S: rows 1 and 2 are the values published with the curve's RFC 6979 test suites (key 1, "Satoshi Nakamoto" and "All those moments will be lost in time..."); all 16 rows (4 keys x 4 messages) were produced by `@noble/curves` 1.6.0 (MIT), `secp256k1.sign(sha256(m), key, {lowS: true})`, an independent implementation | - | MIT (the oracle) |

RFC 6979's own vectors (appendix A.2.5, P-256 with SHA-256, "sample" and "test") are written into
`tests/secp256k1/rfc6979_test.cpp`, which checks the nonce generator for any 256-bit order.

## BIP-39 (`bip39/trezor_english.txt`)

- Source: Trezor's reference vectors for BIP-39,
  <https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json>, the
  `english` array (24 vectors: entropy, mnemonic, seed with the passphrase "TREZOR", BIP-32 master `xprv`).
- SHA-256 of `vectors.json`: `fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8`.
- Licence: MIT (python-mnemonic, Copyright (c) 2013-2016 Pavol Rusnak).
- Script: `scripts/generate_bip39_wordlist.py --source DIR`.

The English word list itself is compiled into `include/snicholls/crypto/bip39/wordlist.hpp` by the same script, from
<https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0039/english.txt>, SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` (the value published with the BIP and checked by
every BIP-39 implementation). The word lists are part of BIP-39, whose header states `License: MIT`. The CTest
`generated.bip39_wordlist_is_official` recomputes that SHA-256 from the header's words, offline.

## Addresses (`address/`)

Converted by `scripts/generate_address_fixtures.py --source DIR`, which refuses a source whose SHA-256 differs.

| Fixture | Source | Revision | Source SHA-256 | Licence |
|---|---|---|---|---|
| `address/bech32.txt`, `address/segwit.txt` | BIP-173, <https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0173.mediawiki>, "Test vectors" | bips `a7f91321` | `b19eab06b264bbd15ad7f7d640fa34de8f4a8809fba8a6ecc3e165545b27a543` | BSD-2-Clause (the BIP's header) |
| the same | BIP-350, <https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0350.mediawiki>, "Test vectors" | bips `a7f91321` | `63634b06aa8bae88b31929674736e74964c4598684269ac2b0b140c43a7a0dec` | BSD-2-Clause (the BIP's header) |
| `address/base58.txt` | Bitcoin Core, <https://github.com/bitcoin/bitcoin/blob/110183746150428e6385880c79f8c5733b1361ba/src/test/data/base58_encode_decode.json> | tag `v28.0`, commit `11018374` | `73006fdb9d8337117bf330c1900974a1242f2e61fd6a1b77217328dbc4b72025` | MIT |

`bech32.txt` lines are `variant valid|invalid <hex of the string>` (hex, because BIP-173's invalid strings include a
space, DEL, 0x80 and 0xFF). `segwit.txt` lines are `bip173|bip350 valid|invalid <address> <scriptPubKey>`: BIP-350
supersedes BIP-173's valid addresses of versions 1 to 16 (written with bech32, now required to be bech32m), and the
test checks that those three are refused.

Short vectors are written into the tests with their sources: the addresses and WIF keys of private key 1 (every
Bitcoin library's), BIP-32 test vector 1's master `xprv`, and the XRP Ledger's ACCOUNT_ZERO, ACCOUNT_ONE and genesis
account from the XRPL documentation, <https://github.com/XRPLF/xrpl-dev-portal/blob/7da79fec8e857e77085a0f0d750b8054c4504db1/docs/concepts/accounts/addresses.md>
(SHA-256 `488312c3c7fbe3237e89664d0665638ea584827c7a17d5682f1c4fab08dae347`). The Flickr-alphabet vector and the
decoded payloads of `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` and the genesis account were computed with the Python
packages `base58` 2.1.1 and `bech32` 1.2.0 as an independent oracle.

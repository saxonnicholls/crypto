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

Each line is `tcId result field ...` in hex, `-` for an empty field. `result` is Wycheproof's: `valid` must be
accepted, `invalid` must be rejected, `acceptable` may go either way (each test states what this library does).
`x25519.txt` is about 105 KB: 518 lines of hex, kept whole.

## RFC vectors

RFC 7748 (sections 5.2 and 6.1) vectors are short and are written into the tests
themselves, with the section they come from.

| Fixture | Source | Source SHA-256 |
|---|---|---|
| `rfc8032_ed25519.txt` | RFC 8032 section 7.1, <https://www.rfc-editor.org/rfc/rfc8032.txt>, converted by `scripts/generate_wycheproof_fixtures.py --rfc8032` (TEST 1024's message is 1,023 bytes) | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` |

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

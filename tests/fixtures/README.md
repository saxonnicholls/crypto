# Test fixtures

Official test vectors, converted by scripts from the published files and never edited by hand. Each section names
the source, the exact revision, the SHA-256 of the file converted, the licence, and the script.

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

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

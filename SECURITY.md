# Security policy

snicholls-crypto is **experimental and has not been independently audited**. Do not use it to secure funds or
other value yet. Reports are welcome, and so is scrutiny of the design: that is why the repository is public.

## Reporting a vulnerability

Report privately, through GitHub's security advisories: the repository's **Security** tab, **Report a
vulnerability** (<https://github.com/saxonnicholls/crypto/security/advisories/new>). Please do not open a public
issue, pull request or discussion for anything that could be a vulnerability.

A useful report says which function and which inputs, what happens and what should happen, and how you found it.
A failing test or a fuzz reproducer (`fuzz/README.md`) is ideal. If you are not sure it is a vulnerability, report
it privately anyway.

What to expect:

| | |
|---|---|
| Acknowledgement | within 7 days |
| A first assessment (confirmed or not, and its severity) | within 14 days |
| A fix or a mitigation | within 90 days of the report, sooner for anything that leaks a secret or accepts a forgery |
| Disclosure | coordinated with you: a GitHub security advisory and a CVE where one applies, published with the fixed release, crediting you unless you prefer otherwise |

There is no bug bounty.

## Supported versions

Before 1.0 only the newest release is supported: a fix is made on `main` and released as a new version, not
backported.

| Version | Supported |
|---|---|
| newest 0.x release | yes |
| older 0.x releases | no |
| unreleased `main` | best effort |

## Threat model

### In scope

- **Correctness.** Every signature, key, derivation and encoding must be what its standard says: RFC 6979, RFC
  8032, RFC 7748, BIP-340, BIP-32, SLIP-10, BIP-39, BIP-173, BIP-350 and base58check. A forgery accepted, a valid
  signature refused, a wrong key or address derived, or a non-canonical input accepted where the documentation
  says it is refused (CLAUDE.md, rule 8) is a vulnerability.
- **Constant time on secret paths.** No private key, nonce, seed, chain code, mnemonic entropy or anything derived
  from them may decide a branch, a loop bound or a memory index, apart from the results revealed on purpose
  through `ct::declassify` (README.md, "Constant time"). A timing or cache leak of a secret, measurable in
  software on the same or another machine, is in scope.
- **Memory safety and the library's other contracts**: out-of-bounds reads or writes, undefined behaviour, and
  secrets left in memory the library owns after it promised to wipe them.

### Out of scope

- Physical attacks: power analysis, electromagnetic emanation, fault injection (glitching, Rowhammer-style
  corruption) and anything needing physical access to the device.
- The paths documented as variable time on public data (verification, recovery, decoding a public key, a
  signature or an `xpub`), except where they are fed a secret, which would be a bug.
- Leaks introduced by a compiler, flags or a processor the constant-time evidence does not cover (README.md,
  "Constant time", lists what it covers); reports of such a leak are still welcome as issues.
- What the caller does with a key: storing, copying or logging it, or a passphrase read from a terminal.
- The test infrastructure: the oracle image, the oracle programs and the fuzz harness (`docker/oracles`,
  `scripts/oracles`, `fuzz/`), which are never part of the library. A wrong oracle that hides a library bug is
  welcome as an ordinary issue.

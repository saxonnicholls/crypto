# The single include

`snicholls_crypto.hpp` is the whole of snicholls-crypto in one file: `crypto.hpp` with every header expanded in
place, once each, snicholls-core's included, needing nothing but the standard library. Copy it into a project and
`#include "snicholls_crypto.hpp"`.

- **Download it** from the [release](https://github.com/saxonnicholls/crypto/releases) for the version you pin. Each
  release's file is generated from that release's tagged commit and compiled on its own before it is attached.
- **Build it** for any other commit with `make single-include`, which writes it here (git-ignored), or with
  `python3 third_party/tooling/scripts/single_include.py --out <dir>`.

It is never committed, so it is never stale: every build generates it and compiles it alone
(`snicholls_crypto_single_include`), and the CTest `check.single_include` fails if a header is missing from
`crypto.hpp`.

A project that also uses snicholls-core's own single include should take crypto through CMake instead (one core
version per build).

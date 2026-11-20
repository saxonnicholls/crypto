# Benchmarks

Every benchmark checks its result against an official test vector before it times anything, and refuses
to run if they disagree (CLAUDE.md, "Benchmarks"). Where a hand-written equivalent exists it is timed beside
the library on identical data. Only Release numbers mean anything; a header quotes its own numbers in its
**Performance** section.

**This file is generated.** Do not edit it: run

    make benchmarks                      # every benchmark, about a minute
    scripts/benchmarks_md.py --filter X  # one file's sections; the rest are kept

and commit the result. The "relative" column is each row's time over the fastest row in its file.

| | |
| --- | --- |
| date | 2026-11-20 |
| machine | Intel(R) Xeon(R) W-3245 CPU @ 3.20GHz, 32 CPUs |
| OS | Darwin 25.6.0 |
| compiler | AppleClang 17.0.0.17000309 |
| build | Release, `build-bench` |
| min time per benchmark | 0.5 s |

## base58_benchmark

`benchmarks/address/base58_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `Base58EncodeAddress` | 563.4 ns | 1.98x |  |
| `Base58DecodeAddress` | 284.4 ns | 1.00x |  |
| `Base58checkEncodeAddress` | 1.34 us | 4.73x |  |
| `Base58checkDecodeAddress` | 1.09 us | 3.83x |  |
| `Base58checkEncodeExtendedKey` | 7.53 us | 26.47x |  |
| `Base58checkDecodeExtendedKey` | 3.75 us | 13.20x |  |

## bech32_benchmark

`benchmarks/address/bech32_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `SegwitEncodeP2wpkh` | 211.0 ns | 1.00x |  |
| `SegwitDecodeP2wpkh` | 323.8 ns | 1.53x |  |
| `SegwitEncodeTaproot` | 304.3 ns | 1.44x |  |
| `SegwitDecodeTaproot` | 475.6 ns | 2.25x |  |

## bip32_benchmark

`benchmarks/hd/bip32_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `MasterFromSeed` | 1.91 us | 1.00x |  |
| `HardenedChild` | 131.94 us | 69.10x |  |
| `NonHardenedChild` | 132.03 us | 69.14x |  |
| `Bip44EthereumPath` | 676.30 us | 354.17x |  |
| `PublicChild` | 131.54 us | 68.89x |  |
| `Slip10SolanaPath` | 350.97 us | 183.80x |  |

## ecdsa_benchmark

`benchmarks/secp256k1/ecdsa_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `PublicKey` | 138.85 us | 12.34x |  |
| `Sign` | 170.86 us | 15.19x |  |
| `Verify` | 200.18 us | 17.80x |  |
| `Recover` | 198.76 us | 17.67x |  |
| `ParsePublicKeyCompressed` | 11.25 us | 1.00x |  |

## ed25519_benchmark

`benchmarks/curve25519/ed25519_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `Ed25519KeyPairFromSeed` | 84.44 us | 1.46x |  |
| `Ed25519Sign` | 79.13 us | 1.37x |  |
| `Ed25519Verify` | 110.32 us | 1.90x |  |
| `Edwards25519MulBaseConstantTime` | 72.20 us | 1.25x |  |
| `Edwards25519MulPublicVariableTime` | 57.94 us | 1.00x |  |

## mnemonic_benchmark

`benchmarks/bip39/mnemonic_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `EntropyToText` | 67.95 us | 1.18x |  |
| `ParseText` | 57.53 us | 1.00x |  |
| `MnemonicToSeed` | 1.74 ms | 30.21x |  |

## schnorr_benchmark

`benchmarks/secp256k1/schnorr_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `XonlyPublicKey` | 129.97 us | 1.00x |  |
| `SchnorrSign` | 263.05 us | 2.02x |  |
| `SchnorrVerify` | 175.06 us | 1.35x |  |

## x25519_benchmark

`benchmarks/curve25519/x25519_benchmark.cpp`

| benchmark | time | relative | throughput |
| --- | ---: | ---: | ---: |
| `X25519PublicKey` | 64.20 us | 1.00x |  |
| `X25519SharedSecret` | 63.94 us | 1.00x |  |

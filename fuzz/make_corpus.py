#!/usr/bin/env python3
#
#  make_corpus.py
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Seed corpora for the fuzz targets, from the oracle fixtures (tests/fixtures/oracles/): real keys, hashes,
#  signatures, DER, addresses, mnemonics and paths, laid out as each target reads its input, so libFuzzer starts
#  from valid cases and mutates them. Deterministic; written into the build directory, never committed.
#
#      python3 -I fuzz/make_corpus.py OUT_DIR
#

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "oracles")


def rows(name, limit=300):
    out = []
    for line in open(os.path.join(FIX, name)):
        if line.startswith("#") or not line.strip():
            continue
        out.append(["" if f == "-" else f for f in line.split()])
        if len(out) >= limit:
            break
    return out


def write(out, target, seeds):
    d = os.path.join(out, target)
    os.makedirs(d, exist_ok=True)
    for s in seeds:
        with open(os.path.join(d, hashlib.sha1(s).hexdigest()), "wb") as f:
            f.write(s)
    return len(seeds)


def main():
    out = sys.argv[1]
    b = bytes.fromhex
    n = 0
    n += write(out, "secp256k1_ecdsa", [bytes([i % 32]) + b(r[0]) + b(r[1]) + bytes([i % 10, (i * 7) % 10, i % 64, i % 8])
                                        for i, r in enumerate(rows("ecdsa_sign.txt"))])
    n += write(out, "secp256k1_parse", [b(r[0]) for r in rows("sec1_parse.txt") if r[0]] +
               [b(r[2]) for r in rows("ecdsa_der.txt", 600)])
    n += write(out, "secp256k1_schnorr", [bytes([i % 32]) + b(r[0]) + b(r[2]) + bytes([len(b(r[1]))]) + b(r[1])
                                          for i, r in enumerate(rows("bip340_sign.txt"))])
    n += write(out, "ed25519", [bytes([i % 64]) + b(r[0]) + bytes([min(len(b(r[1])), 200)]) + b(r[1])[:200] + bytes([i % 14, i % 14])
                                for i, r in enumerate(rows("ed25519_sign.txt"))])
    n += write(out, "x25519", [bytes([i % 8]) + b(r[0]) + b(r[1]) + bytes([i % 14]) for i, r in enumerate(rows("x25519.txt"))])
    text = [b"\x00" + r[2].encode() for r in rows("base58check.txt") if r[0] == "ok" and r[2]]
    text += [b"\x01" + r[4].encode() for r in rows("segwit.txt") if r[0] == "ok"]
    text += [b"\x02" + r[1].replace("+", " ").encode() for r in rows("bip39.txt")]
    text += [b"\x03" + r[1].encode() for r in rows("bip32.txt")]
    n += write(out, "text", text)
    print("make_corpus: %d seeds" % n)


if __name__ == "__main__":
    main()

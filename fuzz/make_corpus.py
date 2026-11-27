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
    rsa = []
    for i, name in enumerate(["rsa_pkcs1_2048_sha256.txt", "rsa_pkcs1_3072_sha256.txt", "rsa_pkcs1_4096_sha256.txt",
                              "rsa_pss_2048_sha256_mgf1_32.txt", "rsa_pss_3072_sha256_mgf1_32.txt", "rsa_pss_4096_sha256_mgf1_32.txt"]):
        key = i % 3
        pss = i >= 3
        first = True
        for line in open(os.path.join(ROOT, "tests", "fixtures", "wycheproof", name)):
            f = line.split()
            if not f or f[0].startswith("#") or f[0] == "key":
                if f and f[0] == "key":
                    if not first:
                        break   # only the first group: the key the target uses
                    first = False
                continue
            m = b"" if f[2] == "-" else b(f[2])
            sig = b"" if f[3] == "-" else b(f[3])
            if len(m) <= 64:
                rsa.append(bytes([(1 if pss else 0) | 4]) + bytes([key]) + bytes([len(m)]) + m + sig)
        key_line = next(l for l in open(os.path.join(ROOT, "tests", "fixtures", "wycheproof", name)) if l.startswith("key - "))
        rsa.append(bytes([3]) + b(key_line.split()[2]))
    n += write(out, "rsa", rsa)
    n += write(out, "p256", [bytes([i % 128 & ~3]) + b(r[0]) + b(r[2]) + bytes([i % 7, i % 7, i % 64, i % 8])
                             for i, r in enumerate(rows("p256_sign.txt"))] +
               [bytes([3]) + b(r[0]) for r in rows("p256_sec1.txt") if r[0]])
    n += write(out, "p384", [bytes([i % 128 & ~3]) + b(r[0]) + b(r[0][::-1]) + bytes([i % 7, i % 7, i % 64, i % 8])
                             for i, r in enumerate(rows("p384_keys.txt")) if r[1]] +
               [bytes([3]) + b(r[0]) for r in rows("p384_sec1.txt") if r[0]])
    aead = []
    for name in ("chacha20_poly1305.txt", "xchacha20_poly1305.txt"):
        for line in open(os.path.join(ROOT, "tests", "fixtures", "wycheproof", name)):
            f = line.split()
            if not f or f[0].startswith("#"):
                continue
            iv, key, ad, msg = (b"" if v == "-" else b(v) for v in (f[2], f[3], f[4], f[5]))
            if len(iv) in (12, 24) and len(ad) <= 64:
                aead.append(bytes([1 if len(iv) == 24 else 0]) + key + iv.ljust(24, b"\x00") + bytes([len(ad)]) + ad + msg)
    n += write(out, "aead", aead)
    text = [b"\x00" + r[2].encode() for r in rows("base58check.txt") if r[0] == "ok" and r[2]]
    text += [b"\x01" + r[4].encode() for r in rows("segwit.txt") if r[0] == "ok"]
    text += [b"\x02" + r[1].replace("+", " ").encode() for r in rows("bip39.txt")]
    text += [b"\x03" + r[1].encode() for r in rows("bip32.txt")]
    n += write(out, "text", text)
    print("make_corpus: %d seeds" % n)


if __name__ == "__main__":
    main()

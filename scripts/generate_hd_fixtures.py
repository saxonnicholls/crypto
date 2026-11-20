#!/usr/bin/env python3
#
#  generate_hd_fixtures.py
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Converts the derivation test vectors of BIP-32 (bip-0032.mediawiki, vectors 1 to 5) and SLIP-10 (slip-0010.md,
#  the secp256k1 and ed25519 vectors) into tests/fixtures/hd/bip32.txt and tests/fixtures/hd/slip10.txt. The
#  documents are downloaded by hand into a directory of their own and passed here; nothing is fetched. Each source
#  is pinned by SHA-256: a different file is refused.
#
#      python3 -I scripts/generate_hd_fixtures.py --source DIR           write both fixtures
#      python3 -I scripts/generate_hd_fixtures.py --source DIR --check   compare, write nothing
#

import argparse
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures", "hd")

SOURCES = {
    "bip-0032.mediawiki": ("https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0032.mediawiki",
                           "e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f", "BSD-2-Clause (BIP-32)"),
    "slip-0010.md": ("https://github.com/satoshilabs/slips/blob/02e7b618deb32952acf77aceb0b6ba984c2420b5/slip-0010.md",
                     "dbd5a324f2a6014bf78fc8cfa85833e4a16256a02283b93d648fccba18ed1ce7", "CC-BY-SA-4.0 (the SLIPs repository)"),
}


def path_of(chain):
    return chain.replace("<sub>H</sub>", "'")


def bip32(text):
    lines, vector, seed, chain = [], None, None, None
    pub = None
    for line in text.splitlines():
        m = re.match(r"===Test vector (\d)===", line)
        if m:
            vector = m.group(1)
            continue
        m = re.match(r"Seed \(hex\): ([0-9a-f]+)", line)
        if m:
            seed = m.group(1)
            continue
        m = re.match(r"\* Chain (\S+)", line)
        if m:
            chain = path_of(m.group(1))
            continue
        m = re.match(r"\*\* ext pub: (\S+)", line)
        if m:
            pub = m.group(1)
            continue
        m = re.match(r"\*\* ext prv: (\S+)", line)
        if m:
            lines.append("valid %s %s %s %s %s" % (vector, seed, chain, pub, m.group(1)))
            continue
        m = re.match(r"\* ([1-9A-HJ-NP-Za-km-z]{100,}) \((.*)\)$", line)
        if m and vector == "5":
            lines.append("invalid 5 %s %s" % (m.group(1), m.group(2).replace(" ", "_")))
    return lines


def slip10(text):
    lines, curve, seed, chain, entry = [], None, None, None, {}
    for line in text.splitlines():
        m = re.match(r"### Test vector (\d) for (\S+)", line)
        if m:
            curve = m.group(2) if m.group(2) in ("secp256k1", "ed25519") else None
            continue
        if curve is None:
            continue
        m = re.match(r"Seed \(hex\): ([0-9a-f]+)", line)
        if m:
            seed = m.group(1)
            continue
        m = re.match(r"\* Chain (\S+)", line)
        if m:
            chain, entry = path_of(m.group(1)), {}
            continue
        m = re.match(r"  \* (fingerprint|chain code|private|public): ([0-9a-f]+)", line)
        if m:
            entry[m.group(1)] = m.group(2)
            if m.group(1) == "public":
                lines.append(" ".join([curve, seed, chain, entry["fingerprint"], entry["chain code"], entry["private"], entry["public"]]))
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    outputs = {}
    for name, (url, sha, licence) in SOURCES.items():
        raw = open(os.path.join(args.source, name), "rb").read()
        if hashlib.sha256(raw).hexdigest() != sha:
            print("%s: SHA-256 is not the pinned %s" % (name, sha), file=sys.stderr)
            return 1
        text = raw.decode("utf-8")
        head = ["# Converted by scripts/generate_hd_fixtures.py from %s" % url,
                "# Source SHA-256 %s; licence: %s" % (sha, licence)]
        if name.startswith("bip"):
            body = bip32(text)
            head.append("# Fields: valid vector seed path xpub xprv | invalid 5 text reason")
            outputs["bip32.txt"] = "\n".join(head + body) + "\n"
        else:
            body = slip10(text)
            head.append("# Fields: curve seed path fingerprint chain_code private public")
            outputs["slip10.txt"] = "\n".join(head + body) + "\n"
    stale = []
    for target, text in outputs.items():
        path = os.path.join(OUT, target)
        if args.check:
            if not os.path.exists(path) or open(path, encoding="utf-8").read() != text:
                stale.append(target)
            continue
        os.makedirs(OUT, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print("%s: %d lines" % (target, text.count("\n") - 3))
    if stale:
        print("stale: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

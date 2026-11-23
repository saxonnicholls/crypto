#!/usr/bin/env python3
#
#  generate_wycheproof_fixtures.py
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Converts Wycheproof test vector files (https://github.com/C2SP/wycheproof, testvectors_v1/, Apache-2.0) into the
#  compact line-based fixtures under tests/fixtures/wycheproof/, which the tests read at run time. The JSON is
#  downloaded by hand into a directory of its own and passed here; this script never fetches anything, so a fixture
#  is reproducible from the recorded source files alone (their SHA-256 values are in tests/fixtures/README.md and in
#  each fixture's header).
#
#      python3 -I scripts/generate_wycheproof_fixtures.py --source DIR --commit SHA          write every fixture
#      python3 -I scripts/generate_wycheproof_fixtures.py --source DIR --commit SHA --check  compare, write nothing
#      python3 -I scripts/generate_wycheproof_fixtures.py --rfc8032 rfc8032.txt               RFC 8032's section 7.1
#      python3 -I scripts/generate_wycheproof_fixtures.py --bip340 test-vectors.csv           BIP-340's vectors
#
#  The RFC 8032 mode reads the RFC's plain text (https://www.rfc-editor.org/rfc/rfc8032.txt) and writes
#  tests/fixtures/rfc8032_ed25519.txt, since TEST 1024's message is too long to copy into a test by hand.
#
#  One function per source file, registered in CONVERTERS: to add a file, write its converter and register it.
#  Every fixture line is "tcId result field field ...", hex fields, "-" for an empty field; result is valid,
#  invalid or acceptable, as Wycheproof gives it.
#

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures", "wycheproof")


def field(x):
    return x if x else "-"


def header(name, source_sha, commit, fields):
    return [
        "# Wycheproof testvectors_v1/%s, converted by scripts/generate_wycheproof_fixtures.py" % name,
        "# Source: https://github.com/C2SP/wycheproof at commit %s, SHA-256 %s" % (commit, source_sha),
        "# Licence: Apache-2.0 (the Wycheproof project's test vectors)",
        "# Fields: tcId result " + " ".join(fields),
    ]


def ed25519(data):
    """ed25519_test.json: one line per test, the group's public key repeated on each."""
    lines = []
    for g in data["testGroups"]:
        pk = g["publicKey"]["pk"]
        for t in g["tests"]:
            lines.append("%d %s %s %s %s" % (t["tcId"], t["result"], pk, field(t["msg"]), field(t["sig"])))
    return ["pk", "msg", "sig"], lines


def x25519(data):
    """x25519_test.json: curve25519 groups only."""
    lines = []
    for g in data["testGroups"]:
        if g["curve"] != "curve25519":
            continue
        for t in g["tests"]:
            lines.append("%d %s %s %s %s" % (t["tcId"], t["result"], t["private"], t["public"], field(t["shared"])))
    return ["private", "public", "shared"], lines


def ecdsa_p256(data):
    """ecdsa_secp256r1_sha256*_test.json: a "key" line per group (the uncompressed SEC1 key), then its tests."""
    lines = []
    for g in data["testGroups"]:
        assert g["publicKey"]["curve"] == "secp256r1" and g["sha"] == "SHA-256"
        lines.append("key - %s" % g["publicKey"]["uncompressed"])
        for t in g["tests"]:
            lines.append("%d %s %s %s" % (t["tcId"], t["result"], field(t["msg"]), field(t["sig"])))
    return ["msg", "sig (key lines: key - uncompressed_public_key)"], lines


def ecdsa_secp256k1(data):
    """ecdsa_secp256k1_sha256*_test.json: a "key" line per group (the uncompressed SEC1 key), then its tests."""
    lines = []
    for g in data["testGroups"]:
        assert g["publicKey"]["curve"] == "secp256k1" and g["sha"] == "SHA-256"
        lines.append("key - %s" % g["publicKey"]["uncompressed"])
        for t in g["tests"]:
            lines.append("%d %s %s %s" % (t["tcId"], t["result"], field(t["msg"]), field(t["sig"])))
    return ["msg", "sig (key lines: key - uncompressed_public_key)"], lines


def rsa(data):
    """rsa_signature_*_sha256_test.json and rsa_pss_*_sha256_mgf1_*_test.json: a "key" line per group (the key as
    SPKI DER, as a bare PKCS#1 RSAPublicKey, and as n and e; and the PSS salt length, '-' for PKCS#1 v1.5), then
    its tests."""
    lines = []
    for g in data["testGroups"]:
        assert g["sha"] == "SHA-256", g["sha"]
        if g["type"] == "RsassaPssVerify":
            assert g["mgf"] == "MGF1" and g["mgfSha"] == "SHA-256"
            slen = str(g["sLen"])
        else:
            assert g["type"] == "RsassaPkcs1Verify", g["type"]
            slen = "-"
        k = g["publicKey"]
        n = k["modulus"].lstrip("0") or "0"
        n = ("0" + n) if len(n) % 2 else n
        lines.append("key - %s %s %s %s %s" % (g["publicKeyDer"], g["publicKeyAsn"], n, k["publicExponent"], slen))
        for t in g["tests"]:
            lines.append("%d %s %s %s" % (t["tcId"], t["result"], field(t["msg"]), field(t["sig"])))
    return ["msg", "sig (key lines: key - spki_der rsapublickey_der n e salt_length)"], lines


CONVERTERS = {
    "ecdsa_secp256k1_sha256_bitcoin_test.json": ("ecdsa_secp256k1_sha256_bitcoin.txt", ecdsa_secp256k1),
    "ecdsa_secp256k1_sha256_p1363_test.json": ("ecdsa_secp256k1_sha256_p1363.txt", ecdsa_secp256k1),
    "ecdsa_secp256k1_sha256_test.json": ("ecdsa_secp256k1_sha256.txt", ecdsa_secp256k1),
    "ed25519_test.json": ("ed25519.txt", ed25519),
    "x25519_test.json": ("x25519.txt", x25519),
    "ecdsa_secp256r1_sha256_test.json": ("ecdsa_p256_sha256.txt", ecdsa_p256),
    "ecdsa_secp256r1_sha256_p1363_test.json": ("ecdsa_p256_sha256_p1363.txt", ecdsa_p256),
    "rsa_signature_2048_sha256_test.json": ("rsa_pkcs1_2048_sha256.txt", rsa),
    "rsa_signature_3072_sha256_test.json": ("rsa_pkcs1_3072_sha256.txt", rsa),
    "rsa_signature_4096_sha256_test.json": ("rsa_pkcs1_4096_sha256.txt", rsa),
    "rsa_pss_2048_sha256_mgf1_0_test.json": ("rsa_pss_2048_sha256_mgf1_0.txt", rsa),
    "rsa_pss_2048_sha256_mgf1_32_test.json": ("rsa_pss_2048_sha256_mgf1_32.txt", rsa),
    "rsa_pss_3072_sha256_mgf1_32_test.json": ("rsa_pss_3072_sha256_mgf1_32.txt", rsa),
    "rsa_pss_4096_sha256_mgf1_32_test.json": ("rsa_pss_4096_sha256_mgf1_32.txt", rsa),
}


def rfc8032_ed25519(raw):
    """RFC 8032 section 7.1: the five Ed25519 tests, hex lines gathered under each label, page breaks skipped."""
    text = raw.decode("ascii")
    start = text.index("\n7.1.  Test Vectors for Ed25519\n")
    end = text.index("\n7.2.  Test Vectors for Ed25519ctx\n")
    tests, label = [], None
    for line in text[start:end].split("\n"):
        m = re.match(r"   -----TEST (.*)$", line)
        if m:
            tests.append({"name": m.group(1).strip().replace(" ", "_"), "sk": "", "pk": "", "msg": "", "sig": ""})
            label = None
            continue
        for key, lab in (("sk", "SECRET KEY:"), ("pk", "PUBLIC KEY:"), ("msg", "MESSAGE"), ("sig", "SIGNATURE:")):
            if line.strip().startswith(lab):
                label = key
        if tests and label and re.fullmatch(r"   [0-9a-f]+", line):
            tests[-1][label] += line.strip()
    out = ["# RFC 8032, section 7.1 (Test Vectors for Ed25519), from https://www.rfc-editor.org/rfc/rfc8032.txt",
           "# Converted by scripts/generate_wycheproof_fixtures.py --rfc8032; source SHA-256 %s" % hashlib.sha256(raw).hexdigest(),
           "# Fields: name seed public_key message signature"]
    out += [" ".join([t["name"], t["sk"], t["pk"], field(t["msg"]), t["sig"]]) for t in tests]
    return "\n".join(out) + "\n"


def bip340(raw):
    """BIP-340's test-vectors.csv: index, secret key, public key, aux_rand, message, signature, result, comment."""
    import csv, io
    out = ["# BIP-340 test-vectors.csv, from https://github.com/bitcoin/bips (bip-0340/), converted by",
           "# scripts/generate_wycheproof_fixtures.py --bip340; source SHA-256 %s; licence BSD-2-Clause (BIP-340)" % hashlib.sha256(raw).hexdigest(),
           "# Fields: index secret_key public_key aux_rand message signature result(TRUE/FALSE)"]
    for row in csv.DictReader(io.StringIO(raw.decode("ascii"))):
        out.append(" ".join([row["index"], field(row["secret key"].lower()), row["public key"].lower(), field(row["aux_rand"].lower()),
                             field(row["message"].lower()), row["signature"].lower(), row["verification result"]]))
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", help="directory holding the downloaded Wycheproof JSON files")
    ap.add_argument("--commit", help="the Wycheproof commit the files were downloaded from")
    ap.add_argument("--rfc8032", help="RFC 8032's plain text, to write rfc8032_ed25519.txt")
    ap.add_argument("--bip340", help="BIP-340's test-vectors.csv, to write bip340.txt")
    ap.add_argument("--check", action="store_true", help="compare with the committed fixtures, write nothing")
    args = ap.parse_args()

    if args.rfc8032:
        text = rfc8032_ed25519(open(args.rfc8032, "rb").read())
        out = os.path.join(ROOT, "tests", "fixtures", "rfc8032_ed25519.txt")
        if args.check:
            return 0 if os.path.exists(out) and open(out, encoding="utf-8").read() == text else 1
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print("rfc8032_ed25519.txt: %d tests" % (text.count("\n") - 3))
        return 0
    if args.bip340:
        text = bip340(open(args.bip340, "rb").read())
        out = os.path.join(ROOT, "tests", "fixtures", "bip340.txt")
        if args.check:
            return 0 if os.path.exists(out) and open(out, encoding="utf-8").read() == text else 1
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print("bip340.txt: %d vectors" % (text.count("\n") - 3))
        return 0
    if not args.source or not args.commit:
        ap.error("--source and --commit are required for the Wycheproof files")

    stale = []
    for source, (target, convert) in sorted(CONVERTERS.items()):
        path = os.path.join(args.source, source)
        if not os.path.exists(path):
            print("skip %s (not in %s)" % (source, args.source))
            continue
        raw = open(path, "rb").read()
        sha = hashlib.sha256(raw).hexdigest()
        fields, lines = convert(json.loads(raw))
        text = "\n".join(header(source, sha, args.commit, fields) + lines) + "\n"
        out = os.path.join(OUT, target)
        if args.check:
            if not os.path.exists(out) or open(out, encoding="utf-8").read() != text:
                stale.append(target)
            continue
        os.makedirs(OUT, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print("%s: %d tests from %s (SHA-256 %s)" % (target, len(lines), source, sha))
    if stale:
        print("stale: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
#
#  generate_oracle_fixtures.py
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Writes tests/fixtures/oracles/: large deterministic corpora answered by other implementations (the oracles of
#  scripts/oracles/, pinned in docker/oracles), which tests/*/*_oracles_test.cpp replay against this library.
#
#      python3 scripts/generate_oracle_fixtures.py            write the fixtures (runs itself in the oracle image)
#      python3 scripts/generate_oracle_fixtures.py --check    regenerate in memory, fail on any difference
#
#  Run outside the image, it builds the image (scripts/oracles/image.sh) and runs itself inside it, the checkout
#  mounted (read-only with --check). The CTest generated.oracle_fixtures_up_to_date runs --check in the image.
#
#  Every input comes from a fixed seed, so a run is deterministic: the same pins give the same bytes.
#
#  The rule, never a majority vote. For each case every oracle that offers the operation is asked. Where the
#  operation is deterministic all of them must give the same answer, byte for byte (after the one stated
#  normalisation: OpenSSL's ECDSA s is not reduced to low-S); that answer is the fixture's, and the library must
#  reproduce it. Where implementations are known to follow different rules (Ed25519 verification, BIP-39 text,
#  SEC1 and DER parsing, base58 and bech32 decoding), each oracle's rule is written down below as a model, every
#  oracle's verdict must match its own model, and the library's expected verdict is the model of its own rule
#  (CLAUDE.md, rule 8). A verdict that matches no stated rule stops the run: someone has to read it.
#

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures", "oracles")
HOME = os.environ.get("ORACLES_HOME", "/opt/oracles")

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ---------------------------------------------------------------------------------------------------------------
# The oracle processes

class Oracle:
    def __init__(self, name, argv, cwd=None):
        self.name = name
        self.proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     bufsize=1)
        self.libs = self.batch([{"op": "version"}])[0]
        self.lock = threading.Lock()

    def batch(self, requests):
        # Requests are written from a thread while answers are read, so neither pipe fills and blocks the other
        def feed():
            for i, q in enumerate(requests):
                self.proc.stdin.write(json.dumps(dict(q, id=i)) + "\n")
            self.proc.stdin.flush()
        t = threading.Thread(target=feed)
        t.start()
        out = []
        for i in range(len(requests)):
            line = self.proc.stdout.readline()
            if not line:
                sys.exit("generate_oracle_fixtures: oracle %s exited" % self.name)
            a = json.loads(line)
            if a.pop("id", i) != i:
                sys.exit("generate_oracle_fixtures: oracle %s answered out of order" % self.name)
            out.append(a)
        t.join()
        return out

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


class Pool:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="oracles-")
        node_dir = os.path.join(self.tmp, "node")
        os.mkdir(node_dir)
        shutil.copy(os.path.join(ROOT, "scripts", "oracles", "node", "oracle.mjs"), node_dir)
        os.symlink(os.path.join(HOME, "node", "node_modules"), os.path.join(node_dir, "node_modules"))
        target = os.environ.get("CARGO_TARGET_DIR", os.path.join(HOME, "rust-target"))
        subprocess.run(["cargo", "build", "--release", "--locked", "--offline", "--quiet",
                        "--manifest-path", os.path.join(ROOT, "scripts", "oracles", "rust", "Cargo.toml")],
                       check=True, env=dict(os.environ, CARGO_TARGET_DIR=target))
        self.oracles = [
            Oracle("python", [os.path.join(HOME, "venv", "bin", "python"), "-I",
                              os.path.join(ROOT, "scripts", "oracles", "python", "oracle.py")]),
            Oracle("node", ["node", os.path.join(node_dir, "oracle.mjs")], cwd=node_dir),
            Oracle("rust", [os.path.join(target, "release", "snicholls-crypto-oracle")]),
        ]
        self.where = {}
        for o in self.oracles:
            for lib, info in o.libs["libs"].items():
                self.where[lib] = (o, info)
        self.used = {}   # lib -> number of answers that went into a fixture

    def libs_for(self, op):
        return sorted(lib for lib, (_, info) in self.where.items() if op in info["ops"])

    def ask(self, op, cases, libs=None):
        """Asks every lib offering op about every case: a list (one per case) of {lib: answer}."""
        libs = libs or self.libs_for(op)
        answers = [dict() for _ in cases]
        for lib in libs:
            o, _ = self.where[lib]
            got = o.batch([dict(c, lib=lib, op=op) for c in cases])
            for i, a in enumerate(got):
                if "crash" in a:
                    sys.exit("generate_oracle_fixtures: %s crashed on %s %s:\n%s" % (lib, op, json.dumps(cases[i]),
                                                                                    a["crash"]))
                if not a.get("unsupported"):
                    answers[i][lib] = a
        return answers

    def count(self, libs):
        for lib in libs:
            self.used[lib] = self.used.get(lib, 0) + 1

    def manifest(self):
        out = {"toolchains": {}, "oracles": {}}
        for o in self.oracles:
            out["toolchains"][o.name] = o.libs.get("node") if o.name == "node" else None
        out["toolchains"]["python"] = sys.version.split()[0]
        out["toolchains"]["node"] = self.oracles[1].libs.get("node")
        out["toolchains"]["rust"] = subprocess.run(["rustc", "--version"], capture_output=True,
                                                   text=True).stdout.strip()
        for lib, (o, info) in sorted(self.where.items()):
            out["oracles"][lib] = {"program": o.name, "version": info["version"], "answers": self.used.get(lib, 0)}
        return out

    def close(self):
        for o in self.oracles:
            o.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class Disagreement(Exception):
    pass


FAILURES = []


def fail(category, case, detail):
    FAILURES.append("%s: %s\n    case: %s" % (category, detail, json.dumps(case, sort_keys=True)))


def consensus(pool, category, case, answers, norm):
    """The one answer every oracle gives (each normalised by norm(lib, answer)), and the libs that gave it."""
    values = {lib: norm(lib, a) for lib, a in answers.items()}
    distinct = set(json.dumps(v, sort_keys=True) for v in values.values())
    if not values:
        fail(category, case, "no oracle answered")
        return None, []
    if len(distinct) != 1:
        fail(category, case, "oracles disagree: " + json.dumps(values, sort_keys=True))
        return None, []
    pool.count(values)
    return next(iter(values.values())), sorted(values)


def refused_or(a, *fields):
    if "error" in a:
        return None
    return [a[f] for f in fields]


# ---------------------------------------------------------------------------------------------------------------
# Fixture files

class Fixture:
    def __init__(self, name, title, columns, notes=()):
        self.name, self.title, self.columns, self.notes = name, title, columns, list(notes)
        self.rows, self.libs = [], set()

    def add(self, fields, libs):
        self.rows.append(" ".join("-" if f in (None, "") else str(f) for f in fields))
        self.libs.update(libs)

    def text(self, pool):
        head = ["# %s" % self.title,
                "# Generated by scripts/generate_oracle_fixtures.py from fixed seeds; never edited by hand.",
                "# Columns: %s" % self.columns]
        head += ["# " + n for n in self.notes]
        head.append("# Oracles (versions in manifest.json): %s" % ", ".join(sorted(self.libs)))
        head.append("# %d cases" % len(self.rows))
        return "\n".join(head + self.rows) + "\n"


# ---------------------------------------------------------------------------------------------------------------
# Inputs

def rand_bytes(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def hx(b):
    return bytes(b).hex()


def i32(v):
    assert 0 <= v < 2**256, v
    return "%064x" % v


EDGE_KEYS = [0, 1, 2, 3, N - 1, N - 2, N, N + 1, 2**256 - 1, 2**255, (N - 1) // 2, (N + 1) // 2, 2**128,
             P, P - N]


# ---------------------------------------------------------------------------------------------------------------
# secp256k1

def gen_secp256k1(pool, fx):
    rng = random.Random("secp256k1 keys v1")
    keys = [i32(k) for k in EDGE_KEYS] + [hx(rand_bytes(rng, 32)) for _ in range(1000)]
    f = Fixture("secp256k1_keys.txt", "secp256k1 private keys to public keys (SEC1)",
                "private key, compressed public key, uncompressed public key ('-' '-': the key is refused, "
                "0 or at or above n)")
    answers = pool.ask("sec_pub", [{"sk": k} for k in keys])
    good = []
    for k, ans in zip(keys, answers):
        v, libs = consensus(pool, f.name, {"sk": k}, ans, lambda lib, a: refused_or(a, "c", "u"))
        if libs:
            f.add([k] + (v or [None, None]), libs)
            if v:
                good.append((k, v[0], v[1]))
    fx.append(f)

    # ECDSA: RFC 6979 with SHA-256's HMAC, low-S, the recovery id
    rng = random.Random("secp256k1 ecdsa v1")
    edge_h = [i32(0), i32(1), i32(N - 1), i32(N), i32(N + 1), i32(2**256 - 1), i32(P)]
    sign_cases = []
    for i, (k, c, u) in enumerate(good):
        h = edge_h[i] if i < len(edge_h) else hx(rand_bytes(rng, 32))
        sign_cases.append({"sk": k, "h": h})
    f = Fixture("ecdsa_sign.txt", "secp256k1 ECDSA signatures: RFC 6979 nonces (HMAC-SHA256), low-S, recovery id",
                "private key, 32-byte hash, r, s, recovery id, DER",
                ["OpenSSL (RFC 6979 mode) does not reduce s to low-S: its s is compared after s -> n - s when s > n/2,",
                 "and it gives no recovery id. DER is compared with the oracles that produce it."])
    answers = pool.ask("ecdsa_sign", sign_cases)
    sigs = []
    for case, ans in zip(sign_cases, answers):
        def rs(lib, a):
            s = int(a["s"], 16)
            return [a["r"], i32(min(s, N - s))]
        v, libs = consensus(pool, f.name, case, ans, rs)
        rec = {lib: a["v"] for lib, a in ans.items() if "v" in a}
        vid, _ = consensus(pool, f.name + " recovery id", case, {l: {"v": x} for l, x in rec.items()},
                           lambda lib, a: a["v"])
        der = {lib: a["der"] for lib, a in ans.items() if "der" in a and lib != "openssl"}
        d, _ = consensus(pool, f.name + " DER", case, {l: {"der": x} for l, x in der.items()},
                         lambda lib, a: a["der"])
        if v is None or vid is None or d is None:
            continue
        f.add([case["sk"], case["h"], v[0], v[1], vid, d], libs)
        sigs.append((case["sk"], case["h"], v[0], v[1], vid, d))
    fx.append(f)
    pub_of = {k: (c, u) for k, c, u in good}

    # Recovery: every signature above, and adversarial (r, s, id) triples
    rng = random.Random("secp256k1 recover v1")
    rec_cases = [{"h": h, "sig": r + s, "v": vid, "expect": pub_of[k][0]} for k, h, r, s, vid, _ in sigs[:600]]
    for _ in range(400):
        h = hx(rand_bytes(rng, 32))
        r = rng.choice([rng.getrandbits(256), rng.getrandbits(120), N - 1 - rng.getrandbits(8), 0, N, N + 1])
        s = rng.choice([rng.getrandbits(256), N - 1, 1, 0, N, (N + 1) // 2])
        rec_cases.append({"h": h, "sig": i32(r % 2**256) + i32(s % 2**256), "v": rng.randrange(4)})
    # High-S forms of real signatures: recovery accepts them (as the precompile does) and gives the same key
    # with the opposite parity bit
    for k, h, r, s, vid, _ in sigs[600:700]:
        rec_cases.append({"h": h, "sig": r + i32(N - int(s, 16)), "v": vid ^ 1, "expect": pub_of[k][0]})
    f = Fixture("ecdsa_recover.txt", "secp256k1 public-key recovery from (hash, r, s, recovery id), high-S accepted",
                "hash, r || s, recovery id, compressed key ('-': no key; r or s out of range, r not an x-coordinate, "
                "or the point at infinity)",
                ["ethers recovers only ids 0 and 1 (v = 27, 28), and refuses an s with its top bit set (s >= 2^255;",
                 "narrower than EIP-2's s <= n/2): it is checked to refuse those rows and not counted on them."])
    answers = pool.ask("ecdsa_recover", [{k: c[k] for k in ("h", "sig", "v")} for c in rec_cases])
    for case, ans in zip(rec_cases, answers):
        if case["v"] > 1:
            ans.pop("ethers", None)
        if int(case["sig"][64:], 16) >= 2**255 and "ethers" in ans:
            # ethers' rule: Signature.from refuses an s whose top bit is set, in recovery too (narrower than
            # EIP-2's s <= n/2: an s between n/2 and 2^255 is accepted, and must then agree)
            if "error" not in ans.pop("ethers"):
                fail(f.name, case, "ethers recovered from an s >= 2^255")
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: refused_or(a, "c"))
        if not libs:
            continue
        if "expect" in case and (v is None or v[0] != case["expect"]):
            fail(f.name, case, "recovered a key other than the signer's")
        f.add([case["h"], case["sig"], case["v"], v[0] if v else None], libs)
    fx.append(f)

    # Ethereum: ecrecover addresses (v = 27 or 28) and the address of a key
    rng = random.Random("secp256k1 ethereum v1")
    eth_cases = []
    for k, h, r, s, vid, _ in sigs[:400]:
        if vid < 2:
            eth_cases.append({"h": h, "sig65": r + s + "%02x" % (27 + vid)})
    for _ in range(100):
        eth_cases.append({"h": hx(rand_bytes(rng, 32)),
                          "sig65": hx(rand_bytes(rng, 64)) + "%02x" % rng.choice([27, 28])})
    f = Fixture("ethereum.txt", "Ethereum ecrecover: the address recovered from (hash, r || s || v), v = 27 or 28",
                "hash, r || s || v (65 bytes), address (20 bytes; '-': nothing recovers)",
                ["ethers refuses an s with its top bit set (narrower than EIP-2's s <= n/2, and unlike the",
                 "precompile, which this library follows with high_s::accept): such rows are checked and left out."])
    answers = pool.ask("eth_ecrecover", eth_cases)
    for case, ans in zip(eth_cases, answers):
        if int(case["sig65"][64:128], 16) >= 2**255:
            # ethers' rule (see ecdsa_recover.txt): an s with its top bit set is refused; ethers is this fixture's
            # only oracle, so the row is left out once that is checked
            if "error" not in ans.get("ethers", {"error": 1}):
                fail("ethereum.txt", case, "ethers recovered from an s >= 2^255")
            continue
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: refused_or(a, "addr"))
        if libs:
            f.add([case["h"], case["sig65"], v[0] if v else None], libs)
    fx.append(f)

    # Addresses of one key: Bitcoin's standard forms and Ethereum's
    f = Fixture("key_addresses.txt", "The addresses of a secp256k1 public key",
                "compressed key, P2PKH, P2SH-P2WPKH (BIP-49), P2WPKH (BIP-84), P2TR output key (the key as BIP-86's "
                "internal key, tweaked), P2TR address, Ethereum address",
                ["The taproot tweak is not part of this library; the replay checks the P2TR address's encoding of",
                 "the output key the oracle computed."])
    sample = good[16:416]
    btc = pool.ask("addresses", [{"pub": c} for _, c, _ in sample])
    eth = pool.ask("eth_address", [{"pub": u} for _, _, u in sample])
    for (k, c, u), b, e in zip(sample, btc, eth):
        bv, bl = consensus(pool, f.name, {"pub": c}, b,
                           lambda lib, a: [a["p2pkh"], a["p2sh_p2wpkh"], a["p2wpkh"], a["p2tr_output"], a["p2tr"]])
        ev, el = consensus(pool, f.name, {"pub": u}, e, lambda lib, a: a["addr"])
        if bl and el:
            f.add([c] + bv + [ev], bl + el)
    fx.append(f)
    return good, sigs, pub_of


def secp_point_y(x):
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    return y if y * y % P == y2 else None


def gen_secp256k1_parse(pool, fx, good):
    # SEC1 public keys: valid, hybrid (0x06 / 0x07), off the curve, x or y at or above p, wrong lengths
    rng = random.Random("secp256k1 sec1 v1")
    cases = []
    for k, c, u in good[:300]:
        cases.append(c)
        cases.append(u)
        x, y = int(u[2:66], 16), int(u[66:], 16)
        cases.append("%02x" % (6 + (y & 1)) + u[2:])                    # hybrid, right parity
        cases.append("%02x" % (7 - (y & 1)) + u[2:])                    # hybrid, wrong parity
        cases.append("04" + i32(x) + i32((y + 1) % P))                  # off the curve
    for _ in range(200):
        x = rng.getrandbits(256)
        cases.append(rng.choice(["02", "03"]) + i32(x))                 # half are not x-coordinates
    for x in (P, P + 1, 2**256 - 1, 0, 1, 7):
        cases.append("02" + i32(x))
        cases.append("03" + i32(x))
    x = int(good[0][2][2:66], 16)
    y = int(good[0][2][66:], 16)
    cases += ["00", "",
              "04" + i32(x), "02" + i32(x) + "00", "05" + i32(x) + i32(y)]
    for x in range(2, 12):
        y = secp_point_y(x)
        if y is not None and y + P < 2**256:
            cases.append("04" + i32(x) + i32(y + P))                    # y at or above p
    f = Fixture("sec1_parse.txt", "SEC1 public-key parsing",
                "encoding, compressed form ('-': refused), rule ('sec1' or 'hybrid')",
                ["This library reads compressed (0x02, 0x03) and uncompressed (0x04) keys only, with x and y below p,",
                 "on the curve. libsecp256k1 (coincurve, secp256k1_rs) also reads SEC1's hybrid form (0x06, 0x07,",
                 "the y parity checked); k256 and noble do not. Hybrid rows say which rule each oracle followed."])
    answers = pool.ask("pub_parse", [{"pub": c} for c in cases])
    hybrid_libs = {"coincurve", "secp256k1_rs"}
    for c, ans in zip(cases, answers):
        if c[:2] in ("06", "07") and len(c) == 130:
            # libsecp256k1's rule: hybrid accepted when the parity matches; the others refuse
            y = int(c[66:], 16)
            on = secp_point_y(int(c[2:66], 16)) is not None and int(c[2:66], 16) < P and y < P and \
                (pow(int(c[2:66], 16), 3, P) + 7 - y * y) % P == 0
            want_hybrid = (("02" if y % 2 == 0 else "03") + c[2:66]) if on and (int(c[:2], 16) & 1) == (y & 1) else None
            for lib, a in ans.items():
                got = a.get("c")
                if lib in hybrid_libs and got != want_hybrid:
                    fail(f.name, c, "%s does not follow libsecp256k1's hybrid rule: %s" % (lib, a))
                if lib not in hybrid_libs and got is not None:
                    fail(f.name, c, "%s accepted a hybrid key" % lib)
            pool.count(ans)
            f.add([c, None, "hybrid"], sorted(ans))
            continue
        v, libs = consensus(pool, f.name, {"pub": c}, ans, lambda lib, a: refused_or(a, "c"))
        if libs:
            f.add([c if c else None, v[0] if v else None, "sec1"], libs)
    fx.append(f)


def gen_ecdsa_verify(pool, fx, good, sigs):
    rng = random.Random("secp256k1 verify v1")
    cases = []

    def add(pub, h, r, s, why):
        cases.append({"pub": pub, "h": h, "sig": i32(r % 2**256) + i32(s % 2**256), "why": why})

    for n, (k, h, r, s, vid, _) in enumerate(sigs[:500]):
        c, u = None, None
        for kk, cc, uu in good:
            if kk == k:
                c, u = cc, uu
                break
        ri, si = int(r, 16), int(s, 16)
        pub = c if n % 2 else u
        add(pub, h, ri, si, "valid")
        add(pub, h, ri, N - si, "high-S")
        flip = 1 << rng.randrange(256)
        add(pub, hx((int(h, 16) ^ flip).to_bytes(32, "big")), ri, si, "hash bit flipped")
        add(pub, h, ri ^ (1 << rng.randrange(256)), si, "r bit flipped")
        add(pub, h, ri, si ^ (1 << rng.randrange(256)), "s bit flipped")
        add(good[(n + 1) % len(good)][1], h, ri, si, "another key")
        if n < 40:
            for rr, ss, why in ((0, si, "r = 0"), (ri, 0, "s = 0"), (N, si, "r = n"), (ri, N, "s = n"),
                                (ri + N, si, "r + n"), (ri, si + N, "s + n"), (N - 1, si, "r = n - 1"),
                                (ri, 2**256 - 1, "s = 2^256 - 1")):
                add(pub, h, rr, ss, why)
    f = Fixture("ecdsa_verify.txt", "secp256k1 ECDSA verification, under both high-S policies",
                "public key (SEC1), hash, r || s, policy (accept or reject: high_s), valid (1 or 0)",
                ["'reject' is libsecp256k1's own rule; libsecp256k1 answers 'accept' after its",
                 "secp256k1_ecdsa_signature_normalize, as Bitcoin Core does where consensus allows high-S; k256",
                 "likewise verifies low-S only and answers 'accept' after its normalize_s. OpenSSL answers 'accept'",
                 "only (textbook ECDSA)."])
    for policy in ("accept", "reject"):
        qs = [{"pub": c["pub"], "h": c["h"], "sig": c["sig"], "high_s": policy} for c in cases]
        libs = [l for l in pool.libs_for("ecdsa_verify") if not (l == "openssl" and policy == "reject")]
        answers = pool.ask("ecdsa_verify", qs, libs)
        for q, ans in zip(qs, answers):
            v, libs_ = consensus(pool, f.name, q, ans, lambda lib, a: int(bool(a.get("valid"))))
            if libs_:
                f.add([q["pub"], q["h"], q["sig"], policy, v], libs_)
    fx.append(f)


def der_int(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def der_of(r, s):
    body = b"\x02" + bytes([len(der_int(r))]) + der_int(r) + b"\x02" + bytes([len(der_int(s))]) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def strict_der(d):
    """This library's rule (and BIP-66's): the canonical DER of two non-negative integers below 2^256."""
    if len(d) < 8 or len(d) > 72 or d[0] != 0x30 or d[1] != len(d) - 2 or d[2] != 0x02:
        return None
    lr = d[3]
    if lr == 0 or 5 + lr >= len(d) or d[4 + lr] != 0x02:
        return None
    ls = d[5 + lr]
    if ls == 0 or lr + ls + 6 != len(d):
        return None
    out = []
    for v in (d[4:4 + lr], d[6 + lr:6 + lr + ls]):
        if v[0] & 0x80 or (len(v) > 1 and v[0] == 0 and not v[1] & 0x80) or len(v) > 33 or (len(v) == 33 and v[0]):
            return None
        out.append(int.from_bytes(v, "big"))
    return out


def libsecp_der(d):
    """libsecp256k1's secp256k1_ecdsa_signature_parse_der: the same DER structure and minimal encodings, but an
    integer that is negative, longer than 32 bytes or at or above n is an overflow, and that integer reads as zero
    (the signature then never verifies) instead of being refused."""
    if len(d) < 8 or len(d) > 72 or d[0] != 0x30 or d[1] != len(d) - 2 or d[2] != 0x02:
        return None
    lr = d[3]
    if lr == 0 or 5 + lr >= len(d) or d[4 + lr] != 0x02:
        return None
    ls = d[5 + lr]
    if ls == 0 or lr + ls + 6 != len(d):
        return None
    out = []
    for v in (d[4:4 + lr], d[6 + lr:6 + lr + ls]):
        if len(v) > 1 and ((v[0] == 0 and not v[1] & 0x80) or (v[0] == 0xff and v[1] & 0x80)):
            return None   # excessive 0x00 or 0xFF padding
        x = int.from_bytes(v, "big")
        out.append(0 if v[0] & 0x80 or x >= N else x)
    return out


def gen_ecdsa_der(pool, fx, good, sigs):
    rng = random.Random("secp256k1 der v1")
    pub_of = {k: c for k, c, _ in good}
    cases = []
    for k, h, r, s, vid, d in sigs[:300]:
        pub = pub_of[k]
        db = bytes.fromhex(d)
        ri, si = int(r, 16), int(s, 16)
        muts = [db,
                db + b"\x00",                                           # trailing byte
                db[:-1],                                                # truncated
                b"\x30\x81" + bytes([len(db) - 2]) + db[2:],            # long-form length
                bytes([db[0], db[1] + 1]) + db[2:4] + b"\x00" + db[4:] if db[3] < 33 else db[:1] + b"\x00" + db[2:],
                b"\x31" + db[1:],                                       # SET, not SEQUENCE
                db[:2] + b"\x03" + db[3:],                              # BIT STRING, not INTEGER
                der_of(ri, N - si),                                     # high-S
                der_of(ri + N, si) if ri + N < 2**256 else der_of(ri, si),   # r at or above n
                der_of(0, si), der_of(ri, 0)]
        m = bytearray(db)
        m[rng.randrange(len(m))] ^= 1 << rng.randrange(8)
        muts.append(bytes(m))
        # an INTEGER with its sign byte dropped (negative), and one of 33 significant bytes
        if db[4] == 0:
            muts.append(db[:1] + bytes([db[1] - 1]) + db[2:3] + bytes([db[3] - 1]) + db[5:])
        muts.append(b"\x30" + bytes([2 + 34 + 2 + len(der_int(si))]) + b"\x02\x22\x01" + ri.to_bytes(33, "big")[1:]
                    .rjust(33, b"\x00") + b"\x02" + bytes([len(der_int(si))]) + der_int(si))
        for x in muts:
            cases.append({"pub": pub, "h": h, "der": hx(x)})
    f = Fixture("ecdsa_der.txt", "secp256k1 ECDSA signatures in DER: parsing and verification (high-S accepted)",
                "public key, hash, DER, r || s as parsed ('-': refused), valid (1 or 0)",
                ["This library and BIP-66 read canonical DER of two non-negative integers below 2^256; r or s at or",
                 "above n then fails verification. Each oracle's parse was checked against its stated rule:",
                 "  k256: the same encoding rule, and refuses r or s outside [1, n - 1];",
                 "  libsecp256k1 (coincurve, secp256k1_rs): the same structure and minimal lengths (no redundant 0x00 or",
                 "  0xFF byte), but a negative",
                 "  INTEGER, or one at or above n, is an overflow and that integer reads as zero, not refused;",
                 "  OpenSSL verifies the bytes, refusing any encoding that does not re-encode to itself.",
                 "valid is under high_s::accept, from every oracle that verifies the row (the low-S-only ones",
                 "are not counted on high-S rows); every one must agree."])
    answers = pool.ask("ecdsa_verify_der", cases)
    for case, ans in zip(cases, answers):
        d = bytes.fromhex(case["der"])
        ours = strict_der(d)
        # valid: every oracle that verified the bytes must agree (libsecp256k1 rejects high-S: normalise first)
        verdicts = {}
        for lib, a in ans.items():
            if "error" in a:
                verdicts[lib] = 0
            elif lib in ("coincurve", "secp256k1_rs", "k256") and a.get("rs") and int(a["rs"][64:], 16) > N // 2:
                continue   # high-S: these verify low-S only; OpenSSL answers for the high-S rows
            else:
                verdicts[lib] = int(bool(a.get("valid")))
        parsed = {}
        for lib in ("coincurve", "secp256k1_rs", "k256"):
            if lib in ans:
                parsed[lib] = ans[lib].get("rs")
        # The stated parse rules: k256 is this library's; libsecp256k1 the same, but r or s >= n reads as 0
        want = None if ours is None else i32(ours[0]) + i32(ours[1])
        lsec = libsecp_der(d)
        for lib, got in parsed.items():
            if lib == "k256":
                # k256: this library's DER rule, and r and s in [1, n - 1] (its Signature holds only those)
                k_want = want if ours is not None and 0 < ours[0] < N and 0 < ours[1] < N else None
                if got != k_want:
                    fail(f.name, case, "k256 parsed %s, the stated rule gives %s" % (got, k_want))
            else:
                l_want = None if lsec is None else i32(lsec[0]) + i32(lsec[1])
                if got != l_want:
                    fail(f.name, case, "%s parsed %s, the stated rule gives %s" % (lib, got, l_want))
        v_set = set(verdicts.values())
        if len(v_set) > 1:
            fail(f.name, case, "verdicts disagree: %s" % verdicts)
            continue
        valid = v_set.pop() if v_set else 0
        if ours is None and valid:
            fail(f.name, case, "an oracle verified a non-canonical DER")
        pool.count(ans)
        f.add([case["pub"], case["h"], case["der"], want, valid], sorted(ans))
    fx.append(f)


def gen_schnorr(pool, fx, good):
    rng = random.Random("secp256k1 bip340 v1")
    cases = []
    for i, (k, c, u) in enumerate(good[:700]):
        n = 32 if i < 600 else rng.choice([0, 1, 17, 31, 33, 64, 100, 255])
        aux = hx(bytes(32)) if i % 10 == 0 else hx(rand_bytes(rng, 32))
        cases.append({"sk": k, "m": hx(rand_bytes(rng, n)), "aux": aux})
    f = Fixture("bip340_sign.txt", "BIP-340 Schnorr signatures with fixed auxiliary randomness",
                "private key, message, aux_rand, signature, x-only public key",
                ["coincurve signs 32-byte messages only; the others sign any length (BIP-340's variable-length",
                 "messages)."])
    answers = pool.ask("schnorr_sign", cases)
    signed = []
    for case, ans in zip(cases, answers):
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: [a["sig"], a["x"]])
        if libs:
            f.add([case["sk"], case["m"], case["aux"], v[0], v[1]], libs)
            signed.append((v[1], case["m"], v[0]))
    fx.append(f)

    vcases = []
    for i, (x, m, sig) in enumerate(signed[:500]):
        r, s = int(sig[:64], 16), int(sig[64:], 16)
        vcases.append({"x": x, "m": m, "sig": sig})
        vcases.append({"x": x, "m": m, "sig": i32(r ^ (1 << rng.randrange(256))) + sig[64:]})
        vcases.append({"x": x, "m": m, "sig": sig[:64] + i32(s ^ (1 << rng.randrange(256)))})
        vcases.append({"x": signed[(i + 1) % len(signed)][0], "m": m, "sig": sig})
        if m:
            mm = bytearray(bytes.fromhex(m))
            mm[0] ^= 1
            vcases.append({"x": x, "m": hx(mm), "sig": sig})
        if i < 30:
            vcases.append({"x": x, "m": m, "sig": i32(P) + sig[64:]})
            vcases.append({"x": x, "m": m, "sig": sig[:64] + i32(N)})
            vcases.append({"x": x, "m": m, "sig": sig[:64] + i32(s + N) if s + N < 2**256 else sig})
            vcases.append({"x": i32(P), "m": m, "sig": sig})
            vcases.append({"x": i32(5), "m": m, "sig": sig})     # 5^3 + 7 is not a square mod p: not on the curve
    f = Fixture("bip340_verify.txt", "BIP-340 Schnorr verification",
                "x-only public key, message, signature, valid (1 or 0; a key that does not parse is 0)")
    answers = pool.ask("schnorr_verify", vcases)
    for case, ans in zip(vcases, answers):
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: int(bool(a.get("valid"))))
        if libs:
            f.add([case["x"], case["m"], case["sig"], v], libs)
    fx.append(f)


# ---------------------------------------------------------------------------------------------------------------
# Curve25519: a small model of the Edwards curve, for the verification rules

EP = 2**255 - 19
ED = (-121665 * pow(121666, EP - 2, EP)) % EP
EL = 2**252 + 27742317777372353535851937790883648493
SQRT_M1 = pow(2, (EP - 1) // 4, EP)


def e_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % EP
    b = (y1 + x1) * (y2 + x2) % EP
    c = 2 * t1 * t2 * ED % EP
    d = 2 * z1 * z2 % EP
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % EP, g * h % EP, f * g % EP, e * h % EP)


def e_mul(k, p):
    q = (0, 1, 1, 0)
    while k:
        if k & 1:
            q = e_add(q, p)
        p = e_add(p, p)
        k >>= 1
    return q


def e_neg(p):
    return ((-p[0]) % EP, p[1], p[2], (-p[3]) % EP)


def e_encode(p):
    zi = pow(p[2], EP - 2, EP)
    x, y = p[0] * zi % EP, p[1] * zi % EP
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def e_decode(b, canonical=True, negative_zero=False):
    v = int.from_bytes(b, "little")
    sign, y = v >> 255, v & (2**255 - 1)
    if y >= EP:
        if canonical:
            return None
        y -= EP
    u, w = (y * y - 1) % EP, (ED * y * y + 1) % EP
    x = u * pow(w, 3, EP) * pow(u * pow(w, 7, EP), (EP - 5) // 8, EP) % EP
    if (w * x * x - u) % EP != 0:
        x = x * SQRT_M1 % EP
        if (w * x * x - u) % EP != 0:
            return None
    if x == 0 and sign:
        if canonical and not negative_zero:
            return None
    if (x & 1) != sign:
        x = (-x) % EP
    return (x, y, 1, x * y % EP)


def e_is_identity(p):
    return p[0] % EP == 0 and (p[1] - p[2]) % EP == 0


def e_eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % EP == 0 and (p[1] * q[2] - q[1] * p[2]) % EP == 0


EB = e_decode((4 * pow(5, EP - 2, EP) % EP).to_bytes(32, "little"))


def small_order(p):
    return e_is_identity(e_mul(8, p))


def ed_rule(rule, pub, msg, sig):
    """The verdict of one stated Ed25519 verification rule. rule: a dict of the choices verifiers differ on."""
    s = int.from_bytes(sig[32:], "little")
    if s >= EL:
        return 0
    a = e_decode(pub, canonical=rule["canonical_A"], negative_zero=rule.get("negative_zero_A", False))
    if a is None:
        return 0
    if rule["reject_small_A"] and small_order(a):
        return 0
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % EL
    if rule["R_bytes"]:
        # R' = [S]B - [k]A, encoded and compared with R's bytes: R itself is never decoded
        if rule["reject_small_R"]:
            r = e_decode(sig[:32], canonical=False)
            if r is not None and small_order(r):
                return 0
        return int(e_encode(e_add(e_mul(s, EB), e_neg(e_mul(k, a)))) == sig[:32])
    r = e_decode(sig[:32], canonical=rule["canonical_R"])
    if r is None:
        return 0
    if rule["reject_small_R"] and small_order(r):
        return 0
    lhs, rhs = e_mul(s, EB), e_add(r, e_mul(k, a))
    if rule["cofactored"]:
        return int(e_is_identity(e_mul(8, e_add(lhs, e_neg(rhs)))))
    return int(e_eq(lhs, rhs))


# This library's rule (curve25519/ed25519.hpp, "Verification rule") and each oracle's, as their documentation
# states it; the run checks every oracle's verdicts against its rule here
ED_RULES = {
    "ours": dict(canonical_A=True, reject_small_A=False, R_bytes=True, canonical_R=True, reject_small_R=False,
                 cofactored=False),
    "openssl": dict(canonical_A=False, reject_small_A=False, R_bytes=True, canonical_R=True, reject_small_R=False,
                    cofactored=False),
    "pynacl": dict(canonical_A=True, reject_small_A=True, R_bytes=True, canonical_R=True, reject_small_R=True,
                   cofactored=False),
    "dalek": dict(canonical_A=False, reject_small_A=False, R_bytes=True, canonical_R=True, reject_small_R=False,
                  cofactored=False),
    "dalek_strict": dict(canonical_A=False, reject_small_A=True, R_bytes=True, canonical_R=True, reject_small_R=True,
                         cofactored=False),
    "noble_ed25519": dict(canonical_A=True, reject_small_A=True, R_bytes=False, canonical_R=True,
                          reject_small_R=False, cofactored=True),
    "noble_zip215": dict(canonical_A=False, reject_small_A=False, R_bytes=False, canonical_R=False,
                         reject_small_R=False, cofactored=True),
}

# Every small-order point in every encoding (canonical first, then y + p and the negative-zero forms)
SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]


def gen_ed25519(pool, fx):
    rng = random.Random("ed25519 sign v1")
    cases = [{"seed": hx(rand_bytes(rng, 32)), "m": hx(rand_bytes(rng, rng.choice([0, 1, 32, 64, 100, 1000])))}
             for _ in range(800)]
    f = Fixture("ed25519_sign.txt", "Ed25519 (RFC 8032) keys and signatures",
                "seed (the 32-byte private key), message, public key, signature")
    answers = pool.ask("ed25519_sign", cases)
    signed = []
    for case, ans in zip(cases, answers):
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: [a["pub"], a["sig"]])
        if libs:
            f.add([case["seed"], case["m"], v[0], v[1]], libs)
            signed.append((case["seed"], case["m"], v[0], v[1]))
    fx.append(f)

    # Verification: honest signatures and their mutations, S + L, every small-order A and R with S = 0, mixed-order
    # keys and nonces signed honestly (cofactorless and cofactored rules part there), keys that do not decode
    vcases = []
    for seed, m, pub, sig in signed[:150]:
        vcases.append(("honest", pub, m, sig))
        s = int.from_bytes(bytes.fromhex(sig[64:]), "little")
        vcases.append(("S + L", pub, m, sig[:64] + hx((s + EL).to_bytes(32, "little"))))
        mm = bytes.fromhex(m) + b"\x00"
        vcases.append(("message changed", pub, hx(mm), sig))
        b = bytearray(bytes.fromhex(sig))
        b[rng.randrange(64)] ^= 1 << rng.randrange(8)
        vcases.append(("signature bit flipped", pub, m, hx(b)))
    for a in SMALL_ORDER:
        for r in SMALL_ORDER:
            vcases.append(("small-order A and R, S = 0", a, hx(rand_bytes(rng, 16)), r + "00" * 32))
    torsion = [e_decode(bytes.fromhex(t)) for t in SMALL_ORDER[1:8]]
    for i in range(80):
        a = rng.randrange(1, EL)
        t = torsion[i % len(torsion)]
        big_a = e_add(e_mul(a, EB), t)
        pub = e_encode(big_a)
        m = rand_bytes(rng, 24)
        r = rng.randrange(1, EL)
        big_r = e_mul(r, EB) if i % 2 == 0 else e_add(e_mul(r, EB), torsion[(i * 3) % len(torsion)])
        rb = e_encode(big_r)
        k = int.from_bytes(hashlib.sha512(rb + pub + m).digest(), "little") % EL
        s = (r + k * a) % EL
        vcases.append(("mixed-order A" + (" and R" if i % 2 else ""), hx(pub), hx(m), hx(rb + s.to_bytes(32, "little"))))
    for _ in range(30):
        while True:
            pub = rand_bytes(rng, 32)
            if e_decode(pub, canonical=False) is None:
                break
        vcases.append(("A not on the curve", hx(pub), "00", hx(rand_bytes(rng, 32)) + "00" * 32))
    libs = pool.libs_for("ed25519_verify")
    cols = " ".join(libs)
    f = Fixture("ed25519_verify.txt", "Ed25519 verification: where verifiers' rules part",
                "case, public key, message, signature, this library's verdict, then each oracle's verdict in the "
                "order: " + cols,
                ["Each oracle's verdicts were checked against its stated rule (ED_RULES in the generator):",
                 "  ours: cofactorless, S < L, A canonical (RFC 8032 5.1.3), R' = [S]B - [k]A compared with R's",
                 "        bytes; small-order A and R accepted when the equation holds (Wycheproof 'acceptable')",
                 "  openssl: ours, except that A is decoded without RFC 8032 5.1.3's canonical checks: y >= p is",
                 "        reduced and 'negative zero' (x = 0, sign bit set) accepted, which this library refuses",
                 "  pynacl (libsodium): the same, and small-order A or R refused",
                 "  dalek: cofactorless, R compared as bytes, A's y may be non-canonical",
                 "  dalek_strict (verify_strict): dalek's, and small-order A or R refused",
                 "  noble_ed25519 (zip215: false): cofactored, canonical A and R, small-order A refused",
                 "  noble_zip215 (ZIP-215, noble's default): cofactored, non-canonical A and R accepted",
                 "This library keeps RFC 8032's cofactorless equation, as OpenSSL, Go and libsodium do."])
    qs = [{"pub": p, "m": m, "sig": s} for _, p, m, s in vcases]
    answers = pool.ask("ed25519_verify", qs, libs)
    for (why, pub, m, sig), ans in zip(vcases, answers):
        pb, mb, sb = bytes.fromhex(pub), bytes.fromhex(m), bytes.fromhex(sig)
        verdicts = []
        for lib in libs:
            got = int(bool(ans[lib].get("valid"))) if lib in ans else None
            want = ed_rule(ED_RULES[lib], pb, mb, sb)
            if got != want:
                fail(f.name, {"why": why, "pub": pub, "m": m, "sig": sig},
                     "%s answered %s, its stated rule gives %s" % (lib, got, want))
            verdicts.append(str(got))
        pool.count(ans)
        f.add([why.replace(" ", "_"), pub, m, sig, ed_rule(ED_RULES["ours"], pb, mb, sb)] + verdicts, libs)
    fx.append(f)


X25519_SPECIAL = [0, 1, 325606250916557431795983626356110631294008115727848805560023387167927233504,
                  39382357235489614581723060781553021112529911719440698176882885853963445705823,
                  EP - 1, EP, EP + 1, EP + 325606250916557431795983626356110631294008115727848805560023387167927233504,
                  EP + 39382357235489614581723060781553021112529911719440698176882885853963445705823,
                  2 * EP - 1, 2 * EP, 2 * EP + 1, 2**255 - 1, 2**255, 2**256 - 1, 9]


def gen_x25519(pool, fx):
    rng = random.Random("x25519 v1")
    cases = []
    for i in range(700):
        k = rand_bytes(rng, 32)
        if i < len(X25519_SPECIAL) * 4:
            u = (X25519_SPECIAL[i // 4] % 2**256).to_bytes(32, "little")
        else:
            u = rand_bytes(rng, 32)
        cases.append({"k": hx(k), "u": hx(u)})
    f = Fixture("x25519.txt", "X25519 (RFC 7748): scalar, u-coordinate, shared secret",
                "scalar (clamped by the function), u-coordinate (bit 255 ignored, u at or above p reduced), "
                "result ('-': refused, the all-zero result of a small-order u)")
    answers = pool.ask("x25519", cases)
    for case, ans in zip(cases, answers):
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: refused_or(a, "out"))
        if libs:
            f.add([case["k"], case["u"], v[0] if v else None], libs)
    fx.append(f)


# ---------------------------------------------------------------------------------------------------------------
# BIP-39, BIP-32, SLIP-10

def wordlist():
    path = os.path.join(ROOT, "include", "snicholls", "crypto", "bip39", "wordlist.hpp")
    import re
    words = re.findall(r'"([a-z]+)"', open(path).read())
    words = [w for w in words if len(w) >= 3][:2048]
    assert len(words) == 2048, len(words)
    return words


def canonical_mnemonic(text, words):
    """This library's rule (bip39/mnemonic.hpp, CLAUDE.md rule 8): lower-case list words, single spaces, 12 to
    24 words in threes, the checksum right."""
    parts = text.split(" ")
    if not (12 <= len(parts) <= 24 and len(parts) % 3 == 0):
        return None
    idx = {w: i for i, w in enumerate(words)}
    if any(p not in idx for p in parts):
        return None
    bits = "".join("{:011b}".format(idx[p]) for p in parts)
    nent = len(bits) * 32 // 33
    ent = int(bits[:nent], 2).to_bytes(nent // 8, "big")
    cs = "{:08b}".format(hashlib.sha256(ent).digest()[0])[:len(bits) - nent]
    return hx(ent) if cs == bits[nent:] else None


def gen_bip39(pool, fx):
    rng = random.Random("bip39 v1")
    printable = [chr(c) for c in range(0x20, 0x7f)]
    cases = []
    for i in range(300):
        n = [16, 20, 24, 28, 32][i % 5]
        e = bytes(n) if i < 5 else (b"\xff" * n if i < 10 else rand_bytes(rng, n))
        pw = "" if i % 7 == 0 else "".join(rng.choice(printable) for _ in range(rng.randrange(1, 24)))
        cases.append({"e": hx(e), "pass": pw})
    f = Fixture("bip39.txt", "BIP-39: entropy to mnemonic, and the seed with a passphrase",
                "entropy, mnemonic (its words joined by '+'), passphrase (hex of its ASCII bytes; '-': empty), "
                "seed (PBKDF2-HMAC-SHA512, 2048 iterations)")
    words_ans = pool.ask("bip39_from_entropy", [{"e": c["e"]} for c in cases])
    phrases = []
    for case, ans in zip(cases, words_ans):
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: refused_or(a, "words"))
        phrases.append((v[0] if v else None, libs))
    seed_cases = [{"words": p, "pass": c["pass"]} for c, (p, _) in zip(cases, phrases)]
    seed_ans = pool.ask("bip39_seed", seed_cases)
    back_ans = pool.ask("bip39_to_entropy", [{"words": p} for p, _ in phrases])
    for case, (phrase, libs), sa, ba in zip(cases, phrases, seed_ans, back_ans):
        sv, sl = consensus(pool, f.name, dict(case, words=phrase), sa, lambda lib, a: a["seed"])
        bv, bl = consensus(pool, f.name + " back", {"words": phrase}, ba, lambda lib, a: refused_or(a, "e"))
        if bv and bv[0] != case["e"]:
            fail(f.name, case, "the words do not give the entropy back")
        if libs and sl:
            f.add([case["e"], phrase.replace(" ", "+"), hx(case["pass"].encode()), sv], set(libs) | set(sl) | set(bl))
    fx.append(f)

    # Text that is not a canonical mnemonic. The oracles normalise differently (case, whitespace); this library
    # refuses anything but the canonical text, and every oracle must at least refuse what fails the checksum
    words = wordlist()
    bad = []
    for phrase, _ in phrases[:60]:
        w = phrase.split(" ")
        bad.append(("canonical", phrase))
        bad.append(("checksum", " ".join(w[:-1] + [words[(words.index(w[-1]) + 1) % 2048]])))
        bad.append(("unknown word", " ".join(w[:-1] + ["zzzz"])))
        bad.append(("one word fewer", " ".join(w[:-1])))
        bad.append(("one word more", " ".join(w + ["abandon"])))
        bad.append(("upper case", phrase.upper()))
        bad.append(("double space", phrase.replace(" ", "  ", 1)))
        bad.append(("trailing space", phrase + " "))
        bad.append(("leading space", " " + phrase))
        bad.append(("tab", phrase.replace(" ", "\t", 1)))
    libs = pool.libs_for("bip39_to_entropy")
    f = Fixture("bip39_text.txt", "BIP-39 mnemonic text: canonical or not",
                "case, text (hex of its bytes), this library's entropy ('-': refused), then each oracle's in the "
                "order: " + " ".join(libs),
                ["This library reads canonical text only: lower-case list words separated by single spaces",
                 "(CLAUDE.md rule 8: never repaired). The oracles normalise first: python-mnemonic, ethers and",
                 "@scure/bip39 split on whitespace and lower-case or NFKD-normalise; bip39_rs splits on whitespace.",
                 "Every oracle agrees with this library wherever the text is canonical, and every one refuses a",
                 "bad checksum, an unknown word and a wrong word count: those are the rows compared."])
    answers = pool.ask("bip39_to_entropy", [{"words": t} for _, t in bad], libs)
    for (why, text), ans in zip(bad, answers):
        ours = canonical_mnemonic(text, words)
        got = {lib: (a.get("e") if "error" not in a else None) for lib, a in ans.items()}
        if why in ("canonical", "checksum", "unknown word", "one word fewer", "one word more"):
            for lib, g in got.items():
                if g != ours:
                    fail(f.name, {"why": why, "text": text}, "%s gave %s, this library's rule %s" % (lib, g, ours))
        else:
            # Normalising oracles may read it; whatever they read must be the entropy of the canonical text
            canon = canonical_mnemonic(" ".join(text.lower().split()), words)
            for lib, g in got.items():
                if g is not None and g != canon:
                    fail(f.name, {"why": why, "text": text}, "%s read %s, the normalised text gives %s" % (lib, g, canon))
            if ours is not None:
                fail(f.name, {"why": why, "text": text}, "the model accepts non-canonical text")
        pool.count(ans)
        f.add([why.replace(" ", "_"), hx(text.encode()), ours] + [got.get(l) or "-" for l in libs], sorted(ans))
    fx.append(f)


def path_text(indices):
    return "m" + "".join("/%d%s" % (i & 0x7fffffff, "'" if i & 0x80000000 else "") for i in indices)


H = 0x80000000


def gen_hd(pool, fx):
    rng = random.Random("bip32 v1")
    cases = []
    for i in range(400):
        seed = hx(rand_bytes(rng, rng.choice([16, 32, 64, rng.randrange(16, 65)])))
        kind = i % 6
        coin = rng.choice([0, 1, 60, 501, rng.randrange(2**31)])
        acct = rng.choice([0, 1, rng.randrange(2**31)])
        change, idx = rng.randrange(2), rng.choice([0, 1, rng.randrange(2**31), 2**31 - 1])
        if kind < 4:
            purpose = [44, 49, 84, 86][kind]
            path = [purpose | H, coin | H, acct | H, change, idx]
        elif kind == 4:
            path = [rng.randrange(2**32) for _ in range(rng.randrange(0, 9))]
        else:
            path = [rng.choice([0, H, 2**31 - 1, 2**32 - 1, rng.randrange(2**32)]) for _ in range(rng.randrange(1, 5))]
        cases.append({"seed": seed, "path": path_text(path)})
    f = Fixture("bip32.txt", "BIP-32 derivation from a seed along BIP-44, 49, 84 and 86 paths and random ones",
                "seed, path, xprv, xpub (mainnet versions)",
                ["The bip32 crate takes seeds of 16, 32 or 64 bytes only (BIP-32 allows 16 to 64): it is checked",
                 "to refuse the others and not counted on them. bitcoinjs' derivePath needs at least one step: it",
                 "is not counted on the path 'm'."])
    answers = pool.ask("bip32", cases)
    for case, ans in zip(cases, answers):
        if case["path"] == "m" and "error" in ans.get("bitcoinjs", {}):
            ans.pop("bitcoinjs")   # its rule: derivePath needs at least one step
        if len(case["seed"]) // 2 not in (16, 32, 64) and "bip32_rs" in ans:
            # the bip32 crate's rule: a seed of 16, 32 or 64 bytes only (BIP-32 allows any length from 16 to 64)
            if "error" not in ans.pop("bip32_rs"):
                fail(f.name, case, "bip32_rs derived from a seed its rule refuses")
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: refused_or(a, "xprv", "xpub"))
        if libs:
            f.add([case["seed"], case["path"]] + (v or [None, None]), libs)
    fx.append(f)

    rng = random.Random("slip10 v1")
    cases = []
    for i in range(300):
        seed = hx(rand_bytes(rng, rng.choice([16, 32, 64, rng.randrange(16, 65)])))
        if i % 3 == 0:
            path = [44 | H, 501 | H, rng.randrange(2**31) | H, 0 | H]   # Solana's BIP-44 path
        else:
            path = [rng.randrange(2**31) | H for _ in range(rng.randrange(0, 7))]
        cases.append({"seed": seed, "path": path_text(path)})
    f = Fixture("slip10_ed25519.txt", "SLIP-10 Ed25519 derivation (hardened only)",
                "seed, path, private key, chain code, public key",
                ["slip10_rs gives the private key and public key only; its chain code is not compared.",
                 "ed25519-hd-key derives along a path of at least one step; it is not counted on the path 'm'."])
    answers = pool.ask("slip10_ed25519", cases)
    for case, ans in zip(cases, answers):
        if case["path"] == "m" and "error" in ans.get("ed25519_hd_key", {}):
            ans.pop("ed25519_hd_key")   # its rule: derivePath needs at least one step; the master key is not offered
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: refused_or(a, "key", "pub"))
        chains = {l: a for l, a in ans.items() if "chain" in a or "error" in a}
        cv, _ = consensus(pool, f.name + " chain", case, chains, lambda lib, a: refused_or(a, "chain"))
        if libs:
            f.add([case["seed"], case["path"]] + ([v[0], cv[0], v[1]] if v and cv else [None, None, None]), libs)
    fx.append(f)


# ---------------------------------------------------------------------------------------------------------------
# base58check, bech32 and segwit

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def gen_addresses(pool, fx):
    rng = random.Random("base58check v1")
    payloads = []
    for i in range(500):
        n = rng.choice([0, 1, 21, 33, 78, rng.randrange(0, 90)])
        p = rand_bytes(rng, n)
        if i % 5 == 0 and n:
            p = bytes(rng.randrange(1, min(n, 6) + 1)) + p[:max(0, n - 6)]   # leading zero bytes
        payloads.append(hx(p))
    f = Fixture("base58check.txt", "base58check (Bitcoin's alphabet): payload and text, and text that must be refused",
                "ok|refused, payload (hex; '-' when empty or refused), text ('-' when empty)",
                ["Rows 'ok <payload> <text>' encode and decode both ways; rows 'refused - <text>' must not decode."])
    enc = pool.ask("base58check_encode", [{"p": p} for p in payloads])
    texts = []
    for p, ans in zip(payloads, enc):
        v, libs = consensus(pool, f.name, {"p": p}, ans, lambda lib, a: a["t"])
        if libs:
            f.add(["ok", p, v], libs)
            texts.append(v)
    bad = []
    for t in texts[:200]:
        i = rng.randrange(len(t))
        c = B58[(B58.index(t[i]) + 1 + rng.randrange(57)) % 58]
        bad.append(t[:i] + c + t[i + 1:])                       # one symbol changed
        bad.append(t[:-1])                                      # truncated
    bad += ["0", "O", "I", "l", texts[3] + "0", "1" + texts[5][1:] + "!", ""]
    dec = pool.ask("base58check_decode", [{"t": t} for t in bad])
    for t, ans in zip(bad, dec):
        v, libs = consensus(pool, f.name, {"t": t}, ans, lambda lib, a: refused_or(a, "p"))
        if libs:
            f.add(["ok" if v else "refused", v[0] if v else None, t if t else None], libs)
    fx.append(f)

    rng = random.Random("segwit v1")
    cases = []
    for i in range(500):
        ver = [0, 0, 1, rng.randrange(1, 17)][i % 4]
        if ver == 0:
            n = rng.choice([20, 32])
        elif ver == 1 and i % 8 == 2:
            n = 32
        else:
            n = rng.randrange(2, 41)
        cases.append({"hrp": rng.choice(["bc", "tb", "bcrt"]), "ver": ver, "prog": hx(rand_bytes(rng, n))})
    f = Fixture("segwit.txt", "Segwit addresses (BIP-173 bech32 for v0, BIP-350 bech32m for v1 to v16)",
                "ok|refused, hrp, witness version, program, address",
                ["bitcoinjs-lib's fromBech32 does not check the witness version range or the program length; it is",
                 "checked to decode those rows exactly as bech32 says and not counted on them."])
    answers = pool.ask("segwit_encode", cases)
    addrs = []
    for case, ans in zip(cases, answers):
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: a["addr"])
        if libs:
            f.add(["ok", case["hrp"], case["ver"], case["prog"], v], libs)
            addrs.append((case["hrp"], v))
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    bad = []
    for hrp, a in addrs[:200]:
        i = rng.randrange(len(hrp) + 1, len(a))
        bad.append((hrp, a[:i] + charset[(charset.index(a[i]) + 1 + rng.randrange(31)) % 32] + a[i + 1:]))
        bad.append((hrp, a[:i] + a[i].upper() + a[i + 1:] if a[i].isalpha() else a[:-1]))   # mixed case
        bad.append((hrp, a.upper()))                                                        # all upper: valid
        bad.append(("bc" if hrp != "bc" else "tb", a))                                     # another network
    # v0 in bech32m, v1+ in bech32, lengths out of range: built by the reference's own bech32 encoder
    sys.path.insert(0, os.path.join(HOME, "python-ref"))
    import segwit_addr as ref
    for _ in range(40):
        prog = list(rand_bytes(rng, 20))
        bad.append(("bc", ref.bech32_encode("bc", [0] + ref.convertbits(prog, 8, 5), ref.Encoding.BECH32M)))
        prog = list(rand_bytes(rng, 32))
        bad.append(("bc", ref.bech32_encode("bc", [1] + ref.convertbits(prog, 8, 5), ref.Encoding.BECH32)))
        prog = list(rand_bytes(rng, rng.choice([1, 41, 21, 19])))
        bad.append(("bc", ref.bech32_encode("bc", [rng.randrange(1, 17)] + ref.convertbits(prog, 8, 5),
                                            ref.Encoding.BECH32M)))
        bad.append(("bc", ref.bech32_encode("bc", [17] + ref.convertbits(list(rand_bytes(rng, 32)), 8, 5),
                                            ref.Encoding.BECH32M)))
    answers = pool.ask("segwit_decode", [{"hrp": h, "addr": a} for h, a in bad])
    for (hrp, a), ans in zip(bad, answers):
        bj = ans.get("bitcoinjs")
        if bj and "error" not in bj and all("error" in x for l, x in ans.items() if l != "bitcoinjs"):
            # bitcoinjs-lib's rule: fromBech32 checks the checksum and its variant for the version, not that the
            # version is at most 16 or the program 2 to 40 bytes (20 or 32 for v0); those rows are not counted
            hrp_, data, spec = ref.bech32_decode(a)
            prog = ref.convertbits(data[1:], 5, 8, False) if data else None
            ok_lax = hrp_ == hrp and data and prog is not None and bj["ver"] == data[0] and bj["prog"] == hx(prog) \
                and spec == (ref.Encoding.BECH32 if data[0] == 0 else ref.Encoding.BECH32M) \
                and (data[0] > 16 or not 2 <= len(prog) <= 40 or (data[0] == 0 and len(prog) not in (20, 32)))
            if not ok_lax:
                fail(f.name, {"hrp": hrp, "addr": a}, "bitcoinjs decoded beyond its stated rule: %s" % bj)
            ans.pop("bitcoinjs")
        v, libs = consensus(pool, f.name, {"hrp": hrp, "addr": a}, ans, lambda lib, x: refused_or(x, "ver", "prog"))
        if libs:
            f.add(["ok" if v else "refused", hrp, v[0] if v else None, v[1] if v else None, a], libs)
    fx.append(f)


# ---------------------------------------------------------------------------------------------------------------
# RSA: test keys made here from fixed seeds (they sign nothing but these fixtures), signatures and verdicts from the
# oracles

def is_probable_prime(n, rng):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(40):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa_test_key(rng, bits, e=65537):
    """A deterministic RSA key of exactly `bits` bits: two primes of bits/2 with their top two bits set."""
    while True:
        ps = []
        while len(ps) < 2:
            c = rng.getrandbits(bits // 2) | (3 << (bits // 2 - 2)) | 1
            if (c - 1) % e and is_probable_prime(c, rng):
                ps.append(c)
        p, q = ps
        n = p * q
        if p != q and n.bit_length() == bits:
            d = pow(e, -1, (p - 1) * (q - 1))
            return {"n": n, "e": e, "d": d, "p": p, "q": q}


def der_len(n):
    return bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else bytes([0x82, n >> 8, n & 0xff]))


def der(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def der_uint(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return der(0x02, (b"\x00" + b) if b[0] & 0x80 else b)


def rsa_spki(k):
    rsapub = der(0x30, der_uint(k["n"]) + der_uint(k["e"]))
    alg = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
    return der(0x30, alg + der(0x03, b"\x00" + rsapub)), rsapub


SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_raw_sign(k, em):
    """s = EM^d mod n: an encoded message signed as it is, to make signatures over malformed encodings."""
    size = (k["n"].bit_length() + 7) // 8
    return pow(int.from_bytes(em, "big"), k["d"], k["n"]).to_bytes(size, "big")


def pss_encode(m_hash, em_bits, salt):
    em_len = (em_bits + 7) // 8
    h = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - len(salt) - 32 - 2) + b"\x01" + salt
    mask, counter = b"", 0
    while len(mask) < len(db):
        mask += hashlib.sha256(h + counter.to_bytes(4, "big")).digest()
        counter += 1
    masked = bytearray(x ^ y for x, y in zip(db, mask))
    masked[0] &= 0xff >> (8 * em_len - em_bits)
    return bytes(masked) + h + b"\xbc"


def gen_rsa(pool, fx):
    rng = random.Random("rsa keys v1")
    keys = [rsa_test_key(rng, bits) for bits in (2048, 2048, 3072, 3072, 4096, 4096)]
    hexn = lambda v: "%x" % v
    evenhex = lambda v: hx(v.to_bytes((v.bit_length() + 7) // 8, "big"))
    pub = lambda k: {"n": hexn(k["n"]), "e": hexn(k["e"])}
    priv = lambda k: dict(pub(k), d=hexn(k["d"]), p=hexn(k["p"]), q=hexn(k["q"]))

    # PKCS#1 v1.5 signatures: deterministic, so byte for byte across the oracles
    cases = []
    for k in keys:
        for _ in range(40):
            cases.append((k, hx(rand_bytes(rng, rng.choice([0, 1, 32, 100, 1000])))))
    f = Fixture("rsa_pkcs1_sign.txt", "RSA PKCS#1 v1.5 signatures with SHA-256 (RS256), from deterministic test keys",
                "SubjectPublicKeyInfo (DER), message, signature",
                ["The keys are made by the generator from a fixed seed and sign nothing but these fixtures."])
    answers = pool.ask("rsa_sign_pkcs1", [dict(priv(k), m=m) for k, m in cases])
    signed = []
    for (k, m), ans in zip(cases, answers):
        v, libs = consensus(pool, f.name, {"n": hexn(k["n"]), "m": m}, ans, lambda lib, a: a["sig"])
        if libs:
            f.add([hx(rsa_spki(k)[0]), m or None, v], libs)
            signed.append((k, m, v))
    fx.append(f)

    # Verification: real signatures and their mutations, and encodings that are not EMSA-PKCS1-v1_5, signed raw
    vcases = []
    for i, (k, m, sig) in enumerate(signed):
        size = len(sig) // 2
        mh = hashlib.sha256(bytes.fromhex(m)).digest()
        vcases.append(("valid", k, m, sig))
        b = bytearray(bytes.fromhex(sig))
        b[rng.randrange(size)] ^= 1 << rng.randrange(8)
        vcases.append(("bit flipped", k, m, hx(b)))
        vcases.append(("another message", k, hx(bytes.fromhex(m) + b"\x00"), sig))
        if i % 40 < 4:
            n_bytes = k["n"].to_bytes(size, "big")
            vcases.append(("s = n", k, m, hx(n_bytes)))
            vcases.append(("one byte short", k, m, sig[2:]))
            vcases.append(("one byte long", k, m, "00" + sig))
            t = SHA256_DIGEST_INFO + mh
            ps = size - len(t) - 3
            crafted = {
                "no NULL": b"\x00\x01" + b"\xff" * (ps + 2) + b"\x00" + bytes.fromhex("302f300b0609608648016503040201") + b"\x04\x20" + mh,
                "block type 2": b"\x00\x02" + b"\xff" * ps + b"\x00" + t,
                "a padding byte FE": b"\x00\x01" + b"\xff" * (ps // 2) + b"\xfe" + b"\xff" * (ps - ps // 2 - 1) + b"\x00" + t,
                "short padding, data after": b"\x00\x01" + b"\xff" * 8 + b"\x00" + t + b"\x00" * (ps - 8),
                "SHA-1 algorithm": b"\x00\x01" + b"\xff" * (ps + 1) + b"\x00" + bytes.fromhex("3021300906052b0e03021a05000414") + mh[:20] + b"\x00" * 0,
                "no zero separator": b"\x00\x01" + b"\xff" * (ps + 1) + t,
                "leading byte 01": b"\x01\x01" + b"\xff" * ps + b"\x00" + t,
            }
            for why, em in crafted.items():
                em = em[:size].ljust(size, b"\x00") if len(em) != size else em
                vcases.append((why, k, m, hx(rsa_raw_sign(k, em))))
    f = Fixture("rsa_pkcs1_verify.txt", "RSA PKCS#1 v1.5 verification with SHA-256: valid, mutated and malformed encodings",
                "case, n, e, message, signature, valid (1 or 0)",
                ["Malformed encodings are signed raw with the test key, so only the encoding is wrong; every oracle must",
                 "agree, and this library rebuilds the encoding and compares it whole."])
    answers = pool.ask("rsa_verify_pkcs1", [dict(pub(k), m=m, sig=sig) for _, k, m, sig in vcases])
    for (why, k, m, sig), ans in zip(vcases, answers):
        v, libs = consensus(pool, f.name, {"why": why, "n": hexn(k["n"])[:16], "sig": sig[:16]}, ans,
                            lambda lib, a: int(bool(a.get("valid"))))
        if libs:
            f.add([why.replace(" ", "_").replace(",", ""), evenhex(k["n"]), evenhex(k["e"]), m or None, sig, v], libs)
    fx.append(f)

    # PSS: encoded here with fixed salts (PSS signing is randomised), verified by every oracle
    pcases = []
    for k in keys:
        size = (k["n"].bit_length() + 7) // 8
        for j in range(20):
            salt_len = [32, 0, 20, 64][j % 4]
            m = rand_bytes(rng, rng.choice([0, 32, 200]))
            salt = rand_bytes(rng, salt_len)
            em = pss_encode(hashlib.sha256(m).digest(), k["n"].bit_length() - 1, salt)
            sig = rsa_raw_sign(k, em.rjust(size, b"\x00"))
            pcases.append(("valid", k, m, sig, salt_len))
            b = bytearray(sig)
            b[rng.randrange(size)] ^= 1 << rng.randrange(8)
            pcases.append(("bit flipped", k, m, bytes(b), salt_len))
            pcases.append(("another salt length", k, m, sig, 32 if salt_len != 32 else 20))
            pcases.append(("another message", k, m + b"\x00", sig, salt_len))
    f = Fixture("rsa_pss_verify.txt", "RSA PSS verification with SHA-256 and MGF1-SHA-256 (PS256 at salt length 32)",
                "case, n, e, message, signature, salt length, valid (1 or 0)",
                ["PSS signing is randomised, so the signatures are encoded here (RFC 8017 9.1.1) with fixed salts and",
                 "signed raw with the test key; every oracle must verify them alike."])
    answers = pool.ask("rsa_verify_pss", [dict(pub(k), m=hx(m), sig=hx(sig), salt=sl) for _, k, m, sig, sl in pcases])
    for (why, k, m, sig, sl), ans in zip(pcases, answers):
        v, libs = consensus(pool, f.name, {"why": why, "n": hexn(k["n"])[:16]}, ans, lambda lib, a: int(bool(a.get("valid"))))
        if libs:
            f.add([why.replace(" ", "_"), evenhex(k["n"]), evenhex(k["e"]), hx(m) or None, hx(sig), sl, v], libs)
    fx.append(f)

    # SubjectPublicKeyInfo: each oracle reads the generator's DER to the same n and e
    f = Fixture("rsa_spki.txt", "RSA SubjectPublicKeyInfo (DER) to n and e", "DER, n, e")
    spkis = [rsa_spki(k)[0] for k in keys]
    answers = pool.ask("rsa_parse_spki", [{"der": hx(d)} for d in spkis])
    for k, d, ans in zip(keys, spkis, answers):
        v, libs = consensus(pool, f.name, {"n": hexn(k["n"])[:16]}, ans, lambda lib, a: refused_or(a, "n", "e"))
        if libs:
            if v != [hexn(k["n"]), hexn(k["e"])]:
                fail(f.name, {"n": hexn(k["n"])[:16]}, "the oracles read another key")
            f.add([hx(d), evenhex(k["n"]), evenhex(k["e"])], libs)
    fx.append(f)


# ---------------------------------------------------------------------------------------------------------------
# P-256

P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def gen_p256(pool, fx):
    rng = random.Random("p256 v1")
    edges = [0, 1, 2, P256_N - 1, P256_N, P256_N + 1, 2**256 - 1]
    keys = [i32(k) for k in edges] + [hx(rand_bytes(rng, 32)) for _ in range(500)]
    f = Fixture("p256_keys.txt", "P-256 private keys to public keys (SEC1)",
                "private key, compressed, uncompressed ('-' '-': refused, 0 or at or above n)")
    answers = pool.ask("p256_pub", [{"sk": k} for k in keys])
    good = []
    for k, ans in zip(keys, answers):
        v, libs = consensus(pool, f.name, {"sk": k}, ans, lambda lib, a: refused_or(a, "c", "u"))
        if libs:
            f.add([k] + (v or [None, None]), libs)
            if v:
                good.append((k, v[0], v[1]))
    fx.append(f)

    # Signatures: RFC 6979 with SHA-256, s as computed (no low-S), byte for byte across OpenSSL, noble and p256
    cases = []
    for i, (k, c, u) in enumerate(good[:500]):
        m = rand_bytes(rng, rng.choice([0, 1, 32, 100]))
        cases.append({"sk": k, "m": hx(m), "h": hx(hashlib.sha256(m).digest())})
    f = Fixture("p256_sign.txt", "P-256 ECDSA signatures (ES256): RFC 6979 nonces with SHA-256, s as computed",
                "private key, message, SHA-256 of the message, r, s")
    answers = pool.ask("p256_sign", [{"sk": c["sk"], "h": c["h"]} for c in cases])
    signed = []
    pub_of = {k: (c, u) for k, c, u in good}
    for case, ans in zip(cases, answers):
        v, libs = consensus(pool, f.name, case, ans, lambda lib, a: [a["r"], a["s"]])
        if libs:
            f.add([case["sk"], case["m"] or None, case["h"], v[0], v[1]], libs)
            signed.append((case, v[0], v[1]))
    fx.append(f)

    # Verification, every oracle (Node's crypto hashes the message itself)
    vcases = []
    for i, (case, r, s_) in enumerate(signed[:400]):
        c, u = pub_of[case["sk"]]
        pub = u if i % 2 else c
        ri, si = int(r, 16), int(s_, 16)
        def add(why, pub_, m, h, rr, ss):
            vcases.append({"why": why, "pub": pub_, "m": m, "h": h, "sig": i32(rr % 2**256) + i32(ss % 2**256)})
        add("valid", pub, case["m"], case["h"], ri, si)
        add("n - s", pub, case["m"], case["h"], ri, P256_N - si)   # either s verifies
        add("r bit flipped", pub, case["m"], case["h"], ri ^ (1 << rng.randrange(256)), si)
        add("s bit flipped", pub, case["m"], case["h"], ri, si ^ (1 << rng.randrange(256)))
        m2 = case["m"] + "00"
        add("another message", pub, m2, hx(hashlib.sha256(bytes.fromhex(m2)).digest()), ri, si)
        add("another key", good[(i + 1) % len(good)][2], case["m"], case["h"], ri, si)
        if i < 20:
            for rr, ss, why in ((0, si, "r = 0"), (ri, 0, "s = 0"), (P256_N, si, "r = n"), (ri, P256_N, "s = n"),
                                (ri + P256_N, si, "r + n"), (ri, 2**256 - 1, "s = 2^256 - 1")):
                add(why, pub, case["m"], case["h"], rr, ss)
    f = Fixture("p256_verify.txt", "P-256 ECDSA verification (either s accepted)",
                "case, public key (SEC1), message, SHA-256, r || s, valid (1 or 0)",
                ["Node's crypto verifies the message (it hashes it) with uncompressed keys only; the others verify the hash."])
    answers = pool.ask("p256_verify", [{k: c[k] for k in ("pub", "m", "h", "sig")} for c in vcases])
    for case, ans in zip(vcases, answers):
        v, libs = consensus(pool, f.name, {"why": case["why"], "sig": case["sig"][:16]}, ans,
                            lambda lib, a: int(bool(a.get("valid"))))
        if libs:
            f.add([case["why"].replace(" ", "_"), case["pub"], case["m"] or None, case["h"], case["sig"], v], libs)
    fx.append(f)

    # SEC1 parsing
    pcases = []
    for k, c, u in good[:200]:
        x, y = int(u[2:66], 16), int(u[66:], 16)
        pcases += [c, u, "04" + i32(x) + i32((y + 1) % P256_P), "%02x" % (6 + (y & 1)) + u[2:]]
    for _ in range(100):
        pcases.append(rng.choice(["02", "03"]) + hx(rand_bytes(rng, 32)))
    for x in (P256_P, P256_P + 1, 2**256 - 1, 0):
        pcases += ["02" + i32(x), "03" + i32(x)]
    pcases += ["00", "04"]
    f = Fixture("p256_sec1.txt", "P-256 SEC1 public-key parsing", "encoding, compressed form ('-': refused)",
                ["Every oracle and this library refuse the hybrid form (0x06, 0x07), points off the curve and x or y",
                 "at or above p."])
    answers = pool.ask("p256_pub_parse", [{"pub": c} for c in pcases])
    for c, ans in zip(pcases, answers):
        v, libs = consensus(pool, f.name, {"pub": c}, ans, lambda lib, a: refused_or(a, "c"))
        if libs:
            f.add([c, v[0] if v else None], libs)
    fx.append(f)


# ---------------------------------------------------------------------------------------------------------------

def generate():
    pool = Pool()
    fx = []
    try:
        good, sigs, _ = gen_secp256k1(pool, fx)
        gen_secp256k1_parse(pool, fx, good)
        gen_ecdsa_verify(pool, fx, good, sigs)
        gen_ecdsa_der(pool, fx, good, sigs)
        gen_schnorr(pool, fx, good)
        gen_ed25519(pool, fx)
        gen_x25519(pool, fx)
        gen_bip39(pool, fx)
        gen_hd(pool, fx)
        gen_addresses(pool, fx)
        gen_rsa(pool, fx)
        gen_p256(pool, fx)
        files = {f.name: f.text(pool) for f in fx}
        manifest = pool.manifest()
        manifest["fixtures"] = {f.name: {"cases": len(f.rows), "oracles": sorted(f.libs)} for f in fx}
        files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    finally:
        pool.close()
    return files


def in_image():
    return os.path.isdir(os.path.join(HOME, "venv")) and os.path.isdir(os.path.join(HOME, "node", "node_modules"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="compare with tests/fixtures/oracles, write nothing")
    args = ap.parse_args()
    if not in_image():
        image = subprocess.run([os.path.join(ROOT, "scripts", "oracles", "image.sh")], check=True,
                               capture_output=True, text=True).stdout.strip()
        mount = "%s:/src%s" % (ROOT, ":ro" if args.check else "")
        argv = ["docker", "run", "--rm", "-v", mount, "-w", "/src", image,
                "python3", "-I", "scripts/generate_oracle_fixtures.py"] + (["--check"] if args.check else [])
        return subprocess.run(argv).returncode
    files = generate()
    if FAILURES:
        by = {}
        for e in FAILURES:
            by.setdefault(e.split(":")[0], []).append(e)
        for cat, es in sorted(by.items()):
            print("generate_oracle_fixtures: %s: %d cases" % (cat, len(es)), file=sys.stderr)
            for e in es[:3]:
                print("    " + e, file=sys.stderr)
        print("generate_oracle_fixtures: %d cases match no stated rule - nothing written" % len(FAILURES),
              file=sys.stderr)
        return 1
    if args.check:
        stale = []
        for name, text in files.items():
            path = os.path.join(OUT, name)
            if not os.path.isfile(path) or open(path).read() != text:
                stale.append(name)
        extra = set(os.listdir(OUT)) - set(files) - {"README.md"} if os.path.isdir(OUT) else set()
        if stale or extra:
            print("generate_oracle_fixtures: out of date: %s" % ", ".join(sorted(stale + list(extra))),
                  file=sys.stderr)
            return 1
        print("generate_oracle_fixtures: %d fixtures up to date" % len(files))
        return 0
    os.makedirs(OUT, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(OUT, name), "w") as f:
            f.write(text)
    total = sum(v["cases"] for v in json.loads(files["manifest.json"])["fixtures"].values())
    print("generate_oracle_fixtures: %d fixtures, %d cases written to tests/fixtures/oracles" % (len(files) - 1, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())

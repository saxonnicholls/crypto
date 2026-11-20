#!/usr/bin/env python3
#
#  check_public.py
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  The repository may become public, so no tracked file and no commit message may name a private repository,
#  product or machine, or an absolute home path. The names are kept here only as SHA-256 hashes of their
#  lower-case form, so this script names nothing itself; every word of every tracked file (and of every commit
#  message, with --commits) is hashed and compared.
#
#      python3 scripts/check_public.py              tracked files
#      python3 scripts/check_public.py --commits    tracked files and every commit message
#
#  Exit status is 0 when nothing private is found and 1 otherwise.
#

import hashlib
import re
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PRIVATE = {
    "04b6dc2f8660b4fd8f2433885a3de66fb98e0b730978e2bd4300f2bf0c1cc0e2",
    "294aa8d75483b8331e3ba6a7f24aea15202747f36de65197e7bc6194880b2558",
    "43d40a651fa47cc6da5c9e622cbae28724fdc31db2623e2610fd8b918e36d416",
    "4bb3e04b340af8d6edc944da27b08c12d60ff0010fcdcc4ab780298a8a105709",
    "606173e3b615464b2620a9943b3bf43ab046e07e5562a04c6d7b1dc5bcdeab3c",
    "849844602725f0a46da32693a3462e3f478bc4c2f8e42e474a1fbd78dbae5a2a",
    "8a2add3cd99418606990fc038c1ae438c83e17139b1762f98f65b77566d24c6f",
    "9cfd75643d6d530fb29087cad767ddf83e2b983c32f1ff348a995d831b569845",
    "cb445bac7138fcf9efab0104d3a47bf47c67db9caa0f2252f523d356a517bea1",
    "cb6be63c971ccee4f4e6b0bd888b663251ddb114f89643d942e1045b35c90dd3",
    "d2c0892b5f9d079fd7c592d6507b03cd275b5c0eed3c814c2b0df78028b57f5c",
    "d9a2372bae19dfe58d4343232f3c49717dc3ed9c27c35a41314bc269ccc2cd2f",
    "dd7a1ae1c9db6ac1f4ee7f505edbe86e99b6f75a090343d4bf6f8cf2e347dda4",
    "f6c6d7941efab13ace3ebf7eedadbf3743431dc17b93fbf6cad73f8cf3a9e57e",
}

WORD = re.compile(r"[A-Za-z0-9_\-]+")
HOME = re.compile(r"/(Users|home)/[A-Za-z]")


def findings(text, where):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if HOME.search(line):
            out.append("%s:%d: an absolute home path" % (where, n))
        for w in WORD.findall(line):
            for part in {w, w.strip("-_")} | set(w.split("-")) | set(w.split("_")):
                if part and hashlib.sha256(part.lower().encode()).hexdigest() in PRIVATE:
                    out.append("%s:%d: a private name" % (where, n))
    return out


def main():
    errors = []
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    for f in files:
        path = os.path.join(ROOT, f)
        if not os.path.isfile(path):
            continue   # a submodule
        try:
            text = open(path, encoding="utf-8").read()
        except UnicodeDecodeError:
            continue
        errors += findings(text, f)
    if "--commits" in sys.argv[1:]:
        log = subprocess.run(["git", "log", "--format=%H%n%B%x00"], cwd=ROOT, capture_output=True, text=True).stdout
        for entry in log.split("\0"):
            entry = entry.strip()
            if entry:
                sha, _, msg = entry.partition("\n")
                errors += findings(msg, "commit " + sha[:12])
    if errors:
        for e in sorted(set(errors)):
            print("check_public: " + e, file=sys.stderr)
        print("check_public: FAILED - nothing private in a repository that may become public", file=sys.stderr)
        return 1
    print("public check: %d tracked files, nothing private" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
#
#  check_version.py
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  The library's version is written down three times: as macros in
#  include/snicholls/crypto/version.hpp, as project(... VERSION) in
#  CMakeLists.txt, and as the git tag on a release. Those are three copies of
#  one fact, and the failure mode is not that they disagree loudly - it is that
#  a release goes out where find_package() reports one number, the header
#  reports another, and nobody notices until a consumer's version check
#  silently does the wrong thing. With the diamond rules depending on this
#  number, that would be a quiet way to defeat them.
#
#  So they are compared on every CI job. It is a static property of the tree,
#  and there is no reason to learn about it from a release later.
#
#      python3 scripts/check_version.py                 # header vs CMake
#      python3 scripts/check_version.py --tag v0.5.0    # ... and vs a tag
#
#  Exit status is 0 when they agree and 1 when they do not.
#

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER = os.path.join(ROOT, "include", "snicholls", "crypto", "version.hpp")
CMAKE = os.path.join(ROOT, "CMakeLists.txt")


def header_version():
    src = open(HEADER, encoding="utf-8").read()
    parts = []
    for field in ("MAJOR", "MINOR", "PATCH"):
        m = re.search(r"^#define\s+SNICHOLLS_CRYPTO_VERSION_%s\s+(\d+)\s*$" % field, src, re.M)
        if not m:
            raise SystemExit("check_version: SNICHOLLS_CRYPTO_VERSION_%s not found in %s"
                             % (field, os.path.relpath(HEADER, ROOT)))
        parts.append(m.group(1))
    return ".".join(parts)


def block_version():
    """The two-versions check before the guard: its literals and its #error text, each must be the version."""
    src = open(HEADER, encoding="utf-8").read()
    guard = src.find("#ifndef snicholls_crypto_version_hpp")
    m = re.search(r"#if defined\(SNICHOLLS_CRYPTO_VERSION_MAJOR\).*?VERSION_MAJOR != (\d+) \|\| SNICHOLLS_CRYPTO_VERSION_MINOR != "
                  r"(\d+) \|\| SNICHOLLS_CRYPTO_VERSION_PATCH != (\d+)\)\s*#error \"[^\"]*: (\d+\.\d+\.\d+) here", src, re.S)
    if not m or guard < 0 or m.start() > guard:
        raise SystemExit("check_version: the two-versions check is missing before the guard in %s" % os.path.relpath(HEADER, ROOT))
    return ".".join(m.groups()[:3]), m.group(4)


def cmake_version():
    src = open(CMAKE, encoding="utf-8").read()
    # The VERSION belonging to project(), not to cmake_minimum_required()
    m = re.search(r"project\s*\(\s*snicholls_crypto\s+VERSION\s+(\d+\.\d+\.\d+)", src, re.S)
    if not m:
        raise SystemExit("check_version: project(snicholls_crypto VERSION x.y.z) not found in CMakeLists.txt")
    return m.group(1)


def main():
    ap = argparse.ArgumentParser(description="Check the version is the same everywhere")
    ap.add_argument("--tag", default=os.environ.get("RELEASE_TAG"),
                    help="a git tag to check too, with or without a leading 'v'")
    args = ap.parse_args()

    hdr = header_version()
    cml = cmake_version()

    ok = True
    print("  include/snicholls/crypto/version.hpp   %s" % hdr)
    print("  CMakeLists.txt                       %s" % cml)
    if hdr != cml:
        print("check_version: header and CMakeLists disagree", file=sys.stderr)
        ok = False
    literals, text = block_version()
    print("  version.hpp two-versions check      %s (%s in its #error)" % (literals, text))
    if literals != hdr or text != hdr:
        print("check_version: the two-versions check does not match the version", file=sys.stderr)
        ok = False

    if args.tag:
        tag = args.tag.lstrip("v")
        print("  git tag                              %s" % args.tag)
        if tag != hdr:
            print("check_version: tag %s does not match version %s" % (args.tag, hdr), file=sys.stderr)
            ok = False

    if not ok:
        print("check_version: FAILED - one release, one number", file=sys.stderr)
        return 1
    print("version check: consistent (%s)" % hdr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

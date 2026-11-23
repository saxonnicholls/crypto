#!/usr/bin/env bash
#
#  lock.sh
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Regenerates the oracles' lock files after a version in requirements.in, package.json or Cargo.toml changes:
#  python/requirements.txt (every distribution's SHA-256), node/package-lock.json and rust/Cargo.lock. Each is
#  resolved inside the oracle image's base, with the image's own Python, Node and Rust, so the locks match what
#  docker/oracles installs. Run by hand; the image build only ever installs from the locks.
#
#      scripts/oracles/lock.sh
#

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="$(sed -n 's/^FROM \(ubuntu[^ ]*\) AS base$/\1/p' "$ROOT/docker/oracles/Dockerfile")"
[ -n "$BASE" ] || { echo "lock.sh: no base image in docker/oracles/Dockerfile" >&2; exit 2; }

docker run --rm -v "$ROOT/scripts/oracles/python:/w" -w /w "$BASE" bash -c '
    set -e
    apt-get update -qq && apt-get install -y -qq --no-install-recommends python3-venv >/dev/null
    python3 -m venv /tmp/v && /tmp/v/bin/pip install -q pip-tools==7.7.0
    /tmp/v/bin/pip-compile -q --generate-hashes --strip-extras --no-emit-index-url --allow-unsafe \
        --output-file requirements.txt requirements.in'

# Node and Rust from the built image (scripts/oracles/image.sh builds it if needed)
IMAGE="$("$ROOT/scripts/oracles/image.sh")"
docker run --rm -v "$ROOT/scripts/oracles/node:/w" -w /w "$IMAGE" \
    npm install --package-lock-only --ignore-scripts --no-audit --no-fund
docker run --rm -v "$ROOT/scripts/oracles/rust:/w" -w /w "$IMAGE" cargo generate-lockfile
echo "lock.sh: python/requirements.txt, node/package-lock.json and rust/Cargo.lock regenerated; rebuild the image"

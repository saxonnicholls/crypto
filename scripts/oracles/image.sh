#!/usr/bin/env bash
#
#  image.sh
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Builds the oracle image (docker/oracles) if it is not already built, and prints its tag. The tag is a hash of
#  the Dockerfile and every manifest it installs from, so moving a pin builds a new image and an unchanged one is
#  reused. Docker is shared: this never removes an image or stops a container.
#
#      scripts/oracles/image.sh             build if needed, print snicholls-crypto-oracles:<hash>
#      scripts/oracles/image.sh --tag       print the tag only (CI builds it with its layer cache)
#

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
INPUTS=(docker/oracles/Dockerfile docker/oracles/Dockerfile.dockerignore
        scripts/oracles/python/requirements.txt scripts/oracles/node/package.json
        scripts/oracles/node/package-lock.json scripts/oracles/rust/Cargo.toml scripts/oracles/rust/Cargo.lock)
hash="$(cat "${INPUTS[@]}" | { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-12)"
tag="snicholls-crypto-oracles:$hash"
if [ "${1:-}" = --tag ]; then
    echo "$tag"
    exit 0
fi
if ! docker image inspect "$tag" >/dev/null 2>&1; then
    echo "image.sh: building $tag" >&2
    DOCKER_BUILDKIT=1 docker build -q -f docker/oracles/Dockerfile -t "$tag" . >&2
fi
echo "$tag"

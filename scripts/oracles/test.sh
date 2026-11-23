#!/usr/bin/env bash
#
#  test.sh
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  The differential gate, locally as in CI: in the oracle image (docker/oracles), the tracked files are copied in,
#  built with warnings as errors, and the oracle tests run: generated.oracle_fixtures_up_to_date (every fixture
#  regenerated from the pinned oracles and compared byte for byte) and the *_oracles_test.cpp replays.
#
#      scripts/oracles/test.sh          (make oracles)
#
#  The checkout is mounted read-only; nothing is written back.
#

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="$("$ROOT/scripts/oracles/image.sh")"
LIST="$(mktemp)"
trap 'rm -f "$LIST"' EXIT
( cd "$ROOT" && git ls-files && git submodule foreach --quiet --recursive 'git ls-files | sed "s|^|$sm_path/|"' ) > "$LIST"

docker run --rm -i -v "$ROOT:/src:ro" -v "$LIST:/filelist:ro" \
    ${CMAKE_BUILD_PARALLEL_LEVEL:+-e CMAKE_BUILD_PARALLEL_LEVEL="$CMAKE_BUILD_PARALLEL_LEVEL"} \
    "$IMAGE" bash -s <<'IN_CONTAINER'
set -euo pipefail
mkdir -p /work/crypto && cd /src && tar -cf - -T /filelist | tar -C /work/crypto -xf -
cd /work/crypto
cmake -S . -B /work/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++ \
    -DSNICHOLLS_CRYPTO_WERROR=ON >/work/configure.log
cmake --build /work/build --target snicholls_crypto_tests >/work/build.log 2>&1 || { tail -40 /work/build.log; exit 1; }
# The regeneration must be registered here (ORACLES_HOME is the image's), or this gate would only replay
ctest --test-dir /work/build -N -R '^generated.oracle_fixtures_up_to_date$' | grep -q 'Total Tests: 1' ||
    { echo "test.sh: generated.oracle_fixtures_up_to_date is not registered" >&2; exit 1; }
ctest --test-dir /work/build --output-on-failure -R '^generated.oracle_fixtures_up_to_date$|Oracles'

IN_CONTAINER

#!/usr/bin/env bash
#
#  test_ubuntu.sh
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Run crypto's full test suite on Ubuntu in Docker, from any machine with
#  Docker - the local half of the gate that CI runs (CLAUDE.md "Build and gates").
#  Two images: docker/ubuntu (Ubuntu 24.04: GCC 13, Clang 18, Doxygen; the
#  compilers of CI's ARM64 legs) and docker/ubuntu-26.04 (Ubuntu 26.04: GCC 15
#  and Clang 21, the g++ and clang++ of CI's x86-64 legs on ubuntu-latest).
#
#      scripts/test_ubuntu.sh            every configuration below but the ARM64 one
#      scripts/test_ubuntu.sh --arm64    the same, then the ARM64 configuration
#      scripts/test_ubuntu.sh --quick    GCC 13, GCC 15 and Clang 21 Release only (and ARM64 GCC with --arm64)
#      scripts/test_ubuntu.sh -j 4       at most 4 compiles (and 4 tests) at once, on a shared machine
#
#  Configurations, each a fresh CMake build of everything with warnings as
#  errors, then every CTest:
#
#      gcc     Release   + benchmarks smoke run + documentation (Doxygen)
#      gcc     Debug     -O0, asserts live
#      clang   Release
#      clang   Debug
#      clang   ASan+UBSan
#      gcc     ASan+UBSan
#      gcc15   Release   + benchmarks smoke run, -march=x86-64-v3 (Ubuntu 26.04 image)
#      gcc15   ASan+UBSan                             (Ubuntu 26.04 image)
#      clang21 Release   + benchmarks smoke run       (Ubuntu 26.04 image)
#      clang21 Debug     -O0                          (Ubuntu 26.04 image)
#      clang21 ASan+UBSan                             (Ubuntu 26.04 image)
#      arm64 gcc Release + benchmarks smoke run       (--arm64 only: Ubuntu 24.04 image, linux/arm64)
#
#  The GCC 15, Clang 21 and ARM64 Release configurations are configured as CI
#  configures its legs, GNU Make included; the others are built with Ninja.
#  GCC 15 Release adds -march=x86-64-v3: CI's g++ emits AVX2 code, and GCC
#  reports false overflows from 32-byte stores that 16-byte ones do not show
#  (ECDSA's DER, once), so the local GCC 15 must see the same vectors.
#  The ARM64 configuration is GCC 13 for aarch64, whose vectoriser warns where
#  x86-64's does not (base58, once). On an x86-64 host it runs under QEMU
#  emulation (Docker Desktop has it; elsewhere binfmt for arm64 must be
#  installed): half an hour on a 16-core host, the image's first build as long
#  again, so it is opt-in; on an ARM64 host it is native.
#
#  The checkout is mounted read-only and copied into the container from
#  `git ls-files` plus the submodules, so nothing untracked is tested and
#  nothing is written back. Exits non-zero if any configuration fails, after
#  running them all.
#

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUICK=0
ARM64=0
JOBS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) QUICK=1 ;;
        --arm64) ARM64=1 ;;
        -j) shift; JOBS="${1:-}" ;;
        -j*) JOBS="${1#-j}" ;;
        -h|--help) sed -n '2,49p' "$0" | sed 's/^#\s\{0,1\}//'; exit 0 ;;
        *) echo "test_ubuntu: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done
case "$JOBS" in
    ""|*[!0-9]*) [ -z "$JOBS" ] || { echo "test_ubuntu: -j needs a number" >&2; exit 2; } ;;
esac

command -v docker >/dev/null || { echo "test_ubuntu: docker is not installed" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "test_ubuntu: docker is not running" >&2; exit 2; }

# Each image is tagged by a hash of its Dockerfile, so editing a Dockerfile
# builds a new image and an unchanged one is reused
image() {   # image <docker/ directory> <repository> [platform]: builds if needed, prints the tag
    local hash
    hash="$(shasum -a 256 "$ROOT/docker/$1/Dockerfile" 2>/dev/null || sha256sum "$ROOT/docker/$1/Dockerfile")"
    local tag="$2:${hash:0:12}"
    if ! docker image inspect "$tag" >/dev/null 2>&1; then
        echo "test_ubuntu: building $tag" >&2
        DOCKER_BUILDKIT=1 docker build -q ${3:+--platform "$3"} -t "$tag" "$ROOT/docker/$1" >/dev/null
    fi
    echo "$tag"
}
IMAGE="$(image ubuntu snicholls-crypto-ubuntu)"
IMAGE_2604="$(image ubuntu-26.04 snicholls-crypto-ubuntu-2604)"
if [ "$ARM64" = 1 ]; then
    IMAGE_ARM64="$(image ubuntu snicholls-crypto-ubuntu-arm64 linux/arm64)"
fi

# Tracked files only, including the submodules' tracked files
LIST="$(mktemp)"
OUT="$(mktemp)"
trap 'rm -f "$LIST" "$OUT"' EXIT
( cd "$ROOT" && git ls-files && git submodule foreach --quiet --recursive \
    'git ls-files | sed "s|^|$sm_path/|"' ) > "$LIST"

# The script each container runs; SET names which image it is in, and so
# which configurations it runs
in_container() {
cat <<'IN_CONTAINER'
set -uo pipefail
mkdir -p /work/crypto && cd /src && tar -cf - -T /filelist | tar -C /work/crypto -xf -
cd /work/crypto

run() {   # run <label> <cmake args...>; with GENERATOR="Unix Makefiles", GNU Make builds it, as in CI
    local label="$1"; shift
    local dir="/work/build-${label// /-}"
    local log="$dir.log"
    printf '  %-28s ' "$label"
    if cmake -S . -B "$dir" -G "${GENERATOR:-Ninja}" -DSNICHOLLS_CRYPTO_WERROR=ON "$@" >"$log" 2>&1 &&
       cmake --build "$dir" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-$(nproc)}" >>"$log" 2>&1 &&   # GNU Make is serial without it
       ctest --test-dir "$dir" --output-on-failure >>"$log" 2>&1; then
        echo "ok   $(grep -E '^[0-9]+% tests passed' "$log" | tail -1)"
    else
        echo "FAILED"
        grep -m 8 -E ": (error|warning): " "$log" | sed "s/^/      /"
        tail -40 "$log" | sed 's/^/      /'
    fi
}

echo "snicholls-crypto on $(. /etc/os-release && echo "$PRETTY_NAME"), $(uname -m)"
if [ "$SET" = ubuntu-26.04 ]; then
    echo "  $(g++-15 --version | head -1)"
    echo "  $(clang++-21 --version | head -1)"
    gcc15="-DCMAKE_C_COMPILER=gcc-15 -DCMAKE_CXX_COMPILER=g++-15"
    clang21="-DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21"
    # Release as CI's x86-64 legs configure it: GNU Make, benchmarks on. CI's g++ on ubuntu-latest generates
    # 32-byte vectors (AVX2), which this archive's GCC 15 does only when asked: GCC's -Wstringop-overflow and
    # -Warray-bounds see the wider stores, so the GCC 15 Release build asks (the host must have AVX2 to run it)
    GENERATOR="Unix Makefiles" run "gcc15 Release x86-64-v3" $gcc15 -DCMAKE_BUILD_TYPE=Release -DSNICHOLLS_CRYPTO_BUILD_BENCHMARKS=ON \
        -DCMAKE_CXX_FLAGS=-march=x86-64-v3
    GENERATOR="Unix Makefiles" run "clang21 Release" $clang21 -DCMAKE_BUILD_TYPE=Release -DSNICHOLLS_CRYPTO_BUILD_BENCHMARKS=ON
    if [ "$QUICK" != 1 ]; then
        run "gcc15 ASan+UBSan"   $gcc15 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSNICHOLLS_CRYPTO_SANITIZE=address,undefined
        run "clang21 Debug"      $clang21 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS_DEBUG=-O0
        run "clang21 ASan+UBSan" $clang21 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSNICHOLLS_CRYPTO_SANITIZE=address,undefined
    fi
    exit 0
fi

if [ "$SET" = arm64 ]; then
    echo "  $(g++ --version | head -1)"
    # As CI's Linux ARM64 GCC leg configures it: GNU Make, benchmarks on
    GENERATOR="Unix Makefiles" run "arm64 gcc Release" -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DSNICHOLLS_CRYPTO_BUILD_BENCHMARKS=ON
    exit 0
fi

echo "  $(g++ --version | head -1)"
echo "  $(clang++ --version | head -1)"
echo "  doxygen $(doxygen --version)"

docs=-DSNICHOLLS_CRYPTO_BUILD_DOCS=ON
case "$(doxygen --version)" in
    1.9.*|1.8.*) docs=-DSNICHOLLS_CRYPTO_BUILD_DOCS=OFF
                 echo "  (docs check skipped: Doxygen $(doxygen --version) is older than the pinned 1.18 - an ARM64 host)";;
esac

run "gcc Release"        -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DSNICHOLLS_CRYPTO_BUILD_BENCHMARKS=ON "$docs"
if [ "$QUICK" != 1 ]; then
    run "gcc Debug"          -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Debug
    run "clang Release"      -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
    run "clang Debug"        -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
    run "clang ASan+UBSan"   -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSNICHOLLS_CRYPTO_SANITIZE=address,undefined
    run "gcc ASan+UBSan"     -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSNICHOLLS_CRYPTO_SANITIZE=address,undefined
fi
IN_CONTAINER
}

in_image() {   # in_image <image> <set> [platform]: runs in_container there, its report shown and kept in OUT
    in_container | docker run --rm -i ${3:+--platform "$3"} \
        -v "$ROOT:/src:ro" -v "$LIST:/filelist:ro" \
        -e QUICK="$QUICK" -e SET="$2" \
        ${JOBS:+-e CMAKE_BUILD_PARALLEL_LEVEL="$JOBS" -e CTEST_PARALLEL_LEVEL="$JOBS"} \
        "$1" bash -s | tee -a "$OUT" || echo "  $2 image                  FAILED" | tee -a "$OUT"
}
in_image "$IMAGE" gcc13-clang18
echo
in_image "$IMAGE_2604" ubuntu-26.04
if [ "$ARM64" = 1 ]; then
    echo
    in_image "$IMAGE_ARM64" arm64 linux/arm64
fi

# Each configuration reported one line, "  <label> ok ..." or "  <label> FAILED"
passed="$(grep -cE '^  [^ ].* ok   ' "$OUT" || true)"
failed="$(grep -E '^  [^ ].* FAILED$' "$OUT" | sed -E 's/^  (.*[^ ]) +FAILED$/\1/' | paste -sd, - || true)"
echo
if [ -z "$failed" ] && [ "$passed" -gt 0 ]; then
    echo "test_ubuntu: all $passed configurations passed"
    exit 0
fi
nfailed="$(grep -cE '^  [^ ].* FAILED$' "$OUT")"
echo "test_ubuntu: $nfailed of $(( passed + nfailed )) configurations FAILED: $failed"
exit 1

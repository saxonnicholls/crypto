#!/usr/bin/env bash
#
#  run.sh
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Builds the differential fuzz harness in the oracle image and runs every target for a while. A divergence is
#  minimised (libFuzzer's -minimize_crash) and written to fuzz/regressions/<target>/, the only place this writes in
#  the checkout, ready to be committed as a regression test (fuzz.<target>.regressions replays it); the run then
#  fails. See fuzz/README.md.
#
#      fuzz/run.sh                  every target, 30 seconds each (CI on every push: a few minutes in all)
#      fuzz/run.sh 3600             every target, an hour each (the nightly workflow)
#      fuzz/run.sh 600 ed25519      one target
#      SNICHOLLS_CRYPTO_FUZZ_CONTROL=1 fuzz/run.sh 10 x25519
#                                   the control: a planted divergence must be found, minimised and reported
#                                   (its reproducer goes to the container's scratch space, not fuzz/regressions)
#

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECONDS_EACH="${1:-30}"
ONLY="${2:-}"
IMAGE="$("$ROOT/scripts/oracles/image.sh")"
LIST="$(mktemp)"
trap 'rm -f "$LIST"' EXIT
( cd "$ROOT" && git ls-files && git submodule foreach --quiet --recursive 'git ls-files | sed "s|^|$sm_path/|"' ) > "$LIST"
mkdir -p "$ROOT/fuzz/regressions"

docker run --rm -i -v "$ROOT:/src:ro" -v "$LIST:/filelist:ro" -v "$ROOT/fuzz/regressions:/regressions" \
    -e SECONDS_EACH="$SECONDS_EACH" -e ONLY="$ONLY" \
    ${SNICHOLLS_CRYPTO_FUZZ_CONTROL:+-e SNICHOLLS_CRYPTO_FUZZ_CONTROL=1} \
    ${CMAKE_BUILD_PARALLEL_LEVEL:+-e CMAKE_BUILD_PARALLEL_LEVEL="$CMAKE_BUILD_PARALLEL_LEVEL"} \
    "$IMAGE" bash -s <<'IN_CONTAINER'
set -uo pipefail
mkdir -p /work/crypto && cd /src && tar -cf - -T /filelist | tar -C /work/crypto -xf -
cd /work/crypto
# The regressions committed so far, and any just found, are replayed from the writable mount
rm -rf fuzz/regressions && ln -s /regressions fuzz/regressions
cargo build --release --locked --offline --quiet --manifest-path scripts/oracles/rust/Cargo.toml
cmake -S . -B /work/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_COMPILER=clang++ \
    -DSNICHOLLS_CRYPTO_WERROR=ON -DSNICHOLLS_CRYPTO_BUILD_FUZZ=ON >/work/configure.log 2>&1 ||
    { tail -30 /work/configure.log; exit 1; }
targets="secp256k1_ecdsa secp256k1_parse secp256k1_schnorr ed25519 x25519 rsa p256 p384 aead text"
[ -n "$ONLY" ] && targets="$ONLY"
for t in $targets; do
    cmake --build /work/build --target snicholls_crypto_fuzz_$t >/work/build-$t.log 2>&1 ||
        { grep -m 10 -E "error" /work/build-$t.log; exit 1; }
done
# The fuzz build's own tests: every committed regression replayed, and every control reported
if [ -z "$ONLY" ]; then
    ctest --test-dir /work/build -L fuzz --output-on-failure >/work/ctest-fuzz.log 2>&1 ||
        { tail -30 /work/ctest-fuzz.log; exit 1; }
    echo "  $(grep -E 'tests passed' /work/ctest-fuzz.log) (fuzz.<target>.regressions and .control)"
fi
python3 -I fuzz/make_corpus.py /work/corpus
REG=/regressions
if [ -n "${SNICHOLLS_CRYPTO_FUZZ_CONTROL:-}" ]; then
    REG=/work/control-regressions
    for t in $targets; do printf 'DIVERGE, the control seed, padded for the minimiser' > /work/corpus/$t/control; done
fi
status=0
for t in $targets; do
    bin=/work/build/fuzz/snicholls_crypto_fuzz_$t
    mkdir -p /work/artifacts/$t
    # the committed regressions first
    if [ -d /regressions/$t ] && [ -n "$(ls -A /regressions/$t 2>/dev/null)" ]; then
        "$bin" -runs=0 /regressions/$t >/work/replay-$t.log 2>&1 || { echo "  $t: a committed regression diverges"; tail -20 /work/replay-$t.log; status=1; continue; }
    fi
    printf '  %-20s ' "$t"
    if "$bin" -max_total_time="$SECONDS_EACH" -timeout=20 -rss_limit_mb=4096 -print_final_stats=1 \
            -artifact_prefix=/work/artifacts/$t/ /work/corpus/$t >/work/fuzz-$t.log 2>&1; then
        echo "ok   $(grep -m1 -oE 'stat::number_of_executed_units: *[0-9]+' /work/fuzz-$t.log | grep -oE '[0-9]+$') runs"
    else
        crash="$(ls /work/artifacts/$t/crash-* /work/artifacts/$t/timeout-* /work/artifacts/$t/oom-* 2>/dev/null | head -1)"
        echo "FAILED"
        grep -m 4 -E "DIVERGENCE|^fuzz: |ERROR: |runtime error" /work/fuzz-$t.log | sed 's/^/      /'
        # an oracle's own error (a Python traceback, a Rust panic) goes to the same log
        grep -A12 -E "^Traceback|panicked at" /work/fuzz-$t.log | head -30 | sed 's/^/      | /'
        if [ -n "$crash" ]; then
            mkdir -p $REG/$t
            out="$REG/$t/$(sha1sum "$crash" | cut -c1-16)"
            "$bin" -minimize_crash=1 -max_total_time=120 -exact_artifact_path="$out" "$crash" >/work/min-$t.log 2>&1 || true
            # A minimised input must still fail on its own; if it does not (state carried between inputs, as in an
            # oracle process), the original input is kept instead
            if [ ! -f "$out" ] || "$bin" "$out" >/work/replay-min-$t.log 2>&1; then
                cp "$crash" "$out"
                echo "      (the minimised input does not fail on its own: the original input is kept)"
            fi
            echo "      reproducer: ${REG#/}/$t/$(basename "$out") ($(stat -c %s "$out") bytes)"
            if "$bin" "$out" >/work/replay-out-$t.log 2>&1; then
                echo "      (and it does not fail when replayed alone: state carried between inputs)"
            else
                grep -m 3 -E "DIVERGENCE|^fuzz: |runtime error" /work/replay-out-$t.log | sed 's/^/      /'
            fi
        fi
        status=1
    fi
done
exit $status
IN_CONTAINER

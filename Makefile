# snicholls-crypto
#
# The library is header-only (include/snicholls/crypto/*.hpp). CMake is the
# build; this is the short way to drive it, with the same gates CI runs.
#
#   make test            configure, build, run every CTest (unit, demo, boundary)
#   make test-werror     the same with warnings as errors, as CI does
#   make asan            Address + UB sanitizers
#   make docs            Doxygen, warnings as errors; opens nothing, writes build-docs/docs/html
#   make check           the static checks CI runs first: version, mirror, nothing private
#   make ubuntu          the full suite on Ubuntu 24.04 and 26.04 in Docker, GCC 13 and 15, Clang 18,
#                        sanitizers and the Valgrind secret-marking check (scripts/test_ubuntu.sh)
#   make oracles         the differential gate in the oracle image (docker/oracles): every fixture under
#                        tests/fixtures/oracles regenerated from the pinned oracles, then replayed
#                        (scripts/oracles/test.sh; scripts/generate_oracle_fixtures.py to rewrite them)
#   make benchmarks      every benchmark in Release, results written to BENCHMARKS.md
#                        (scripts/benchmarks_md.py; --filter for one file)
#   make demos           build and run every demo, output shown (scripts/run_demos.sh --all;
#                        scripts/run_demos.sh ecdsa for one)
#   make clean
#
#   make test CXX=clang++      any target with a different compiler
#   make test BUILD=build-x    any target in a different build directory

CXX      ?= c++
BUILD    ?= build
CONFIG   ?= Release
CMAKE_FLAGS ?=

.PHONY: all test test-werror asan docs check ubuntu oracles demos benchmarks clean

all: test

check:
	python3 scripts/check_version.py
	python3 scripts/check_mirror.py
	python3 scripts/check_public.py --commits

$(BUILD)/CMakeCache.txt:
	cmake -B $(BUILD) -DCMAKE_BUILD_TYPE=$(CONFIG) -DCMAKE_CXX_COMPILER=$(CXX) $(CMAKE_FLAGS)

test: check $(BUILD)/CMakeCache.txt
	cmake --build $(BUILD) --parallel
	ctest --test-dir $(BUILD) --output-on-failure

test-werror:
	$(MAKE) test BUILD=build-werror CMAKE_FLAGS="-DSNICHOLLS_CRYPTO_WERROR=ON"

asan:
	$(MAKE) test BUILD=build-asan CONFIG=RelWithDebInfo \
	    CMAKE_FLAGS="-DSNICHOLLS_CRYPTO_WERROR=ON -DSNICHOLLS_CRYPTO_SANITIZE=address,undefined"

docs:
	cmake -B build-docs -DSNICHOLLS_CRYPTO_BUILD_TESTS=OFF -DSNICHOLLS_CRYPTO_BUILD_DOCS=ON
	cmake --build build-docs --target docs

ubuntu:
	scripts/test_ubuntu.sh

oracles:
	scripts/oracles/test.sh

benchmarks:
	cmake -B build-bench -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=$(CXX) -DSNICHOLLS_CRYPTO_BUILD_BENCHMARKS=ON -DSNICHOLLS_CRYPTO_BUILD_TESTS=OFF
	cmake --build build-bench --parallel
	python3 scripts/benchmarks_md.py --build build-bench

demos:
	BUILD=$(BUILD) CONFIG=$(CONFIG) CXX=$(CXX) scripts/run_demos.sh --all

clean:
	rm -rf build build-*

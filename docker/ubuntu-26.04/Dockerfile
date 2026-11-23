# syntax=docker/dockerfile:1.6
#
# snicholls-crypto - the GCC 15 and Clang 21 build and test image.
#
# CI's Linux x86-64 legs run on ubuntu-latest, which is Ubuntu 26.04: its g++ is
# GCC 15 and its clang++ is Clang 21, compiling against GCC 15's libstdc++. Both
# warn or fail where GCC 13 and Clang 18 do not (GCC 15: false -Warray-bounds and
# -Wstringop-overflow; Clang 21 with libstdc++ 15: more constexpr steps for the same
# evaluation, since libstdc++'s assertions are checked in constant expressions).
# This image puts those compilers in the local gate: scripts/test_ubuntu.sh builds
# it beside docker/ubuntu/Dockerfile (Ubuntu 24.04, GCC 13 and Clang 18) and runs
# the GCC 15 and Clang 21 configurations in it.
#
# Ubuntu 26.04 LTS ships both compilers in its own archive, so the image needs no
# PPA and no compiler built from source: the base image is pinned by its release,
# and the compilers by their major versions, as docker/ubuntu/Dockerfile pins GCC 13
# and Clang 18. libclang-rt-21-dev is compiler-rt, for Clang's sanitizers; Valgrind
# is the secret-marking check, as CI installs it. The documentation is checked in
# the other image.

FROM ubuntu:26.04

LABEL org.opencontainers.image.title="snicholls-crypto Ubuntu GCC 15 and Clang 21 builder" \
      org.opencontainers.image.description="Ubuntu 26.04: GCC 15, Clang 21 with compiler-rt, CMake, Ninja, GNU Make, Valgrind"

ENV DEBIAN_FRONTEND=noninteractive

# The apt caches are this repository's own (id) and locked: Docker's build cache
# is shared with every project on the machine, and two apt-gets in one cache
# directory at once take each other's lock and fail (exit 100).
RUN --mount=type=cache,id=snicholls-crypto-ubuntu-2604-apt-cache,sharing=locked,target=/var/cache/apt \
    --mount=type=cache,id=snicholls-crypto-ubuntu-2604-apt-lib,sharing=locked,target=/var/lib/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential gcc-15 g++-15 \
      clang-21 libclang-rt-21-dev \
      cmake ninja-build make \
      python3-minimal git ca-certificates valgrind && \
    rm -rf /var/lib/apt/lists/* && \
    g++-15 --version | head -1 && \
    clang++-21 --version | head -1

# Sources are mounted read-only by scripts/test_ubuntu.sh and copied in, so a
# build inside the container never writes into the checkout.
WORKDIR /work
CMD ["bash"]

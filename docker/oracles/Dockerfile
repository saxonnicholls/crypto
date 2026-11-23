# syntax=docker/dockerfile:1.6
#
# snicholls-crypto - the oracle image: other implementations to compare against, every one pinned.
#
# Test-only. The library never includes or links anything here; scripts/generate_oracle_fixtures.py drives the
# oracle programs under scripts/oracles/ (JSON lines on stdin and stdout) to produce tests/fixtures/oracles/, and
# the CTest generated.oracle_fixtures_up_to_date reruns it in this image and fails on any difference.
#
#   - the base image by digest (Ubuntu 24.04: GCC 13, Clang 18, Python 3.12, CMake, Ninja);
#   - Node by version and SHA-256 of the official tarball, the packages by node/package-lock.json (npm ci);
#   - Rust by rustup-init's SHA-256 and an exact toolchain, the crates by rust/Cargo.lock (--locked);
#   - the Python packages by python/requirements.txt, every distribution's SHA-256 (--require-hashes);
#   - the BIP-173 / BIP-350 reference code by commit and SHA-256;
#   - for the fuzz harness, libsecp256k1 and libsodium from their release tarballs by SHA-256, and OpenSSL.
#
# Built from the repository root, which is the context, by scripts/oracles/image.sh:
#
#     docker build -f docker/oracles/Dockerfile -t <tag> .
#
# Only the manifests are copied in (Dockerfile.dockerignore, next to this file, admits nothing else); the oracle programs themselves
# are read from the checkout when the fixtures are generated, so the image is rebuilt only when a pin moves.

FROM ubuntu@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289 AS base

LABEL org.opencontainers.image.title="snicholls-crypto oracles" \
      org.opencontainers.image.description="Pinned Python, Node and Rust implementations of secp256k1, Ed25519, X25519, BIP-39, BIP-32, SLIP-10 and the address encodings, for differential tests"

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential g++-13 clang-18 libclang-rt-18-dev \
      cmake ninja-build pkg-config \
      python3 python3-venv git ca-certificates curl xz-utils && \
    ln -sf /usr/bin/clang-18 /usr/local/bin/clang && \
    ln -sf /usr/bin/clang++-18 /usr/local/bin/clang++ && \
    rm -rf /var/lib/apt/lists/*

ENV ORACLES_HOME=/opt/oracles

# Node 26.13.1 (LTS)
ARG NODE_VERSION=26.13.1
ARG NODE_SHA256_X64=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864
ARG NODE_SHA256_ARM64=89e1853138db51e8b82d3e98ba9c0d3f2956a28e5e55ea1b7e12d25aae92d5dd
RUN case "${TARGETARCH:-amd64}" in \
      amd64) arch=x64;   sum="$NODE_SHA256_X64" ;; \
      arm64) arch=arm64; sum="$NODE_SHA256_ARM64" ;; \
      *) echo "no Node for $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" && \
    echo "${sum}  /tmp/node.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --exclude='*/CHANGELOG.md' --exclude='*/README.md' && \
    rm /tmp/node.tar.xz && node --version

# Rust 1.100.0, through rustup 1.29.3
ARG RUSTUP_VERSION=1.29.3
ARG RUST_VERSION=1.100.0
ARG RUSTUP_SHA256_X64=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
ARG RUSTUP_SHA256_ARM64=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN case "${TARGETARCH:-amd64}" in \
      amd64) triple=x86_64-unknown-linux-gnu;  sum="$RUSTUP_SHA256_X64" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum="$RUSTUP_SHA256_ARM64" ;; \
      *) echo "no Rust for $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init" && \
    echo "${sum}  /tmp/rustup-init" | sha256sum -c - && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" && \
    rm /tmp/rustup-init && rustc --version && cargo --version

# The BIP-173 / BIP-350 reference implementation (MIT), Pieter Wuille's ref/python/segwit_addr.py
ARG BECH32_REF_COMMIT=7a7d7ab158db7078a333384e0e918c90dbc42917
ARG BECH32_REF_SHA256=2884ce04a36c8374c4249177cd90e91e545ac73b5c9260307bbeb74ae2e9de0f
RUN mkdir -p "$ORACLES_HOME/python-ref" && \
    curl -fsSL -o "$ORACLES_HOME/python-ref/segwit_addr.py" \
      "https://raw.githubusercontent.com/sipa/bech32/${BECH32_REF_COMMIT}/ref/python/segwit_addr.py" && \
    echo "${BECH32_REF_SHA256}  $ORACLES_HOME/python-ref/segwit_addr.py" | sha256sum -c - && \
    echo "${BECH32_REF_COMMIT}" > "$ORACLES_HOME/python-ref/COMMIT"

# Python: a virtual environment, from the hashed lock only
COPY scripts/oracles/python/requirements.txt /tmp/requirements.txt
RUN python3 -m venv "$ORACLES_HOME/venv" && \
    "$ORACLES_HOME/venv/bin/pip" install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Node: npm ci from the lock, without install scripts
COPY scripts/oracles/node/package.json scripts/oracles/node/package-lock.json $ORACLES_HOME/node/
RUN cd "$ORACLES_HOME/node" && npm ci --ignore-scripts --no-audit --no-fund && npm ls --all >/dev/null

# Rust: every crate fetched and compiled once into a shared target directory, so building the oracle from the
# checkout later is offline and compiles only its own source (the placeholder's own artifacts are removed, so
# that build never mistakes the placeholder for the oracle)
COPY scripts/oracles/rust/Cargo.toml scripts/oracles/rust/Cargo.lock $ORACLES_HOME/rust/
ENV CARGO_TARGET_DIR=$ORACLES_HOME/rust-target
RUN cd "$ORACLES_HOME/rust" && mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --locked && \
    cargo clean --release --locked -p snicholls-crypto-oracle && rm -rf src

# The C oracles for the fuzz harness (fuzz/, -DSNICHOLLS_CRYPTO_BUILD_FUZZ=ON): libsecp256k1 and libsodium from
# their release tarballs by SHA-256, into $ORACLES_HOME/c with pkg-config files; OpenSSL is the image's package
# (Ubuntu 24.04's 3.0 series). None of them is reachable from the snicholls::crypto target.
ARG SECP256K1_VERSION=0.8.0
ARG SECP256K1_SHA256=eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb
ARG SODIUM_VERSION=1.0.22
ARG SODIUM_SHA256=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends libssl-dev && rm -rf /var/lib/apt/lists/* && \
    curl -fsSL -o /tmp/secp.tgz "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${SECP256K1_VERSION}.tar.gz" && \
    echo "${SECP256K1_SHA256}  /tmp/secp.tgz" | sha256sum -c - && \
    mkdir /tmp/secp && tar -xzf /tmp/secp.tgz -C /tmp/secp --strip-components=1 && \
    cmake -S /tmp/secp -B /tmp/secp/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang \
      -DCMAKE_INSTALL_PREFIX="$ORACLES_HOME/c" -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
      -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
      -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF \
      -DBUILD_SHARED_LIBS=OFF && \
    cmake --build /tmp/secp/build && cmake --install /tmp/secp/build && \
    curl -fsSL -o /tmp/sodium.tgz "https://github.com/jedisct1/libsodium/releases/download/${SODIUM_VERSION}-RELEASE/libsodium-${SODIUM_VERSION}.tar.gz" && \
    echo "${SODIUM_SHA256}  /tmp/sodium.tgz" | sha256sum -c - && \
    mkdir /tmp/sodium && tar -xzf /tmp/sodium.tgz -C /tmp/sodium --strip-components=1 && \
    cd /tmp/sodium && CC=clang ./configure --quiet --prefix="$ORACLES_HOME/c" --disable-shared --with-pic && \
    make -s -j"$(nproc)" && make -s install && \
    rm -rf /tmp/secp /tmp/secp.tgz /tmp/sodium /tmp/sodium.tgz && \
    echo "libsecp256k1 ${SECP256K1_VERSION}, libsodium ${SODIUM_VERSION}" > "$ORACLES_HOME/c/VERSIONS"
ENV PKG_CONFIG_PATH=$ORACLES_HOME/c/lib/pkgconfig

WORKDIR /work
CMD ["bash"]

# OSS-Fuzz build image for snicholls-crypto (fuzz/cryptofuzz/README.md, route 2). Not submitted.
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake libboost-dev
RUN git clone --depth 1 --recursive https://github.com/saxonnicholls/crypto.git snicholls-crypto
RUN git clone --depth 1 https://github.com/MozillaSecurity/cryptofuzz.git cryptofuzz
RUN curl -fsSL -o secp.tgz https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.7.0.tar.gz && \
    echo "073d19064f3600014750d6949b31a0c957aa7b98920fb4aaa495be07e8e7cd00  secp.tgz" | sha256sum -c - && \
    mkdir secp256k1 && tar -xzf secp.tgz -C secp256k1 --strip-components=1 && rm secp.tgz
COPY build.sh $SRC/
WORKDIR $SRC

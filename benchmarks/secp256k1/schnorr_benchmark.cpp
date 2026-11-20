//
//  schnorr_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// BIP-340: x-only public key, sign, verify. Refused unless BIP-340's vector 0 comes out.
#include <snicholls/crypto/secp256k1/schnorr.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <array>
#include <cstdio>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::test::hex;

namespace {
const auto key_bytes = hex<32>("0000000000000000000000000000000000000000000000000000000000000003");
const std::array<std::uint8_t, 32> message{};
const std::array<std::uint8_t, 32> aux{};

void XonlyPublicKey(benchmark::State& state)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(xonly_public_key_of(key));
}
BENCHMARK(XonlyPublicKey);

void SchnorrSign(benchmark::State& state)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(schnorr_sign(key, message, aux));
}
BENCHMARK(SchnorrSign);

void SchnorrVerify(benchmark::State& state)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    const auto pub = xonly_public_key_of(key);
    const auto sig = schnorr_sign(key, message, aux);
    for (auto _ : state)
        benchmark::DoNotOptimize(schnorr_verify(pub, message, sig));
}
BENCHMARK(SchnorrVerify);
} // namespace

int main(int argc, char** argv)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    const auto sig = schnorr_sign(key, message, aux);
    if (sig.bytes != hex<64>("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0") ||
        !schnorr_verify(xonly_public_key_of(key), message, sig)) {
        std::fprintf(stderr, "schnorr_benchmark: BIP-340 vector 0 does not come out; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

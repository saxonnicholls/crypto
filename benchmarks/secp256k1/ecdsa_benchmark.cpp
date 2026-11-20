//
//  ecdsa_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ECDSA over secp256k1: public key, sign, verify, recover. The constant-time multiplication (sign, public key) and
// the variable-time double multiplication (verify, recover) are timed side by side. Every benchmark is refused if
// the RFC 6979 vector for key 1 and "Satoshi Nakamoto" does not come out.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>

using namespace snicholls::crypto::secp256k1;
using snicholls::crypto::test::hex;

namespace {
const auto key_bytes = hex<32>("0000000000000000000000000000000000000000000000000000000000000001");
const auto hash = snicholls::crypto::detail::sha256::hash(snicholls::crypto::test::bytes_of("Satoshi Nakamoto"));

void PublicKey(benchmark::State& state)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(key.public_key());
}
BENCHMARK(PublicKey);

void Sign(benchmark::State& state)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(sign(key, hash));
}
BENCHMARK(Sign);

void Verify(benchmark::State& state)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    const auto pub = key.public_key();
    const auto sig = sign(key, hash).sig;
    for (auto _ : state)
        benchmark::DoNotOptimize(verify(pub, hash, sig));
}
BENCHMARK(Verify);

void Recover(benchmark::State& state)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    const auto sig = sign(key, hash);
    for (auto _ : state)
        benchmark::DoNotOptimize(recover(hash, sig.sig, sig.recovery_id));
}
BENCHMARK(Recover);

void ParsePublicKeyCompressed(benchmark::State& state)
{
    const auto c = private_key::from_bytes(key_bytes).unwrap().public_key().compressed();
    for (auto _ : state)
        benchmark::DoNotOptimize(public_key::parse(c));
}
BENCHMARK(ParsePublicKeyCompressed);
} // namespace

int main(int argc, char** argv)
{
    const auto key = private_key::from_bytes(key_bytes).unwrap();
    const auto sig = sign(key, hash);
    if (sig.sig.r != hex<32>("934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8") ||
        sig.sig.s != hex<32>("2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5") ||
        !verify(key.public_key(), hash, sig.sig) || !(recover(hash, sig.sig, sig.recovery_id).unwrap() == key.public_key())) {
        std::fprintf(stderr, "ecdsa_benchmark: the RFC 6979 vector does not come out; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

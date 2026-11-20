//
//  bech32_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// Segwit addresses: a P2WPKH (version 0, bech32) and a taproot (version 1, bech32m) address, encode and decode.
// Before timing, BIP-173's and BIP-350's vectors for those programs must reproduce, or nothing is timed.
#include <snicholls/crypto/address/bech32.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>
#include <string_view>

namespace {

namespace a = snicholls::crypto::address;

constexpr auto p2wpkh = snicholls::crypto::test::hex<20>("751e76e8199196d454941c45d1b3a323f1433bd6");
constexpr auto taproot = snicholls::crypto::test::hex<32>("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
constexpr std::string_view p2wpkh_text = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
constexpr std::string_view taproot_text = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

void SegwitEncodeP2wpkh(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::segwit_encode("bc", 0, p2wpkh));
}
BENCHMARK(SegwitEncodeP2wpkh);

void SegwitDecodeP2wpkh(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::segwit_decode("bc", p2wpkh_text));
}
BENCHMARK(SegwitDecodeP2wpkh);

void SegwitEncodeTaproot(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::segwit_encode("bc", 1, taproot));
}
BENCHMARK(SegwitEncodeTaproot);

void SegwitDecodeTaproot(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::segwit_decode("bc", taproot_text));
}
BENCHMARK(SegwitDecodeTaproot);

} // namespace

int main(int argc, char** argv)
{
    const auto v0 = a::segwit_encode("bc", 0, p2wpkh);
    const auto v1 = a::segwit_encode("bc", 1, taproot);
    if (!v0 || !v1 || std::string_view(v0->data(), v0->size()) != p2wpkh_text ||
        std::string_view(v1->data(), v1->size()) != taproot_text || !a::segwit_decode("bc", taproot_text)) {
        std::fprintf(stderr, "bech32_benchmark: the BIP-173 / BIP-350 vectors do not reproduce; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

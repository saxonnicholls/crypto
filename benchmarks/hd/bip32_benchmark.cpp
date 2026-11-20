//
//  bip32_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Key derivation: the BIP-32 master key, one hardened and one non-hardened step, the BIP-44 Ethereum path from a
// seed, public (xpub) derivation, and SLIP-10 Ed25519 along Solana's path. Refused unless BIP-32 vector 1 comes out.
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/hd/slip10.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>
#include <string>

using namespace snicholls::crypto::hd;

namespace {
const auto seed = snicholls::crypto::test::hex<16>("000102030405060708090a0b0c0d0e0f");

void MasterFromSeed(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(extended_private_key::from_seed(seed));
}
BENCHMARK(MasterFromSeed);

void HardenedChild(benchmark::State& state)
{
    const auto m = extended_private_key::from_seed(seed).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(m.derive_child(hardened(0)));
}
BENCHMARK(HardenedChild);

void NonHardenedChild(benchmark::State& state)
{
    const auto m = extended_private_key::from_seed(seed).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(m.derive_child(0));
}
BENCHMARK(NonHardenedChild);

void Bip44EthereumPath(benchmark::State& state)
{
    const auto path = derivation_path::parse("m/44'/60'/0'/0/0").unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(extended_private_key::from_seed(seed).unwrap().derive(path));
}
BENCHMARK(Bip44EthereumPath);

void PublicChild(benchmark::State& state)
{
    const auto x = extended_private_key::from_seed(seed).unwrap().public_key();
    for (auto _ : state)
        benchmark::DoNotOptimize(x.derive_child(0));
}
BENCHMARK(PublicChild);

void Slip10SolanaPath(benchmark::State& state)
{
    const auto path = derivation_path::parse("m/44'/501'/0'/0'").unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(slip10_ed25519_key::from_seed(seed).unwrap().derive(path).unwrap().public_key());
}
BENCHMARK(Slip10SolanaPath);
} // namespace

int main(int argc, char** argv)
{
    const auto t = extended_private_key::from_seed(seed).unwrap().to_text();
    if (std::string(t.begin(), t.end()) != "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi") {
        std::fprintf(stderr, "bip32_benchmark: BIP-32 vector 1's master key does not come out; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

//
//  ecdh_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ECDH on P-256 (constant time): one shared secret. Refuses to run unless RFC 7518 appendix C's Z reproduces.
#include <snicholls/crypto/p256/ecdh.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>

namespace {

namespace p256 = snicholls::crypto::p256;
using snicholls::crypto::test::hex;

constexpr auto alice_bytes = hex<32>("d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a");
constexpr auto bob_bytes = hex<32>("5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc");
constexpr auto expected_z = hex<32>("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");

void P256SharedSecret(benchmark::State& state)
{
    const auto alice = p256::private_key::from_bytes(alice_bytes).unwrap();
    const auto bob = p256::private_key::from_bytes(bob_bytes).unwrap().public_key();
    for (auto _ : state)
        benchmark::DoNotOptimize(p256::shared_secret(alice, bob));
}
BENCHMARK(P256SharedSecret);

} // namespace

int main(int argc, char** argv)
{
    const auto alice = p256::private_key::from_bytes(alice_bytes).unwrap();
    const auto z = p256::shared_secret(alice, p256::private_key::from_bytes(bob_bytes).unwrap().public_key());
    if (!z.is_ok() || !std::equal(expected_z.begin(), expected_z.end(), z.unwrap().reveal().begin())) {
        std::fprintf(stderr, "ecdh_benchmark (P-256): RFC 7518 appendix C's Z does not reproduce; refusing to time a wrong implementation\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

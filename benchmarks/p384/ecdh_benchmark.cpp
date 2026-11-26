//
//  ecdh_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ECDH on P-384 (constant time): one shared secret. Refuses to run unless Wycheproof's ecdh_secp384r1_ecpoint tcId 1
// reproduces.
#include <snicholls/crypto/p384/ecdh.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <algorithm>
#include <cstdio>

namespace {

namespace p384 = snicholls::crypto::p384;
using snicholls::crypto::test::hex;

constexpr auto peer_bytes = hex<97>("04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f791b64a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b3b56eadff6b0f668c3b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163caa");
constexpr auto key_bytes = hex<48>("766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1fb1dee4edd64356b9f21c588b75dfd81");
constexpr auto expected_z = hex<48>("6461defb95d996b24296f5a1832b34db05ed031114fbe7d98d098f93859866e4de1e229da71fef0c77fe49b249190135");

void P384SharedSecret(benchmark::State& state)
{
    const auto key = p384::private_key::from_bytes(key_bytes).unwrap();
    const auto peer = p384::public_key::parse(peer_bytes).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(p384::shared_secret(key, peer));
}
BENCHMARK(P384SharedSecret);

} // namespace

int main(int argc, char** argv)
{
    const auto key = p384::private_key::from_bytes(key_bytes).unwrap();
    const auto z = p384::shared_secret(key, p384::public_key::parse(peer_bytes).unwrap());
    if (!z.is_ok() || !std::equal(expected_z.begin(), expected_z.end(), z.unwrap().reveal().begin())) {
        std::fprintf(stderr, "ecdh_benchmark (P-384): Wycheproof tcId 1 does not reproduce; refusing to time a wrong implementation\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

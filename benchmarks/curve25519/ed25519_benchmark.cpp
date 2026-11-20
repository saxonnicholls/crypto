//
//  ed25519_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Ed25519: key pair from seed, sign, verify; and the constant-time base multiplication beside the variable-time one
// used by verification. Refuses to run unless RFC 8032 TEST 2 reproduces.
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <array>
#include <cstdio>

namespace {

namespace ed25519 = snicholls::crypto::ed25519;
namespace c25519 = snicholls::crypto::curve25519;
using snicholls::crypto::test::hex;

constexpr auto seed = hex<32>("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
constexpr std::array<std::uint8_t, 1> message{0x72};
constexpr auto expected = hex<64>("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                                  "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

void Ed25519KeyPairFromSeed(benchmark::State& state)
{
    for (auto _ : state) {
        auto kp = ed25519::key_pair::from_seed(seed);
        auto pk = kp.public_key();
        benchmark::DoNotOptimize(pk);
    }
}
BENCHMARK(Ed25519KeyPairFromSeed);

void Ed25519Sign(benchmark::State& state)
{
    const auto kp = ed25519::key_pair::from_seed(seed);
    for (auto _ : state)
        benchmark::DoNotOptimize(kp.sign(message));
}
BENCHMARK(Ed25519Sign);

void Ed25519Verify(benchmark::State& state)
{
    const auto kp = ed25519::key_pair::from_seed(seed);
    const auto sig = kp.sign(message);
    for (auto _ : state)
        benchmark::DoNotOptimize(ed25519::verify(kp.public_key(), message, sig));
}
BENCHMARK(Ed25519Verify);

// The same multiplication, constant time (signing) and variable time (verification's form)
void Edwards25519MulBaseConstantTime(benchmark::State& state)
{
    const auto k = c25519::scalar::reduce(std::array<std::uint8_t, 64>{0x5a, 0x17, 0xc3});
    for (auto _ : state)
        benchmark::DoNotOptimize(c25519::point::mul_base(k));
}
BENCHMARK(Edwards25519MulBaseConstantTime);

void Edwards25519MulPublicVariableTime(benchmark::State& state)
{
    const auto k = c25519::scalar::reduce(std::array<std::uint8_t, 64>{0x5a, 0x17, 0xc3});
    for (auto _ : state)
        benchmark::DoNotOptimize(c25519::point::mul_public(k.to_bytes(), c25519::point::base()));
}
BENCHMARK(Edwards25519MulPublicVariableTime);

} // namespace

int main(int argc, char** argv)
{
    const auto kp = ed25519::key_pair::from_seed(seed);
    const auto sig = kp.sign(message);
    if (sig.bytes != expected || !ed25519::verify(kp.public_key(), message, sig).is_ok()) {
        std::fprintf(stderr, "ed25519_benchmark: RFC 8032 TEST 2 does not reproduce; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

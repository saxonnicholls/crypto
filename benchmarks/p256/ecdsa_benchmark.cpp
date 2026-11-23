//
//  ecdsa_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ECDSA on P-256: the public key (constant time), signing (constant time, RFC 6979) and verification (variable time).
// Refuses to run unless RFC 6979 appendix A.2.5's "sample" signature reproduces.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/p256/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>

namespace {

namespace p256 = snicholls::crypto::p256;
using snicholls::crypto::test::hex;

constexpr auto key_bytes = hex<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
constexpr auto expected_r = hex<32>("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");

std::array<std::uint8_t, 32> sample_hash()
{
    snicholls::crypto::detail::sha256 h;
    h.update(std::string_view("sample"));
    return h.finish();
}

void P256PublicKey(benchmark::State& state)
{
    const auto key = p256::private_key::from_bytes(key_bytes).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(key.public_key());
}
BENCHMARK(P256PublicKey);

void P256Sign(benchmark::State& state)
{
    const auto key = p256::private_key::from_bytes(key_bytes).unwrap();
    const auto h = sample_hash();
    for (auto _ : state)
        benchmark::DoNotOptimize(p256::sign(key, h));
}
BENCHMARK(P256Sign);

void P256Verify(benchmark::State& state)
{
    const auto key = p256::private_key::from_bytes(key_bytes).unwrap();
    const auto pub = key.public_key();
    const auto h = sample_hash();
    const auto sig = p256::sign(key, h);
    for (auto _ : state)
        benchmark::DoNotOptimize(p256::verify(pub, h, sig));
}
BENCHMARK(P256Verify);

} // namespace

int main(int argc, char** argv)
{
    const auto key = p256::private_key::from_bytes(key_bytes).unwrap();
    if (p256::sign(key, sample_hash()).r != expected_r) {
        std::fprintf(stderr, "ecdsa_benchmark (P-256): RFC 6979's signature does not reproduce; refusing to time a wrong implementation\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

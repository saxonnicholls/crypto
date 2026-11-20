//
//  x25519_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// X25519: public key from secret and the shared secret (one Montgomery ladder each). Refuses to run unless RFC 7748
// section 6.1 reproduces.
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>

namespace {

namespace x25519 = snicholls::crypto::x25519;
using snicholls::crypto::secret_bytes;
using snicholls::crypto::test::hex;

constexpr auto alice = hex<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
constexpr auto bob_public = hex<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
constexpr auto expected = hex<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

void X25519PublicKey(benchmark::State& state)
{
    const secret_bytes<32> secret(alice);
    for (auto _ : state)
        benchmark::DoNotOptimize(x25519::public_key_from_secret(secret));
}
BENCHMARK(X25519PublicKey);

void X25519SharedSecret(benchmark::State& state)
{
    const secret_bytes<32> secret(alice);
    const x25519::public_key peer{bob_public};
    for (auto _ : state) {
        auto k = x25519::shared_secret(secret, peer);
        benchmark::DoNotOptimize(k);
    }
}
BENCHMARK(X25519SharedSecret);

} // namespace

int main(int argc, char** argv)
{
    const secret_bytes<32> secret(alice);
    auto k = x25519::shared_secret(secret, x25519::public_key{bob_public});
    if (!k.is_ok() || k.unwrap().reveal()[0] != expected[0] || !(k.unwrap() == secret_bytes<32>(expected))) {
        std::fprintf(stderr, "x25519_benchmark: RFC 7748 section 6.1 does not reproduce; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

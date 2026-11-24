//
//  ecdh_es_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// JOSE's ECDH-ES (constant time): the Concat KDF alone (16, 32 and 64 bytes), and the whole agreement on X25519 and
// P-256. Refuses to run unless RFC 7518 appendix C's key reproduces.
#include <snicholls/crypto/jose/ecdh_es.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <algorithm>
#include <array>
#include <cstdio>

namespace {

using namespace snicholls::crypto;
using snicholls::crypto::test::hex;

constexpr auto alice_bytes = hex<32>("d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a");
constexpr auto bob_bytes = hex<32>("5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc");
constexpr auto z = hex<32>("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");
constexpr auto expected = hex<16>("56aa8deaf8236d205c2228cd71a7101a");
constexpr std::array<std::uint8_t, 5> apu{'A', 'l', 'i', 'c', 'e'};
constexpr std::array<std::uint8_t, 3> apv{'B', 'o', 'b'};

template <std::size_t N>
void JoseConcatKdf(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(jose::ecdh_es_kdf<N>(z, "A256GCM", apu, apv));
}
BENCHMARK(JoseConcatKdf<16>);
BENCHMARK(JoseConcatKdf<32>);
BENCHMARK(JoseConcatKdf<64>);

void JoseEcdhEsX25519(benchmark::State& state)
{
    const secret_bytes<32> s(alice_bytes);
    const auto peer = x25519::public_key_from_secret(secret_bytes<32>(bob_bytes));
    for (auto _ : state)
        benchmark::DoNotOptimize(jose::ecdh_es_x25519<32>(s, peer, "ECDH-ES+A256KW"));
}
BENCHMARK(JoseEcdhEsX25519);

void JoseEcdhEsP256(benchmark::State& state)
{
    const auto key = p256::private_key::from_bytes(alice_bytes).unwrap();
    const auto peer = p256::private_key::from_bytes(bob_bytes).unwrap().public_key();
    for (auto _ : state)
        benchmark::DoNotOptimize(jose::ecdh_es_p256<32>(key, peer, "ECDH-ES+A256KW"));
}
BENCHMARK(JoseEcdhEsP256);

} // namespace

int main(int argc, char** argv)
{
    const auto bob = p256::private_key::from_bytes(bob_bytes).unwrap();
    const auto epk = p256::private_key::from_bytes(alice_bytes).unwrap().public_key();
    const auto k = jose::ecdh_es_p256<16>(bob, epk, "A128GCM", apu, apv);
    if (!k.is_ok() || !std::equal(expected.begin(), expected.end(), k.unwrap().reveal().begin())) {
        std::fprintf(stderr, "ecdh_es_benchmark: RFC 7518 appendix C's key does not reproduce; refusing to time a wrong implementation\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

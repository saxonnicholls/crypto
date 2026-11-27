//
//  ecdsa_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ECDSA on P-384: the public key (constant time) and verification (variable time). Refuses to run unless RFC 6979
// appendix A.2.6's public key reproduces and its SHA-384 "sample" signature verifies.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/p384/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>

namespace {

namespace p384 = snicholls::crypto::p384;
using snicholls::crypto::test::hex;

constexpr auto key_bytes = hex<48>("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5");
constexpr auto expected_x = hex<48>("ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13");
const p384::signature sample{hex<48>("94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46"),
                             hex<48>("99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8")};

std::array<std::uint8_t, 48> sample_hash()
{
    snicholls::crypto::detail::sha384 h;
    h.update(std::string_view("sample"));
    return h.finish();
}

void P384PublicKey(benchmark::State& state)
{
    const auto key = p384::private_key::from_bytes(key_bytes).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(key.public_key());
}
BENCHMARK(P384PublicKey);

void P384Verify(benchmark::State& state)
{
    const auto pub = p384::private_key::from_bytes(key_bytes).unwrap().public_key();
    const auto h = sample_hash();
    for (auto _ : state)
        benchmark::DoNotOptimize(p384::verify(pub, h, sample));
}
BENCHMARK(P384Verify);

} // namespace

int main(int argc, char** argv)
{
    const auto pub = p384::private_key::from_bytes(key_bytes).unwrap().public_key();
    if (pub.point().x.to_bytes() != expected_x || !p384::verify(pub, sample_hash(), sample)) {
        std::fprintf(stderr, "ecdsa_benchmark (P-384): RFC 6979 A.2.6 does not reproduce; refusing to time a wrong implementation\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

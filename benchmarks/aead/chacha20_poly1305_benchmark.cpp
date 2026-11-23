//
//  chacha20_poly1305_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// ChaCha20-Poly1305 and XChaCha20-Poly1305 seal and open, at 64 bytes (a cookie) and 16 KiB. Refuses to run unless
// RFC 8439 section 2.8.2's tag reproduces.
#include <snicholls/crypto/aead/chacha20_poly1305.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>
#include <string_view>
#include <vector>

namespace {

namespace aead = snicholls::crypto::aead;
using snicholls::crypto::test::hex;

constexpr auto key = hex<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

void AeadChaCha20Poly1305Seal(benchmark::State& state)
{
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(state.range(0)), 7);
    for (auto _ : state)
        benchmark::DoNotOptimize(aead::chacha20_poly1305_seal(key, hex<12>("070000004041424344454647"), {}, buf, buf));
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(AeadChaCha20Poly1305Seal)->Arg(64)->Arg(16384);

void AeadXChaCha20Poly1305Open(benchmark::State& state)
{
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(state.range(0)), 7), out(buf.size());
    const auto nonce = hex<24>("404142434445464748494a4b4c4d4e4f5051525354555657");
    const auto tag = aead::xchacha20_poly1305_seal(key, nonce, {}, buf, buf).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(aead::xchacha20_poly1305_open(key, nonce, {}, buf, tag, out));
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(AeadXChaCha20Poly1305Open)->Arg(64)->Arg(16384);

} // namespace

int main(int argc, char** argv)
{
    constexpr std::string_view s = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::vector<std::uint8_t> pt(s.begin(), s.end()), ct(pt.size());
    const auto tag = aead::chacha20_poly1305_seal(key, hex<12>("070000004041424344454647"), hex<12>("50515253c0c1c2c3c4c5c6c7"), pt, ct);
    if (!tag || *tag != hex<16>("1ae10b594f09e26a7e902ecbd0600691")) {
        std::fprintf(stderr, "chacha20_poly1305_benchmark: RFC 8439's tag does not reproduce; refusing to time a wrong implementation\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

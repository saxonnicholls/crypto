//
//  mnemonic_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// BIP-39: entropy to words, words (text) to a verified mnemonic, and the seed. Each is checked against Trezor's
// vector for 32 bytes of 0x7f before anything is timed; the benchmark refuses to run if it disagrees.
#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <array>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

namespace bip39 = snicholls::crypto::bip39;

const std::array<std::uint8_t, 32> entropy = [] {
    std::array<std::uint8_t, 32> e{};
    e.fill(0x7f);
    return e;
}();
constexpr std::string_view words =
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner "
    "thank year wave sausage worth title";
constexpr std::string_view seed_hex =
    "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87";

bool vector_agrees()
{
    const auto m = bip39::from_entropy(entropy);
    std::array<char, bip39::max_text_length> text{};
    const std::size_t n = m->to_text(text);
    const auto p = bip39::parse(words);
    const auto seed = bip39::to_seed(*p, "TREZOR");
    return std::string_view(text.data(), n) == words && p && *p == *m &&
           snicholls::crypto::test::to_hex(seed->reveal()) == seed_hex;
}

void EntropyToText(benchmark::State& state)
{
    std::array<char, bip39::max_text_length> text{};
    for (auto _ : state) {
        auto m = bip39::from_entropy(entropy);
        benchmark::DoNotOptimize(m->to_text(text));
        benchmark::DoNotOptimize(text.data());
    }
}
BENCHMARK(EntropyToText);

void ParseText(benchmark::State& state)
{
    for (auto _ : state) {
        auto m = bip39::parse(words);
        benchmark::DoNotOptimize(m.is_ok());
    }
}
BENCHMARK(ParseText);

void MnemonicToSeed(benchmark::State& state)
{
    const auto m = bip39::parse(words);
    for (auto _ : state) {
        auto seed = bip39::to_seed(*m, "TREZOR");
        benchmark::DoNotOptimize(seed->reveal().data());
    }
}
BENCHMARK(MnemonicToSeed)->Unit(benchmark::kMillisecond);

} // namespace

int main(int argc, char** argv)
{
    if (!vector_agrees()) {
        std::fprintf(stderr, "mnemonic_benchmark: Trezor's vector does not agree; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

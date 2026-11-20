//
//  base58_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// Base58 and base58check: a 25-byte address and an 82-byte extended key (78 + 4), encode and decode. Before timing,
// the address of private key 1 and BIP-32 vector 1's master key must reproduce, or nothing is timed.
#include <snicholls/crypto/address/base58.hpp>
#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

namespace a = snicholls::crypto::address;

constexpr auto address_payload = snicholls::crypto::test::hex<21>("00751e76e8199196d454941c45d1b3a323f1433bd6");
constexpr std::string_view address_text = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
constexpr std::string_view xprv =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

void Base58EncodeAddress(benchmark::State& state)
{
    std::array<std::uint8_t, 25> full{};
    for (std::size_t i = 0; i < 21; ++i)
        full[i] = address_payload[i];
    for (auto _ : state)
        benchmark::DoNotOptimize(a::base58_encode(full));
}
BENCHMARK(Base58EncodeAddress);

void Base58DecodeAddress(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::base58_decode(address_text));
}
BENCHMARK(Base58DecodeAddress);

void Base58checkEncodeAddress(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::base58check_encode_exact(address_payload));
}
BENCHMARK(Base58checkEncodeAddress);

void Base58checkDecodeAddress(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::base58check_decode_exact<21>(address_text));
}
BENCHMARK(Base58checkDecodeAddress);

void Base58checkEncodeExtendedKey(benchmark::State& state)
{
    const auto payload = *a::base58check_decode_exact<78>(xprv);
    for (auto _ : state)
        benchmark::DoNotOptimize(a::base58check_encode_exact(payload));
}
BENCHMARK(Base58checkEncodeExtendedKey);

void Base58checkDecodeExtendedKey(benchmark::State& state)
{
    for (auto _ : state)
        benchmark::DoNotOptimize(a::base58check_decode_exact<78>(xprv));
}
BENCHMARK(Base58checkDecodeExtendedKey);

} // namespace

int main(int argc, char** argv)
{
    const auto t = a::base58check_encode_exact(address_payload);
    const auto x = a::base58check_decode_exact<78>(xprv);
    const bool ok = std::string_view(t.data(), t.size()) == address_text && x &&
                    [&] {
                        const auto again = a::base58check_encode_exact(*x);
                        return std::string_view(again.data(), again.size()) == xprv;
                    }();
    if (!ok) {
        std::fprintf(stderr, "base58_benchmark: the published address or extended key does not reproduce; refusing to benchmark\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

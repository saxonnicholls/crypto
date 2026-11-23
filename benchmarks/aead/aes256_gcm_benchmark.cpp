//
//  aes256_gcm_benchmark.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// AES-256-GCM seal and open at 64 bytes (a cookie or a JWE's key) and 1 KiB, and AES-256 key wrap of a 32-byte key.
// The AES here computes its S-box (no tables, constant time), so expect it well below AES-NI. Refuses to run unless
// the GCM specification's test case 15 reproduces.
#include <snicholls/crypto/aead/aes256_gcm.hpp>
#include <snicholls/crypto/aead/aes_key_wrap.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <benchmark/benchmark.h>

#include <cstdio>
#include <vector>

namespace {

namespace aead = snicholls::crypto::aead;
using snicholls::crypto::test::hex;
using snicholls::crypto::test::hex_bytes;

constexpr auto key = hex<32>("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
constexpr auto nonce = hex<12>("cafebabefacedbaddecaf888");

void AeadAes256GcmSeal(benchmark::State& state)
{
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(state.range(0)), 7);
    for (auto _ : state)
        benchmark::DoNotOptimize(aead::aes256_gcm_seal(key, nonce, {}, buf, buf));
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(AeadAes256GcmSeal)->Arg(64)->Arg(1024);

void AeadAes256GcmOpen(benchmark::State& state)
{
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(state.range(0)), 7), out(buf.size());
    const auto tag = aead::aes256_gcm_seal(key, nonce, {}, buf, buf).unwrap();
    for (auto _ : state)
        benchmark::DoNotOptimize(aead::aes256_gcm_open(key, nonce, {}, buf, tag, out));
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(AeadAes256GcmOpen)->Arg(64)->Arg(1024);

void AeadAes256KeyWrap(benchmark::State& state)
{
    std::array<std::uint8_t, 32> cek{};
    std::array<std::uint8_t, 40> wrapped{};
    for (auto _ : state)
        benchmark::DoNotOptimize(aead::aes256_key_wrap(key, cek, wrapped));
}
BENCHMARK(AeadAes256KeyWrap);

} // namespace

int main(int argc, char** argv)
{
    const auto pt = hex_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    std::vector<std::uint8_t> ct(pt.size());
    const auto tag = aead::aes256_gcm_seal(key, nonce, {}, pt, ct);
    if (!tag || *tag != hex<16>("b094dac5d93471bdec1a502270e3cc6c")) {
        std::fprintf(stderr, "aes256_gcm_benchmark: the GCM specification's test case 15 does not reproduce; refusing to time a wrong implementation\n");
        return 1;
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

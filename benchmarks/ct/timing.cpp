//
//  timing.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  An informational timing test in the style of dudect (Reparaz, Balasch, Verbauwhede, 2017): each secret
//  operation runs on two classes of secret, one fixed and one fresh at random, interleaved in a random order;
//  Welch's t statistic compares the two timing distributions, after cropping the slowest measurements at several
//  percentiles. |t| above 4.5 would be evidence of a leak at that sample size; a small |t| is not proof of its
//  absence (the measurements are wall-clock time on a shared machine). The Valgrind secret-marking check
//  (tests/ct/secret_marking.cpp) is the stronger evidence; this complements it on the real hardware.
//
//      snicholls_crypto_ct_timing [samples per operation, default 20000]
//
//  Exits non-zero only if an operation gives a wrong result, never on the statistic.
//

#include <snicholls/core/stats/random.hpp>
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <vector>

namespace {

struct moments {
    double n = 0, mean = 0, m2 = 0;
    void add(double x)
    {
        n += 1;
        const double d = x - mean;
        mean += d / n;
        m2 += d * (x - mean);
    }
    double variance() const { return n > 1 ? m2 / (n - 1) : 0; }
};

double welch_t(const moments& a, const moments& b)
{
    const double se = std::sqrt(a.variance() / a.n + b.variance() / b.n);
    return se > 0 ? (a.mean - b.mean) / se : 0;
}

// Runs op(secret) on the two classes; returns the largest |t| over the croppings
double measure(const char* name, std::size_t samples, const std::function<void(const std::array<std::uint8_t, 32>&)>& op)
{
    snicholls::stats::wyrand rng(0x5eed0000 + samples);
    std::array<std::uint8_t, 32> fixed{};
    fixed[31] = 1;   // a low-weight key: the classic worst case for a leaky ladder
    std::vector<std::array<std::uint8_t, 32>> inputs(samples);
    std::vector<int> cls(samples);
    for (std::size_t i = 0; i < samples; ++i) {
        cls[i] = static_cast<int>(rng() & 1);
        if (cls[i] == 0) {
            inputs[i] = fixed;
        } else {
            for (std::size_t j = 0; j < 32; j += 8) {
                const std::uint64_t r = rng();
                for (std::size_t b = 0; b < 8; ++b)
                    inputs[i][j + b] = static_cast<std::uint8_t>(r >> (8 * b));
            }
            inputs[i][0] &= 0x7f;   // below every group order used here
            inputs[i][31] |= 1;     // never zero
        }
    }
    for (std::size_t i = 0; i < std::min<std::size_t>(samples, 200); ++i)   // warm up
        op(inputs[i]);
    std::vector<double> t(samples);
    for (std::size_t i = 0; i < samples; ++i) {
        const auto start = std::chrono::steady_clock::now();
        op(inputs[i]);
        const auto stop = std::chrono::steady_clock::now();
        t[i] = std::chrono::duration<double, std::nano>(stop - start).count();
    }
    std::vector<double> sorted = t;
    std::sort(sorted.begin(), sorted.end());
    double worst = 0;
    std::printf("%-28s", name);
    for (const double pct : {1.0, 0.99, 0.9, 0.5}) {
        const double cut = sorted[static_cast<std::size_t>(pct * static_cast<double>(samples - 1))];
        moments a, b;
        for (std::size_t i = 0; i < samples; ++i)
            if (t[i] <= cut)
                (cls[i] == 0 ? a : b).add(t[i]);
        const double v = welch_t(a, b);
        worst = std::max(worst, std::fabs(v));
        std::printf("  |t|<=p%-3.0f %6.2f", pct * 100, std::fabs(v));
    }
    std::printf("   median %.1f us   %s\n", sorted[samples / 2] / 1000, worst > 4.5 ? "LOOK AT THIS" : "no evidence of a leak");
    return worst;
}

} // namespace

int main(int argc, char** argv)
{
    using namespace snicholls::crypto;
    const std::size_t samples = argc > 1 ? static_cast<std::size_t>(std::strtoull(argv[1], nullptr, 10)) : 20000;
    std::printf("dudect-style timing, %zu samples per operation, fixed against random secrets\n", samples);
    const std::array<std::uint8_t, 32> hash{0x11, 0x22};
    volatile std::uint8_t sink = 0;
    bool wrong = false;

    measure("secp256k1 public key", samples, [&](const auto& k) { sink = sink ^ secp256k1::private_key::from_bytes(k).unwrap().public_key().compressed()[1]; });
    measure("ECDSA sign", samples, [&](const auto& k) { sink = sink ^ secp256k1::sign(secp256k1::private_key::from_bytes(k).unwrap(), hash).sig.r[0]; });
    measure("Ed25519 sign", samples, [&](const auto& k) { sink = sink ^ ed25519::key_pair::from_seed(std::span<const std::uint8_t, 32>(k)).sign(hash).bytes[0]; });
    const x25519::public_key peer = x25519::public_key_from_secret(secret_bytes<32>(std::span<const std::uint8_t, 32>(hash)));
    measure("X25519 shared secret", samples, [&](const auto& k) {
        const auto s = x25519::shared_secret(secret_bytes<32>(std::span<const std::uint8_t, 32>(k)), peer);
        if (!s) wrong = true;
        else sink = sink ^ s->reveal()[0];
    });
    measure("BIP-32 hardened child", samples, [&](const auto& k) {
        std::array<std::uint8_t, 64> seed{};
        std::copy(k.begin(), k.end(), seed.begin());
        sink = sink ^ hd::extended_private_key::from_seed(seed).unwrap().derive_child(hd::hardened(0)).unwrap().chain_code()[0];
    });
    return wrong ? 1 : 0;
}

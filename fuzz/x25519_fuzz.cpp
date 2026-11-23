//
//  x25519_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of X25519 against libsodium and OpenSSL: arbitrary scalars, and u-coordinates that are
//  arbitrary, small-order, at or above p, or with bit 255 set. All three refuse the all-zero result.
//
#include "support/fuzz_support.hpp"
#include "support/openssl_oracle.hpp"

#include <snicholls/crypto/curve25519/x25519.hpp>

#include <sodium.h>

namespace f = snicholls::crypto::fuzz;
using namespace snicholls::crypto::x25519;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("x25519", data, size);
    static const bool ready = sodium_init() >= 0;
    (void)ready;
    f::input in(data, size);
    const std::uint8_t mode = in.byte();
    const auto k = in.take<32>();
    auto u = in.take<32>();
    if (mode & 1)
        u = f::curve25519_small_order(in.byte());   // as u-coordinates these are small-order or arbitrary
    if (mode & 2) {   // u + p, where it fits
        unsigned carry = 0;
        static constexpr std::uint8_t p[32] = {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
        u[31] &= 0x7f;
        for (int i = 0; i < 32; ++i) {
            const unsigned t = u[i] + p[i] + carry;
            u[i] = static_cast<std::uint8_t>(t);
            carry = t >> 8;
        }
    }
    if (mode & 4)
        u[31] |= 0x80;
    const snicholls::crypto::secret_bytes<32> secret(k);
    const auto ours = shared_secret(secret, public_key{u});
    std::array<std::uint8_t, 32> lib{};
    const bool s = crypto_scalarmult(lib.data(), k.data(), u.data()) == 0;
    const auto ossl = f::openssl::x25519(k, u);
    const std::string c = f::hex(k) + " " + f::hex(u);
    auto same = [&](const std::array<std::uint8_t, 32>& x) { return std::equal(x.begin(), x.end(), ours->reveal().begin()); };
    if (static_cast<bool>(ours) != s || (s && !same(lib)))
        f::divergence("x25519", "libsodium: " + c);
    if (static_cast<bool>(ours) != static_cast<bool>(ossl) || (ossl && !same(*ossl)))
        f::divergence("x25519", "OpenSSL: " + c);
    return 0;
}

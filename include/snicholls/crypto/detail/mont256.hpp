//
//  mont256.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Arithmetic modulo a 256-bit odd modulus in Montgomery form, on four 64-bit limbs, for moduli that are not of the
//  form 2^256 - c with a small c (P-256's p and n). Values are kept fully reduced, below m, as a R mod m with
//  R = 2^256. The names of detail/mont.hpp's N-limb arithmetic at N = 4: one implementation, shared with P-384.
//
//  Constant time throughout: every loop has a fixed trip count, the final subtraction of each operation is selected
//  by a mask, never a branch, and the exponentiations take a public exponent (Fermat's inverse, the square root).
//  constexpr throughout; the 64 x 64 -> 128 multiply is core's.
//

#ifndef snicholls_crypto_detail_mont256_hpp
#define snicholls_crypto_detail_mont256_hpp

#include <snicholls/crypto/detail/limbs.hpp>
#include <snicholls/crypto/detail/mont.hpp>

#include <cstdint>

namespace snicholls::crypto::detail {

using mont256_params = mont_params<4>;

constexpr mont256_params make_mont256(const limbs4& m) noexcept { return make_mont<4>(m); }

constexpr limbs4 mont256_reduce_once(const limbs4& a, std::uint64_t carry, const limbs4& m) noexcept
{
    return mont_reduce_once<4>(a, carry, m);
}

constexpr limbs4 mont256_mul(const limbs4& a, const limbs4& b, const mont256_params& p) noexcept { return mont_mul<4>(a, b, p); }

constexpr limbs4 mont256_add(const limbs4& a, const limbs4& b, const mont256_params& p) noexcept { return mont_add<4>(a, b, p); }

constexpr limbs4 mont256_sub(const limbs4& a, const limbs4& b, const mont256_params& p) noexcept { return mont_sub<4>(a, b, p); }

constexpr limbs4 mont256_to(const limbs4& a, const mont256_params& p) noexcept { return mont_to<4>(a, p); }

constexpr limbs4 mont256_from(const limbs4& a, const mont256_params& p) noexcept { return mont_from<4>(a, p); }

// a^e for a public exponent e: square and multiply, every bit squared
constexpr limbs4 mont256_pow(const limbs4& a, const limbs4& e, const mont256_params& p) noexcept { return mont_pow<4>(a, e, p); }

} // namespace snicholls::crypto::detail

#endif /* snicholls_crypto_detail_mont256_hpp */

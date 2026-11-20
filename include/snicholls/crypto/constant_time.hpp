//
//  constant_time.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `snicholls::crypto::ct`: masks, selection, swaps and comparisons whose timing does not depend on the data.
/// \ingroup crypto
///
/// \overview
/// The building blocks of every secret-dependent computation in the library. A condition on secret data is never
/// a branch or an index: it becomes a mask (all ones or all zeros) and the two candidate results are combined with
/// it. `value_barrier` hides a value from the optimiser at run time, so it cannot prove a mask is 0 or 1 and turn
/// the selection back into a branch, which compilers do.
///
/// Use these for anything that touches a private key, a nonce, a seed or an intermediate derived from one. Data that
/// is public (a signature being verified, a public key) may use ordinary code.
///
/// \relations
/// - `secret.hpp`: the buffer that holds secrets and wipes them.
/// - Every field and scalar type in `secp256k1/` and `curve25519/` is built on these.
/// - Group: \ref crypto.
///
/// \impls
/// One. The barrier is an empty `asm` with the value as an in-out register operand on GCC and Clang, and a
/// `volatile` round trip elsewhere (MSVC). In a constant expression it is the identity.
///
/// \contracts
/// Every function is `constexpr` and `noexcept`. Timing depends only on the sizes of the arguments, never on their
/// values. That is a property of the source and of the compilers the library is tested with (see "Known issues").
///
/// \errors
/// None.
///
/// \examples
/// \snippet constant_time_demo.cpp ct
///
/// \perf
/// Not benchmarked on its own: a handful of instructions each; the curve benchmarks measure them in use.
///
/// \testing
/// `tests/constant_time_test.cpp`, `demos/constant_time_demo.cpp`. The secret-marking check
/// (`tests/ct/secret_marking.cpp`, run under Valgrind in `make ubuntu`) runs the signing and derivation paths with
/// the secret inputs marked undefined, so a branch or an index on them is reported.
///
/// \deps
/// `<cstddef>`, `<cstdint>`, `<span>`, `<type_traits>`.
///
/// \gotchas
/// Constant time in C++ is a property no standard promises: a compiler may still emit a branch. The barrier and the
/// mask style defeat the transformations GCC and Clang are known to make; the Valgrind check is the evidence for the
/// built binaries, and only for the compilers and flags it ran with.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_constant_time_hpp
#define snicholls_crypto_constant_time_hpp

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

/// \brief Constant-time primitives.
namespace snicholls::crypto::ct {

/// \brief Returns `x` unchanged, but opaque to the optimiser at run time.
/// \tparam T An unsigned integer type.
/// \param x The value.
/// \return `x`.
template <class T>
    requires std::is_unsigned_v<T>
[[nodiscard]] constexpr T value_barrier(T x) noexcept
{
    if (std::is_constant_evaluated())
        return x;
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(x));
    return x;
#else
    volatile T v = x;
    return v;
#endif
}

/// \brief All ones if `bit` is 1, zero if it is 0.
/// \pre `bit` is 0 or 1.
/// \param bit The condition as a number.
/// \return The mask.
[[nodiscard]] constexpr std::uint64_t mask_from_bit(std::uint64_t bit) noexcept
{
    return std::uint64_t{0} - value_barrier(bit);
}

/// \brief All ones if `x` is zero, zero otherwise.
/// \param x The value.
/// \return The mask.
[[nodiscard]] constexpr std::uint64_t mask_is_zero(std::uint64_t x) noexcept
{
    // (x | -x) has its top bit set exactly when x is not zero
    const std::uint64_t nz = (x | (std::uint64_t{0} - x)) >> 63;
    return mask_from_bit(nz ^ 1);
}

/// \brief All ones if `a == b`, zero otherwise.
/// \param a A value.
/// \param b Another value.
/// \return The mask.
[[nodiscard]] constexpr std::uint64_t mask_equal(std::uint64_t a, std::uint64_t b) noexcept { return mask_is_zero(a ^ b); }

/// \brief All ones if `a < b` (unsigned), zero otherwise.
/// \param a A value.
/// \param b Another value.
/// \return The mask.
[[nodiscard]] constexpr std::uint64_t mask_less(std::uint64_t a, std::uint64_t b) noexcept
{
    // The borrow out of a - b, computed without a comparison
    const std::uint64_t borrow = ((~a & b) | ((~a | b) & (a - b))) >> 63;
    return mask_from_bit(borrow);
}

/// \brief `a` where `mask` is all ones, `b` where it is zero.
/// \tparam T An unsigned integer type.
/// \param mask All ones or zero.
/// \param a The value chosen by all ones.
/// \param b The value chosen by zero.
/// \return The selection.
template <class T>
    requires std::is_unsigned_v<T>
[[nodiscard]] constexpr T select(std::uint64_t mask, T a, T b) noexcept
{
    const T m = static_cast<T>(value_barrier(mask));
    return static_cast<T>(b ^ (m & (a ^ b)));
}

/// \brief Swaps `a` and `b` where `mask` is all ones; leaves them where it is zero.
/// \tparam T An unsigned integer type.
/// \param mask All ones or zero.
/// \param a A value.
/// \param b Another value.
template <class T>
    requires std::is_unsigned_v<T>
constexpr void conditional_swap(std::uint64_t mask, T& a, T& b) noexcept
{
    const T m = static_cast<T>(value_barrier(mask));
    const T t = static_cast<T>(m & (a ^ b));
    a = static_cast<T>(a ^ t);
    b = static_cast<T>(b ^ t);
}

/// \brief Whether two byte ranges hold the same bytes; the time depends on the lengths only.
/// \param a A range.
/// \param b Another range.
/// \return `true` if the lengths and every byte agree. Unequal lengths are unequal (lengths are not secret).
[[nodiscard]] constexpr bool equal(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) noexcept
{
    if (a.size() != b.size())
        return false;
    std::uint64_t acc = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        acc |= static_cast<std::uint64_t>(a[i] ^ b[i]);
    return mask_is_zero(acc) != 0;
}

/// \brief Whether every byte is zero; the time depends on the length only.
/// \param a The range.
/// \return `true` for an all-zero (or empty) range.
[[nodiscard]] constexpr bool is_zero(std::span<const std::uint8_t> a) noexcept
{
    std::uint64_t acc = 0;
    for (const std::uint8_t x : a)
        acc |= x;
    return mask_is_zero(acc) != 0;
}

/// \brief Copies `src` over `dst` where `mask` is all ones; leaves `dst` where it is zero.
/// \pre `dst.size() == src.size()`.
/// \param mask All ones or zero.
/// \param dst The destination.
/// \param src The source.
constexpr void conditional_copy(std::uint64_t mask, std::span<std::uint8_t> dst, std::span<const std::uint8_t> src) noexcept
{
    const auto m = static_cast<std::uint8_t>(value_barrier(mask));
    for (std::size_t i = 0; i < dst.size() && i < src.size(); ++i)
        dst[i] = static_cast<std::uint8_t>(dst[i] ^ (m & (dst[i] ^ src[i])));
}

} // namespace snicholls::crypto::ct

#endif /* snicholls_crypto_constant_time_hpp */

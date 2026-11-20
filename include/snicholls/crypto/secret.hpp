//
//  secret.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `secret_bytes<N>`: a fixed-size buffer for key material that is wiped when it dies, and `secure_wipe`.
/// \ingroup crypto
///
/// \overview
/// Private keys, seeds, chain codes, nonces and every intermediate derived from them live in a `secret_bytes<N>`. It
/// owns N bytes inline (no allocation), zeroes them in its destructor with writes the optimiser may not remove, and
/// makes copying explicit: the copy constructor is deleted, `clone()` is the one way to a second copy, and a move
/// wipes the source. The bytes are reached through `reveal()`, as core's `snicholls::secret`, so every use of key
/// material is easy to find.
///
/// Use it for anything that would let an attacker sign, derive or decrypt. Do not use it for public data: a public
/// key or a signature is a plain `std::array`.
///
/// \relations
/// - `snicholls::secret<T>` (core): the masking wrapper for secrets in configuration and logs; this is its
///   cryptographic counterpart, fixed-size and wiped.
/// - `constant_time.hpp`: comparisons on secrets.
/// - Group: \ref crypto.
///
/// \impls
/// One. `secure_wipe` writes through a `volatile` pointer and ends with a compiler barrier; in a constant expression it
/// is a plain fill.
///
/// \contracts
/// - Not thread-safe (a value type). Every member is `noexcept`; construction and destruction are `constexpr`.
/// - The destructor wipes; a moved-from buffer is all zeros.
/// - It is not printable: no `operator<<`, no `print`, so `acout` and `print_to` refuse it at compile time.
/// - Equality is constant-time (`ct::equal`).
///
/// \errors
/// None.
///
/// \examples
/// \snippet secret_demo.cpp secret
///
/// \perf
/// Not benchmarked: a wipe is N byte stores.
///
/// \testing
/// `tests/secret_test.cpp`, `demos/secret_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstddef>`, `<cstdint>`, `<span>`, `<type_traits>`.
///
/// \gotchas
/// Wiping cannot reach copies the program never sees: registers, spilled stack slots in callees, pages the operating
/// system swapped out, and copies the caller made before handing the bytes over. Lock the memory and disable core
/// dumps in the program if those matter; that needs the operating system and is outside this library.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secret_hpp
#define snicholls_crypto_secret_hpp

#include <snicholls/crypto/constant_time.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace snicholls::crypto {

/// \brief Zeroes `n` bytes at `p` in a way the optimiser may not remove.
/// \param p The first byte.
/// \param n The number of bytes.
inline void secure_wipe(void* p, std::size_t n) noexcept
{
    volatile auto* q = static_cast<volatile std::uint8_t*>(p);
    while (n--)
        *q++ = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/// \brief Zeroes a trivially copyable object in place, also in a constant expression.
/// \tparam T A trivially copyable type (an array of limbs, a struct of them).
/// \param x The object.
template <class T>
    requires std::is_trivially_copyable_v<T>
constexpr void secure_wipe(T& x) noexcept
{
    if (std::is_constant_evaluated())
        x = T{};
    else
        secure_wipe(static_cast<void*>(&x), sizeof x);
}

/// \brief N bytes of key material: inline, wiped on destruction, copied only on request.
/// \ingroup crypto
/// \tparam N The number of bytes.
///
/// \overview
/// See the file description. A move wipes the source; `clone()` makes an explicit copy.
///
/// \contracts
/// `noexcept` and `constexpr` throughout. The layout is exactly `std::array<std::uint8_t, N>`.
template <std::size_t N>
class secret_bytes {
public:
    /// \brief The number of bytes.
    static constexpr std::size_t size_bytes = N;

    /// \brief All zeros.
    constexpr secret_bytes() noexcept = default;

    /// \brief A copy of `bytes`; the caller still owns, and should wipe, the original.
    /// \param bytes Exactly N bytes.
    constexpr explicit secret_bytes(std::span<const std::uint8_t, N> bytes) noexcept
    {
        for (std::size_t i = 0; i < N; ++i)
            bytes_[i] = bytes[i];
    }

    /// \brief Takes the bytes of `bytes` and wipes it.
    /// \param bytes The source array, zero afterwards.
    constexpr explicit secret_bytes(std::array<std::uint8_t, N>&& bytes) noexcept : bytes_(bytes)
    {
        secure_wipe(bytes);
    }

    secret_bytes(const secret_bytes&) = delete;
    secret_bytes& operator=(const secret_bytes&) = delete;

    /// \brief Takes the bytes of `other` and wipes it.
    /// \param other The source, zero afterwards.
    constexpr secret_bytes(secret_bytes&& other) noexcept : bytes_(other.bytes_) { secure_wipe(other.bytes_); }

    /// \brief Wipes this, takes the bytes of `other` and wipes it.
    /// \param other The source, zero afterwards.
    /// \return `*this`.
    constexpr secret_bytes& operator=(secret_bytes&& other) noexcept
    {
        if (this != &other) {
            bytes_ = other.bytes_;
            secure_wipe(other.bytes_);
        }
        return *this;
    }

    /// \brief Wipes the bytes.
    constexpr ~secret_bytes() { secure_wipe(bytes_); }

    /// \brief An explicit second copy.
    /// \return A buffer with the same bytes.
    [[nodiscard]] constexpr secret_bytes clone() const noexcept { return secret_bytes(std::span<const std::uint8_t, N>(bytes_)); }

    /// \brief The bytes, read-only. The one way to the key material; easy to grep for.
    /// \return A view valid while this buffer lives.
    [[nodiscard]] constexpr std::span<const std::uint8_t, N> reveal() const noexcept { return bytes_; }

    /// \brief The bytes, writable, for filling in place.
    /// \return A view valid while this buffer lives.
    [[nodiscard]] constexpr std::span<std::uint8_t, N> reveal_mutable() noexcept { return bytes_; }

    /// \brief Zeroes the bytes now.
    constexpr void wipe() noexcept { secure_wipe(bytes_); }

    /// \brief Constant-time equality.
    /// \param a A buffer.
    /// \param b Another.
    /// \return Whether the bytes agree.
    [[nodiscard]] friend constexpr bool operator==(const secret_bytes& a, const secret_bytes& b) noexcept
    {
        return ct::equal(a.bytes_, b.bytes_);
    }

private:
    std::array<std::uint8_t, N> bytes_{};
};

} // namespace snicholls::crypto

#endif /* snicholls_crypto_secret_hpp */

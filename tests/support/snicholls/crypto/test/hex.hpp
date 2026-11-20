//
//  hex.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Test and demo support: hex text to bytes and back, for writing test vectors as the standards print them.
//  Test-only, and temporary: hex digits belong to snicholls-core (planned there), and this file is deleted for
//  core's codec when crypto pins a core that has one. Not installed, not part of the library.
//

#ifndef snicholls_crypto_test_hex_hpp
#define snicholls_crypto_test_hex_hpp

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace snicholls::crypto::test {

constexpr int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    throw std::invalid_argument("hex: not a hex digit");
}

// Exactly N bytes from 2N hex digits; a wrong length or a non-digit throws (at compile time, fails to compile)
template <std::size_t N>
constexpr std::array<std::uint8_t, N> hex(std::string_view s)
{
    if (s.size() != 2 * N)
        throw std::invalid_argument("hex: wrong length");
    std::array<std::uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i)
        out[i] = static_cast<std::uint8_t>(hex_value(s[2 * i]) * 16 + hex_value(s[2 * i + 1]));
    return out;
}

// Any even number of hex digits
inline std::vector<std::uint8_t> hex_bytes(std::string_view s)
{
    if (s.size() % 2 != 0)
        throw std::invalid_argument("hex: odd length");
    std::vector<std::uint8_t> out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>(hex_value(s[2 * i]) * 16 + hex_value(s[2 * i + 1]));
    return out;
}

// Lowercase hex of any bytes
inline std::string to_hex(std::span<const std::uint8_t> b)
{
    constexpr const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(2 * b.size());
    for (const std::uint8_t x : b) {
        s.push_back(digits[x >> 4]);
        s.push_back(digits[x & 0xf]);
    }
    return s;
}

// The bytes of a string, for messages given as text
inline std::span<const std::uint8_t> bytes_of(std::string_view s)
{
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

} // namespace snicholls::crypto::test

#endif /* snicholls_crypto_test_hex_hpp */

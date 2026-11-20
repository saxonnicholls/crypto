//
//  rfc6979.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `secp256k1::rfc6979`: deterministic ECDSA nonces (RFC 6979, HMAC-SHA256), for any 256-bit group order.
/// \ingroup secp256k1
///
/// \overview
/// ECDSA leaks the private key if a nonce repeats or is biased, so the nonce is derived from the key and the message
/// hash with HMAC_DRBG (RFC 6979 section 3.2), and needs no random generator. The generator yields candidates
/// k in [1, q - 1] in order; ECDSA takes the first that gives r != 0 and s != 0. Optional extra data (section 3.6,
/// what libsecp256k1 calls `ndata`) mixes 32 more bytes into the derivation, for signers that want fresh randomness
/// without giving up determinism's protection.
///
/// The group order is a parameter, so the RFC's own appendix A.2.5 vectors (P-256 with SHA-256) test it exactly; the
/// signer uses secp256k1's n.
///
/// \relations
/// - `secp256k1/ecdsa.hpp`: its user.
/// - Group: \ref secp256k1.
///
/// \impls
/// One: hlen = qlen = 256 (SHA-256, a 256-bit order), the case of every curve this library signs on.
///
/// \contracts
/// - The key, the reduced hash and the DRBG state (K, V) are secret; the state is wiped on destruction.
/// - Constant time except for one rejection test per candidate (k = 0 or k >= q), whose outcome is public in effect:
///   for secp256k1 it happens with probability below 2^-127.
/// - `constexpr`, no allocation, `noexcept`.
///
/// \errors
/// None.
///
/// \examples
/// \snippet secp256k1/rfc6979_demo.cpp rfc6979
///
/// \perf
/// Two HMACs per candidate after six for the set-up; included in the signing benchmark.
///
/// \testing
/// `tests/secp256k1/rfc6979_test.cpp`: RFC 6979 A.2.5 ("sample" and "test", P-256, SHA-256) and the secp256k1 nonces
/// widely published with libraries' test suites; `demos/secp256k1/rfc6979_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; the library's HMAC-SHA256.
///
/// \gotchas
/// The hash is reduced modulo q before use (bits2octets), as the RFC requires; passing an unreduced hash to a
/// different implementation gives a different nonce for hashes at or above q.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_secp256k1_rfc6979_hpp
#define snicholls_crypto_secp256k1_rfc6979_hpp

#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/detail/limbs.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace snicholls::crypto::secp256k1 {

/// \brief RFC 6979's HMAC_DRBG nonce generator, HMAC-SHA256, for a 256-bit group order.
/// \ingroup secp256k1
class rfc6979 {
public:
    /// \brief Seeds the generator (RFC 6979 3.2, steps b to f).
    /// \param key The private key, 32 bytes big-endian (int2octets(x)).
    /// \param hash The message hash, 32 bytes; reduced modulo `order` here (bits2octets).
    /// \param order The group order q, 32 bytes big-endian.
    /// \param extra Optional additional data (section 3.6): empty, or 32 bytes.
    constexpr rfc6979(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 32> hash,
                      std::span<const std::uint8_t, 32> order, std::span<const std::uint8_t> extra = {}) noexcept
        : q_(crypto::detail::from_be(order))
    {
        // bits2octets(h1): the hash as an integer, minus q once if it is not below q (it is below 2q)
        const auto h = crypto::detail::from_be(hash);
        crypto::detail::limbs4 t{};
        const std::uint64_t borrow = crypto::detail::sub4(t, h, q_);
        auto h1 = crypto::detail::to_be(crypto::detail::select4(ct::mask_from_bit(borrow), h, t));
        v_.fill(0x01);
        k_.fill(0x00);
        for (std::uint8_t round = 0; round < 2; ++round) {
            crypto::detail::hmac_sha256 m(k_);
            m.update(v_);
            const std::uint8_t sep = round;
            m.update(std::span<const std::uint8_t>(&sep, 1));
            m.update(key);
            m.update(h1);
            m.update(extra);
            k_ = m.finish();
            v_ = crypto::detail::hmac_sha256::mac(k_, v_);
        }
        secure_wipe(h1);
    }

    rfc6979(const rfc6979&) = delete;
    rfc6979& operator=(const rfc6979&) = delete;

    /// \brief Wipes the state.
    constexpr ~rfc6979()
    {
        secure_wipe(k_);
        secure_wipe(v_);
    }

    /// \brief The next candidate nonce, in [1, q - 1] (step h).
    /// \return k, 32 bytes big-endian, in a wiped buffer.
    [[nodiscard]] constexpr secret_bytes<32> next() noexcept
    {
        for (;;) {
            if (!first_) {
                crypto::detail::hmac_sha256 m(k_);
                m.update(v_);
                const std::uint8_t zero = 0;
                m.update(std::span<const std::uint8_t>(&zero, 1));
                k_ = m.finish();
                v_ = crypto::detail::hmac_sha256::mac(k_, v_);
            }
            first_ = false;
            v_ = crypto::detail::hmac_sha256::mac(k_, v_);
            const auto k = crypto::detail::from_be(v_);
            const std::uint64_t ok = crypto::detail::mask_less4(k, q_) & ~crypto::detail::mask_is_zero4(k);
            if (ok)
                return secret_bytes<32>(std::span<const std::uint8_t, 32>(v_));
        }
    }

private:
    crypto::detail::limbs4 q_;
    std::array<std::uint8_t, 32> k_{};
    std::array<std::uint8_t, 32> v_{};
    bool first_ = true;
};

} // namespace snicholls::crypto::secp256k1

#endif /* snicholls_crypto_secp256k1_rfc6979_hpp */

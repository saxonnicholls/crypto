//
//  sign.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief RSA signing (RFC 8017): RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 and SHA-512 (RS256, RS384, RS512), with a
/// private key held in constant time.
/// \ingroup rsa
///
/// \overview
/// `rsa::private_key` holds the two primes and the CRT exponents (p, q, dP, dQ, qInv) and its public key;
/// `sign_pkcs1v15_sha256` (and `_sha384`, `_sha512`, each with a prehashed form) writes the signature, as long as
/// the modulus. PKCS#1 v1.5 signing is deterministic: the same key and message always give the same bytes, the bytes
/// every other implementation gives.
///
/// - Keys: `private_key::from_components` (a JWK's `n`, `e`, `p`, `q`, `dp`, `dq`, `qi`, base64url-decoded),
///   `from_pkcs1_der` (an RSAPrivateKey, PEM's "RSA PRIVATE KEY") and `from_pkcs8_der` (an unencrypted
///   PrivateKeyInfo with rsaEncryption, PEM's "PRIVATE KEY"). Moduli of 2048 to 4096 bits, two primes, each of at
///   most 2048 bits. An encrypted key (EncryptedPrivateKeyInfo) is another structure and is refused as malformed.
/// - Every key is checked when it is made: p and q odd and different, p q = n, dP < p, dQ < q, qInv q = 1 mod p, and
///   then a whole signature is made and verified with the public key (a pairwise consistency test), which is what
///   proves dP and dQ belong to e. A key that fails any of it is `errc::invalid_private_key`, never a key that signs
///   wrongly later.
/// - Every signature is verified with the public key before it is released (`errc::signing_fault`, the output
///   zeroed, when it does not verify): a miscomputed CRT half, from a hardware fault or a damaged key, would
///   otherwise reveal a prime to anyone holding the bad signature and the message (the Bellcore attack).
///
/// Strict input (CLAUDE.md rule 8): components have no leading zero byte; DER is DER (minimal lengths and
/// integers, version 0, nothing trailing, no attributes or other primes).
///
/// \relations
/// - `rsa/rsa.hpp`: `public_key` and verification, the other half; `detail/mont.hpp`: the constant-time Montgomery
///   arithmetic (shared with P-256 and P-384), `make_mont_ct` and `mont_pow_ct`.
/// - Above this library: holding keys by id, rotation and a KMS are a signer's (core's `signer` contract), which
///   calls these functions. The family's production RSA signer is the OpenSSL one above this library; this is the
///   family's own implementation of the same operation.
/// - Group: \ref rsa.
///
/// \impls
/// One: m^d mod n by the Chinese remainder theorem (RFC 8017 5.1.2, the second form). m is reduced modulo each
/// prime through Montgomery multiplication, each half is a fixed 4-bit-window exponentiation of exactly as many
/// steps as the prime's limb count gives, Garner's recombination is one more Montgomery multiplication, and
/// s = m2 + q h is a plain multiplication. The limb count N is 16, 24 or 32 (primes up to 1024, 1536, 2048 bits),
/// chosen from the lengths of p and q.
///
/// \contracts
/// - Constant time in p, q, dP, dQ, qInv and every value derived from them: no branch, loop bound or memory index
///   depends on them (Montgomery multiplication with a masked final subtraction, a table scanned whole, a fixed
///   number of squarings and multiplications). Public: n, e, the message, and the byte lengths of p and q (they
///   choose N; in DER they are in the clear).
/// - Revealed on purpose (`ct::declassify`): whether a key passed its checks; a component's leading-zero and sign
///   tests when it is read (they decide its length, not its value); the finished signature, to verify it (a
///   signature is public; one that then fails to verify is zeroed and never returned).
/// - No blinding: the arithmetic does not need it for timing. It would add protection against power and
///   electromagnetic analysis, which this library does not claim anywhere (README, "Constant time").
/// - The key wipes itself; every intermediate (residues, the window table, the CRT halves) is wiped.
/// - `constexpr`, `noexcept`, no allocation. A key is about 2.6 KB.
///
/// \errors
/// `errc::invalid_private_key` for a key that is malformed, outside the limits, inconsistent, or that fails its
/// consistency test (`errc::non_canonical` for a component with a leading zero byte); `errc::invalid_length` for an
/// output that is not exactly `modulus_bytes()`; `errc::signing_fault` for a signature that did not verify after it
/// was made. No error carries key material.
///
/// \examples
/// \snippet rsa/sign_demo.cpp rsa_sign
///
/// \perf
/// Two exponentiations of half the modulus's length: about 2.5 N 64 N Montgomery multiplications of N limbs each.
/// See BENCHMARKS.md, `benchmarks/rsa/sign_benchmark.cpp`. Several times slower than OpenSSL (no assembly, no
/// dedicated squaring).
///
/// \testing
/// `tests/rsa/sign_test.cpp`: every Wycheproof `rsa_pkcs1_{2048,3072,4096}_sig_gen` case byte for byte, each key
/// read from PKCS#8 and from its components; keys that must be refused (inconsistent, out of range, malformed DER,
/// an encrypted key); the fault check, by signing with a damaged CRT half. The secret paths are in the Valgrind
/// check (`tests/ct/secret_marking.cpp`). `demos/rsa/sign_demo.cpp`.
///
/// \deps
/// `<array>`, `<cstdint>`, `<span>`; core's `result.hpp`, `wide_mul.hpp` and SHA-2.
///
/// \gotchas
/// - Primality of p and q is not tested: a key made by a trustworthy generator is assumed. The checks catch
///   damage and inconsistency, not a key built to be weak.
/// - PEM is base64 text around DER: strip the armour and decode it first, into memory you wipe.
/// - RSASSA-PSS signing is not here yet (it needs a random salt, so a random source).
///
/// \status
/// Experimental (0.5). Not the family's production signer.

#ifndef snicholls_crypto_rsa_sign_hpp
#define snicholls_crypto_rsa_sign_hpp

#include <snicholls/core/detail/wide_mul.hpp>
#include <snicholls/core/result.hpp>
#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/detail/mont.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/rsa/rsa.hpp>
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace snicholls::crypto::rsa {

namespace detail {

using crypto::detail::limbs_n;
using crypto::detail::mont_params;

inline constexpr std::size_t crt_max_limbs = 32;   // a prime of up to 2048 bits

// The private key's CRT form at N limbs a prime: the primes with their Montgomery constants, dP, dQ, and qInv
// (q^-1 mod p). All of it is secret
template <std::size_t N>
struct crt_key {
    mont_params<N> p{};
    mont_params<N> q{};
    limbs_n<N> dp{};
    limbs_n<N> dq{};
    limbs_n<N> qinv{};
};

template <std::size_t N>
using limbs_2n = std::array<std::uint64_t, 2 * N>;

// x R mod m (x in Montgomery form) for any x below 2^(128 N), x = hi 2^(64 N) + lo. A Montgomery multiplication by
// R^2 mod m is fully reduced for any other operand below R, so lo R and (hi R) R come out below m
template <std::size_t N>
constexpr limbs_n<N> residue_mont(const limbs_2n<N>& x, const mont_params<N>& m) noexcept
{
    limbs_n<N> lo{}, hi{};
    for (std::size_t i = 0; i < N; ++i) {
        lo[i] = x[i];
        hi[i] = x[N + i];
    }
    limbs_n<N> a = crypto::detail::mont_mul<N>(lo, m.r2, m);
    limbs_n<N> b = crypto::detail::mont_mul<N>(crypto::detail::mont_mul<N>(hi, m.r2, m), m.r2, m);
    const limbs_n<N> r = crypto::detail::mont_add<N>(a, b, m);
    secure_wipe(lo);
    secure_wipe(hi);
    secure_wipe(a);
    secure_wipe(b);
    return r;
}

// a b, all 2 N limbs, in constant time
template <std::size_t N>
constexpr limbs_2n<N> mul_wide(const limbs_n<N>& a, const limbs_n<N>& b) noexcept
{
    limbs_2n<N> r{};
    for (std::size_t i = 0; i < N; ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < N; ++j) {
            const auto prod = snicholls::detail::umul128(a[i], b[j]);
            std::uint64_t lo = prod.low, hi = prod.high, c = 0;
            lo = crypto::detail::add_carry(lo, r[i + j], c);
            hi += c;
            c = 0;
            lo = crypto::detail::add_carry(lo, carry, c);
            hi += c;
            r[i + j] = lo;
            carry = hi;
        }
        r[i + N] = carry;
    }
    return r;
}

// m^d mod n by the CRT (RFC 8017 5.1.2, step 2.b), for m < n = p q:
//   m1 = m^dP mod p, m2 = m^dQ mod q, h = qInv (m1 - m2) mod p, s = m2 + q h
template <std::size_t N>
constexpr limbs_2n<N> crt_power(const crt_key<N>& k, const limbs_2n<N>& m) noexcept
{
    using namespace crypto::detail;
    limbs_n<N> mp = residue_mont<N>(m, k.p);
    limbs_n<N> mq = residue_mont<N>(m, k.q);
    limbs_n<N> m1 = mont_pow_ct<N>(mp, k.dp, k.p);                      // m1 R mod p
    limbs_n<N> m2r = mont_pow_ct<N>(mq, k.dq, k.q);                     // m2 R mod q
    limbs_n<N> m2 = mont_from<N>(m2r, k.q);                             // m2, below q
    limbs_n<N> m2p = mont_mul<N>(m2, k.p.r2, k.p);                      // m2 R mod p (m2 may be above p: it is below R)
    limbs_n<N> diff = mont_sub<N>(m1, m2p, k.p);                        // (m1 - m2) R mod p
    limbs_n<N> h = mont_mul<N>(diff, k.qinv, k.p);                      // (m1 - m2) qInv mod p, out of Montgomery form
    limbs_2n<N> s = mul_wide<N>(k.q.m, h);                              // q h < q p = n
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < 2 * N; ++i)                             // + m2 < q: s < n, no carry out
        s[i] = add_carry(s[i], i < N ? m2[i] : 0, carry);
    secure_wipe(mp);
    secure_wipe(mq);
    secure_wipe(m1);
    secure_wipe(m2r);
    secure_wipe(m2);
    secure_wipe(m2p);
    secure_wipe(diff);
    secure_wipe(h);
    return s;
}

// Big-endian bytes (at most 8 L of them) into L limbs, zero above; the bytes may be secret, their number is public
template <std::size_t L>
constexpr std::array<std::uint64_t, L> limbs_from_be(std::span<const std::uint8_t> b) noexcept
{
    std::array<std::uint64_t, L> r{};
    for (std::size_t i = 0; i < b.size(); ++i) {
        const std::size_t bit = 8 * (b.size() - 1 - i);
        r[bit / 64] |= static_cast<std::uint64_t>(b[i]) << (bit % 64);
    }
    return r;
}

// a < b as a mask
template <std::size_t N>
constexpr std::uint64_t mask_less_n(const limbs_n<N>& a, const limbs_n<N>& b) noexcept
{
    limbs_n<N> t{};
    const std::uint64_t borrow = crypto::detail::sub_n<N>(t, a, b);
    secure_wipe(t);
    return ct::mask_from_bit(borrow);
}

// A component read where its bytes are secret: non-empty and without a leading zero byte. The test is on the first
// byte only and decides the component's length, which is public
constexpr bool canonical_secret(std::span<const std::uint8_t> v) noexcept
{
    return !v.empty() && ct::declassify(v[0] != 0);
}

// A DER INTEGER's contents, secret, as its unsigned magnitude: non-negative and minimal (der_unsigned, with the
// tests on its first two bytes declared: they are DER's form, not the number)
constexpr std::optional<std::span<const std::uint8_t>> der_unsigned_secret(std::span<const std::uint8_t> v) noexcept
{
    if (v.empty() || ct::declassify((v[0] & 0x80) != 0))
        return std::nullopt;
    if (v.size() == 1)
        return v;
    const bool zero = ct::declassify(v[0] == 0);
    if (zero && !ct::declassify((v[1] & 0x80) != 0))
        return std::nullopt;
    return zero ? v.subspan(1) : v;
}

} // namespace detail

/// \brief An RSA private key in CRT form, with its public key. Move-only; wiped when it dies.
/// \ingroup rsa
class private_key {
public:
    /// \brief A key from its components, big-endian with no leading zero byte (a JWK's `n`, `e`, `p`, `q`, `dp`,
    /// `dq` and `qi`, decoded). Constant time in p, q, dp, dq and qinv; n and e are public.
    /// \param n The modulus.
    /// \param e The public exponent.
    /// \param p The first prime.
    /// \param q The second prime.
    /// \param dp d mod (p - 1).
    /// \param dq d mod (q - 1).
    /// \param qinv q^-1 mod p.
    /// \return The key; `errc::non_canonical` for a leading zero byte; `errc::invalid_private_key` for a public part
    /// `public_key::from_components` refuses, a prime over 2048 bits, or a key that fails its checks.
    [[nodiscard]] static constexpr result<private_key, errc> from_components(
        std::span<const std::uint8_t> n, std::span<const std::uint8_t> e, std::span<const std::uint8_t> p, std::span<const std::uint8_t> q,
        std::span<const std::uint8_t> dp, std::span<const std::uint8_t> dq, std::span<const std::uint8_t> qinv) noexcept
    {
        if (!detail::canonical_secret(p) || !detail::canonical_secret(q) || !detail::canonical_secret(dp) ||
            !detail::canonical_secret(dq) || !detail::canonical_secret(qinv))
            return err(errc::non_canonical);
        auto pub = public_key::from_components(n, e);
        if (!pub)
            return err(pub.unwrap_err() == errc::non_canonical ? errc::non_canonical : errc::invalid_private_key);
        return make(*pub, n, p, q, dp, dq, qinv);
    }

    /// \brief A key from a DER RSAPrivateKey (PKCS#1, RFC 8017 A.1.2; PEM's "RSA PRIVATE KEY"): version 0, two
    /// primes. Constant time in the key's numbers; the DER structure (tags and lengths) is public.
    /// \param der The DER. The caller wipes it.
    /// \return The key, or `errc::invalid_private_key` for anything but exactly that, in DER, that passes its checks.
    [[nodiscard]] static constexpr result<private_key, errc> from_pkcs1_der(std::span<const std::uint8_t> der) noexcept
    {
        detail::der_reader outer(der);
        const auto seq = outer.next(0x30);
        if (!seq || !outer.done())
            return err(errc::invalid_private_key);
        detail::der_reader in(*seq);
        const auto version = in.next(0x02);
        if (!version || version->size() != 1 || ct::declassify((*version)[0] != 0))
            return err(errc::invalid_private_key);   // 0: two primes; 1 (multi-prime) is not read
        std::array<std::span<const std::uint8_t>, 8> v{};   // n, e, d, p, q, dP, dQ, qInv
        for (auto& x : v) {
            const auto raw = in.next(0x02);
            const auto u = raw ? detail::der_unsigned_secret(*raw) : std::nullopt;
            if (!u)
                return err(errc::invalid_private_key);
            x = *u;
        }
        if (!in.done())
            return err(errc::invalid_private_key);
        // d (v[2]) is not used: the CRT exponents are, and the consistency test proves them against e
        auto pub = public_key::from_components(v[0], v[1]);
        if (!pub)
            return err(errc::invalid_private_key);
        for (std::size_t i = 3; i < 8; ++i)
            if (!detail::canonical_secret(v[i]))
                return err(errc::invalid_private_key);
        return make(*pub, v[0], v[3], v[4], v[5], v[6], v[7]);
    }

    /// \brief A key from an unencrypted DER PrivateKeyInfo (PKCS#8, RFC 5208; PEM's "PRIVATE KEY") with the
    /// rsaEncryption algorithm: version 0, no attributes. Constant time in the key's numbers.
    /// \param der The DER. The caller wipes it.
    /// \return The key, or `errc::invalid_private_key` for any other structure (an EncryptedPrivateKeyInfo among
    /// them), another algorithm, or a key that fails its checks.
    [[nodiscard]] static constexpr result<private_key, errc> from_pkcs8_der(std::span<const std::uint8_t> der) noexcept
    {
        detail::der_reader outer(der);
        const auto seq = outer.next(0x30);
        if (!seq || !outer.done())
            return err(errc::invalid_private_key);
        detail::der_reader in(*seq);
        const auto version = in.next(0x02);
        const auto alg = version ? in.next(0x30) : std::nullopt;
        const auto key = alg ? in.next(0x04) : std::nullopt;
        if (!key || !in.done() || version->size() != 1 || (*version)[0] != 0)
            return err(errc::invalid_private_key);
        detail::der_reader a(*alg);
        const auto oid = a.next(0x06);
        const auto null = oid ? a.next(0x05) : std::nullopt;
        if (!null || !null->empty() || !a.done() || oid->size() != detail::rsa_encryption_oid.size())
            return err(errc::invalid_private_key);
        for (std::size_t i = 0; i < oid->size(); ++i)
            if ((*oid)[i] != detail::rsa_encryption_oid[i])
                return err(errc::invalid_private_key);
        return from_pkcs1_der(*key);
    }

    private_key(const private_key&) = delete;
    private_key& operator=(const private_key&) = delete;

    /// \brief Takes `other`'s key and wipes it.
    /// \param other The source, zero afterwards.
    constexpr private_key(private_key&& other) noexcept
        : pub_(other.pub_), limbs_(other.limbs_), p_(other.p_), q_(other.q_), dp_(other.dp_), dq_(other.dq_), qinv_(other.qinv_)
    {
        other.wipe();
    }

    /// \brief Wipes this, takes `other`'s key and wipes it.
    /// \param other The source, zero afterwards.
    /// \return `*this`.
    constexpr private_key& operator=(private_key&& other) noexcept
    {
        if (this != &other) {
            pub_ = other.pub_;
            limbs_ = other.limbs_;
            p_ = other.p_;
            q_ = other.q_;
            dp_ = other.dp_;
            dq_ = other.dq_;
            qinv_ = other.qinv_;
            other.wipe();
        }
        return *this;
    }

    /// \brief Wipes the key.
    constexpr ~private_key() { wipe(); }

    /// \brief An explicit second copy.
    /// \return A key with the same numbers.
    [[nodiscard]] constexpr private_key clone() const noexcept { return private_key(pub_, limbs_, p_, q_, dp_, dq_, qinv_); }

    /// \brief The public key.
    /// \return n and e.
    [[nodiscard]] constexpr const rsa::public_key& public_key() const noexcept { return pub_; }

    /// \brief The modulus's length in bytes, which is a signature's length.
    /// \return 256 to 512.
    [[nodiscard]] constexpr std::size_t modulus_bytes() const noexcept { return pub_.modulus_bytes(); }

    /// \brief RSASP1 with its check (RFC 8017 5.2.1): `out` = em^d mod n, verified with the public key before it is
    /// returned. For the signature schemes of this header and for tests; `em` is an encoded message, never raw data.
    /// Constant time in the key.
    /// \param em The encoded message, exactly `modulus_bytes()` long and below the modulus (public).
    /// \param out The signature, exactly `modulus_bytes()` long; zeroed on any error.
    /// \return Success; `errc::invalid_length` for another length; `errc::signing_fault` when em is not below the
    /// modulus or the result did not verify.
    [[nodiscard]] constexpr result<void, errc> sign_encoded(std::span<const std::uint8_t> em, std::span<std::uint8_t> out) const noexcept
    {
        if (em.size() != modulus_bytes() || out.size() != modulus_bytes())
            return err(errc::invalid_length);
        switch (limbs_) {   // public: the primes' length
        case 16: return sign_n<16>(em, out);
        case 24: return sign_n<24>(em, out);
        default: return sign_n<32>(em, out);
        }
    }

private:
    using big = std::array<std::uint64_t, detail::crt_max_limbs>;

    constexpr private_key(const rsa::public_key& pub, std::size_t limbs, const big& p, const big& q, const big& dp, const big& dq,
                          const big& qinv) noexcept
        : pub_(pub), limbs_(limbs), p_(p), q_(q), dp_(dp), dq_(dq), qinv_(qinv)
    {
    }

    constexpr void wipe() noexcept
    {
        secure_wipe(p_);
        secure_wipe(q_);
        secure_wipe(dp_);
        secure_wipe(dq_);
        secure_wipe(qinv_);
    }

    template <std::size_t N>
    static constexpr crypto::detail::limbs_n<N> low(const big& a) noexcept
    {
        crypto::detail::limbs_n<N> r{};
        for (std::size_t i = 0; i < N; ++i)
            r[i] = a[i];
        return r;
    }

    // The checks of a key at N limbs a prime, as one mask: p and q odd and different, p q = n, 0 < dP < p,
    // 0 < dQ < q, 0 < qInv < p, qInv q = 1 mod p
    template <std::size_t N>
    constexpr std::uint64_t consistent(std::span<const std::uint8_t> n) const noexcept
    {
        using namespace crypto::detail;
        limbs_n<N> p = low<N>(p_), q = low<N>(q_), dp = low<N>(dp_), dq = low<N>(dq_), qinv = low<N>(qinv_);
        std::uint64_t good = ct::mask_from_bit(p[0] & q[0] & 1);
        good &= ~mask_equal_n<N>(p, q);
        auto pq = detail::mul_wide<N>(p, q);
        const auto nl = detail::limbs_from_be<2 * N>(n);
        good &= mask_equal_n<2 * N>(pq, nl);
        good &= detail::mask_less_n<N>(dp, p) & ~mask_is_zero_n<N>(dp);
        good &= detail::mask_less_n<N>(dq, q) & ~mask_is_zero_n<N>(dq);
        good &= detail::mask_less_n<N>(qinv, p) & ~mask_is_zero_n<N>(qinv);
        // with an even p there is no Montgomery form; the product below is then meaningless and good is already zero
        mont_params<N> mp = make_mont_ct<N>(p);
        limbs_n<N> qr = mont_mul<N>(q, mp.r2, mp);        // q R mod p
        limbs_n<N> one = mont_mul<N>(qr, qinv, mp);       // q qInv mod p
        limbs_n<N> expect{};
        expect[0] = 1;
        good &= mask_equal_n<N>(one, expect);
        secure_wipe(p);
        secure_wipe(q);
        secure_wipe(dp);
        secure_wipe(dq);
        secure_wipe(qinv);
        secure_wipe(pq);
        secure_wipe(mp);
        secure_wipe(qr);
        secure_wipe(one);
        return good;
    }

    constexpr std::uint64_t consistent(std::span<const std::uint8_t> n) const noexcept
    {
        switch (limbs_) {
        case 16: return consistent<16>(n);
        case 24: return consistent<24>(n);
        default: return consistent<32>(n);
        }
    }

    template <std::size_t N>
    constexpr result<void, errc> sign_n(std::span<const std::uint8_t> em, std::span<std::uint8_t> out) const noexcept
    {
        using namespace crypto::detail;
        const std::size_t k = modulus_bytes();
        detail::crt_key<N> key;
        key.p = make_mont_ct<N>(low<N>(p_));
        key.q = make_mont_ct<N>(low<N>(q_));
        key.dp = low<N>(dp_);
        key.dq = low<N>(dq_);
        key.qinv = low<N>(qinv_);
        auto s = detail::crt_power<N>(key, detail::limbs_from_be<2 * N>(em));
        secure_wipe(key);
        std::array<std::uint8_t, max_modulus_bytes> sig{};
        for (std::size_t i = 0; i < k; ++i) {
            const std::size_t bit = 8 * (k - 1 - i);
            sig[i] = static_cast<std::uint8_t>(s[bit / 64] >> (bit % 64));
        }
        secure_wipe(s);
        // The signature is public from here: it is what this function returns. Declared so, it is verified with the
        // public key (variable time); one that does not verify is wiped and never leaves
        sig = ct::declassify(sig);
        std::array<std::uint8_t, max_modulus_bytes> check{};
        bool same = pub_.open(std::span<const std::uint8_t>(sig).first(k), check).is_ok();
        std::uint8_t diff = 0;
        for (std::size_t i = 0; i < k; ++i)
            diff = static_cast<std::uint8_t>(diff | (check[i] ^ em[i]));
        same = same && diff == 0;
        for (std::size_t i = 0; i < k; ++i)
            out[i] = same ? sig[i] : std::uint8_t{0};
        secure_wipe(sig);
        if (!same)
            return err(errc::signing_fault);
        return ok();
    }

    static constexpr result<private_key, errc> make(const rsa::public_key& pub, std::span<const std::uint8_t> n,
                                                    std::span<const std::uint8_t> p, std::span<const std::uint8_t> q,
                                                    std::span<const std::uint8_t> dp, std::span<const std::uint8_t> dq,
                                                    std::span<const std::uint8_t> qinv) noexcept
    {
        // The primes' byte lengths are public and choose the limb count
        const std::size_t widest = p.size() > q.size() ? p.size() : q.size();
        const std::size_t limbs = widest <= 128 ? 16 : widest <= 192 ? 24 : 32;
        if (widest > 8 * detail::crt_max_limbs || dp.size() > 8 * limbs || dq.size() > 8 * limbs || qinv.size() > 8 * limbs ||
            n.size() > 16 * limbs)
            return err(errc::invalid_private_key);
        private_key key(pub, limbs, detail::limbs_from_be<detail::crt_max_limbs>(p), detail::limbs_from_be<detail::crt_max_limbs>(q),
                        detail::limbs_from_be<detail::crt_max_limbs>(dp), detail::limbs_from_be<detail::crt_max_limbs>(dq),
                        detail::limbs_from_be<detail::crt_max_limbs>(qinv));
        if (!ct::declassify(key.consistent(n) != 0))
            return err(errc::invalid_private_key);
        // The pairwise consistency test: a signature over a fixed encoded message must verify. It proves dP and dQ
        // against e (the checks above do not), with the same code that signs
        std::array<std::uint8_t, max_modulus_bytes> em{}, sig{};
        const std::size_t k = pub.modulus_bytes();
        for (std::size_t i = 1; i < k; ++i)
            em[i] = 0x5a;   // the first byte is zero: below the modulus
        const bool signs = key.sign_encoded(std::span<const std::uint8_t>(em).first(k), std::span<std::uint8_t>(sig).first(k)).is_ok();
        secure_wipe(sig);
        if (!signs)
            return err(errc::invalid_private_key);
        return ok(std::move(key));
    }

    rsa::public_key pub_;
    std::size_t limbs_ = 0;
    big p_{};
    big q_{};
    big dp_{};
    big dq_{};
    big qinv_{};
};

namespace detail {

// EMSA-PKCS1-v1_5 (RFC 8017 9.2) over a hash, then RSASP1
template <class Scheme>
constexpr result<void, errc> sign_pkcs1v15(const private_key& key, std::span<const std::uint8_t, Scheme::hash::digest_size> hash,
                                           std::span<std::uint8_t> sig) noexcept
{
    const std::size_t k = key.modulus_bytes();
    if (sig.size() != k)
        return err(errc::invalid_length);
    // EM = 0x00 0x01 0xFF ... 0xFF 0x00 DigestInfo H (k >= 256, so far more than 8 bytes of 0xFF)
    std::array<std::uint8_t, max_modulus_bytes> em{};
    const std::size_t t = Scheme::digest_info.size() + hash.size();
    std::size_t i = 0;
    em[i++] = 0x00;
    em[i++] = 0x01;
    for (; i < k - t - 1; ++i)
        em[i] = 0xff;
    em[i++] = 0x00;
    for (const auto b : Scheme::digest_info)
        em[i++] = b;
    for (const auto b : hash)
        em[i++] = b;
    return key.sign_encoded(std::span<const std::uint8_t>(em).first(k), sig);
}

} // namespace detail

/// \brief Signs a SHA-256 hash with RSASSA-PKCS1-v1_5 (RFC 8017 8.2.1). Constant time in the key.
/// \ingroup rsa
/// \param key The private key.
/// \param hash The SHA-256 of the message.
/// \param sig Where the signature goes: exactly `key.modulus_bytes()`; zeroed on any error.
/// \return Success, `errc::invalid_length`, or `errc::signing_fault`.
[[nodiscard]] constexpr result<void, errc> sign_pkcs1v15_sha256_prehashed(const private_key& key, std::span<const std::uint8_t, 32> hash,
                                                                          std::span<std::uint8_t> sig) noexcept
{
    return detail::sign_pkcs1v15<detail::with_sha256>(key, hash, sig);
}

/// \brief Signs a message with RSASSA-PKCS1-v1_5 and SHA-256: JOSE's RS256, `openssl dgst -sha256 -sign`. Constant
/// time in the key.
/// \ingroup rsa
/// \param key The private key.
/// \param message The bytes to sign.
/// \param sig Where the signature goes: exactly `key.modulus_bytes()`; zeroed on any error.
/// \return Success, `errc::invalid_length`, or `errc::signing_fault`.
[[nodiscard]] constexpr result<void, errc> sign_pkcs1v15_sha256(const private_key& key, std::span<const std::uint8_t> message,
                                                                std::span<std::uint8_t> sig) noexcept
{
    const auto h = crypto::detail::sha256::hash(message);
    return sign_pkcs1v15_sha256_prehashed(key, h, sig);
}

/// \brief Signs a SHA-384 hash with RSASSA-PKCS1-v1_5. Constant time in the key.
/// \ingroup rsa
/// \param key The private key.
/// \param hash The SHA-384 of the message.
/// \param sig Where the signature goes: exactly `key.modulus_bytes()`; zeroed on any error.
/// \return Success, `errc::invalid_length`, or `errc::signing_fault`.
[[nodiscard]] constexpr result<void, errc> sign_pkcs1v15_sha384_prehashed(const private_key& key, std::span<const std::uint8_t, 48> hash,
                                                                          std::span<std::uint8_t> sig) noexcept
{
    return detail::sign_pkcs1v15<detail::with_sha384>(key, hash, sig);
}

/// \brief Signs a message with RSASSA-PKCS1-v1_5 and SHA-384: JOSE's RS384. Constant time in the key.
/// \ingroup rsa
/// \param key The private key.
/// \param message The bytes to sign.
/// \param sig Where the signature goes: exactly `key.modulus_bytes()`; zeroed on any error.
/// \return Success, `errc::invalid_length`, or `errc::signing_fault`.
[[nodiscard]] constexpr result<void, errc> sign_pkcs1v15_sha384(const private_key& key, std::span<const std::uint8_t> message,
                                                                std::span<std::uint8_t> sig) noexcept
{
    const auto h = crypto::detail::sha384::hash(message);
    return sign_pkcs1v15_sha384_prehashed(key, h, sig);
}

/// \brief Signs a SHA-512 hash with RSASSA-PKCS1-v1_5. Constant time in the key.
/// \ingroup rsa
/// \param key The private key.
/// \param hash The SHA-512 of the message.
/// \param sig Where the signature goes: exactly `key.modulus_bytes()`; zeroed on any error.
/// \return Success, `errc::invalid_length`, or `errc::signing_fault`.
[[nodiscard]] constexpr result<void, errc> sign_pkcs1v15_sha512_prehashed(const private_key& key, std::span<const std::uint8_t, 64> hash,
                                                                          std::span<std::uint8_t> sig) noexcept
{
    return detail::sign_pkcs1v15<detail::with_sha512>(key, hash, sig);
}

/// \brief Signs a message with RSASSA-PKCS1-v1_5 and SHA-512: JOSE's RS512. Constant time in the key.
/// \ingroup rsa
/// \param key The private key.
/// \param message The bytes to sign.
/// \param sig Where the signature goes: exactly `key.modulus_bytes()`; zeroed on any error.
/// \return Success, `errc::invalid_length`, or `errc::signing_fault`.
[[nodiscard]] constexpr result<void, errc> sign_pkcs1v15_sha512(const private_key& key, std::span<const std::uint8_t> message,
                                                                std::span<std::uint8_t> sig) noexcept
{
    const auto h = crypto::detail::sha512::hash(message);
    return sign_pkcs1v15_sha512_prehashed(key, h, sig);
}

} // namespace snicholls::crypto::rsa

#endif /* snicholls_crypto_rsa_sign_hpp */

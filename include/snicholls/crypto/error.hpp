//
//  error.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief `snicholls::crypto::errc`: every expected failure in snicholls-crypto, one enumeration.
/// \ingroup crypto
///
/// \overview
/// Every operation that can fail on its input (a key out of range, a signature that does not verify, a mnemonic with
/// a bad checksum, a path that is not hardened where it must be) returns `snicholls::result<V, errc>`. One enumeration
/// for the whole library, so a caller that handles a wallet flow end to end (words to seed to key to signature)
/// matches on one type. Exceptions are kept for the unexpected; nothing here throws.
///
/// \relations
/// - `snicholls::result` (core's `result.hpp`): the carrier. `SNICHOLLS_TRY_ASSIGN` propagates.
/// - Group: \ref crypto.
///
/// \impls
/// None: one enumeration and its text.
///
/// \contracts
/// `to_string` is `constexpr` and `noexcept`; the text never contains key material, so an error may be logged.
///
/// \errors
/// None of its own.
///
/// \examples
/// \snippet error_demo.cpp errors
///
/// \perf
/// Not benchmarked: an enumeration.
///
/// \testing
/// `tests/error_test.cpp`, `demos/error_demo.cpp`.
///
/// \deps
/// `<string_view>`.
///
/// \gotchas
/// A failed verification is `errc::invalid_signature`, the same value for every reason a signature is wrong (bad
/// range, wrong key, wrong message): a verifier should not tell an attacker which check failed.
///
/// \status
/// Experimental (0.1).

#ifndef snicholls_crypto_error_hpp
#define snicholls_crypto_error_hpp

#include <string_view>

namespace snicholls::crypto {

/// \brief Why an operation failed. The values are stable: new ones are only ever appended.
/// \ingroup crypto
enum class errc : unsigned char {
    invalid_length = 1,       ///< An input had the wrong number of bytes.
    invalid_private_key,      ///< A private key or scalar was zero or not below the group order.
    invalid_public_key,       ///< A public key was badly encoded, not on the curve, or the point at infinity.
    invalid_signature,        ///< A signature was out of range, badly encoded, or did not verify.
    invalid_recovery_id,      ///< A recovery id was not 0 to 3 (or an Ethereum `v` not 27 or 28).
    high_s,                   ///< A signature's `s` was above n / 2 where only low-S is accepted.
    recovery_failed,          ///< No public key could be recovered: `r` is not the x of a curve point, or Q is infinity.
    small_order,              ///< X25519 gave the all-zero shared secret: the peer's key has small order.
    invalid_seed,             ///< A seed was not 16 to 64 bytes.
    invalid_derivation,       ///< A BIP-32 child is invalid (I_L at or above n, or a zero key): use the next index.
    hardened_required,        ///< A non-hardened index where only hardened derivation is defined (SLIP-10 Ed25519, or from a public key).
    invalid_path,             ///< A derivation path did not parse.
    invalid_mnemonic_length,  ///< A mnemonic was not 12, 15, 18, 21 or 24 words, or entropy not 16 to 32 bytes in steps of 4.
    unknown_word,             ///< A mnemonic word is not in the word list.
    invalid_checksum,         ///< A mnemonic's checksum, or an extended key's, did not match.
    non_canonical,            ///< Text was not in the canonical form this library accepts (see the function's documentation).
    invalid_extended_key,     ///< A serialised BIP-32 extended key was malformed or inconsistent.
    invalid_character,        ///< Text held a character outside its alphabet (base58, bech32), or outside printable ASCII.
    invalid_hrp,              ///< A bech32 human-readable part was empty, too long, out of range, missing, or not the one expected.
    invalid_witness_version,  ///< A segwit witness version above 16, or the wrong checksum variant for the version.
    invalid_witness_program,  ///< A segwit witness program outside 2 to 40 bytes, or not 20 or 32 bytes for version 0.
    authentication_failed,    ///< An AEAD tag did not match: the ciphertext, the associated data, the nonce or the key differ.
    signing_fault,            ///< A signature did not verify after it was made (a fault, or input out of range): nothing was released.
};

/// \brief The name of an error, for logs and messages; never key material.
/// \param e The error.
/// \return A string literal, `"unknown"` for a value outside the enumeration.
[[nodiscard]] constexpr std::string_view to_string(errc e) noexcept
{
    switch (e) {
    case errc::invalid_length: return "invalid_length";
    case errc::invalid_private_key: return "invalid_private_key";
    case errc::invalid_public_key: return "invalid_public_key";
    case errc::invalid_signature: return "invalid_signature";
    case errc::invalid_recovery_id: return "invalid_recovery_id";
    case errc::high_s: return "high_s";
    case errc::recovery_failed: return "recovery_failed";
    case errc::small_order: return "small_order";
    case errc::invalid_seed: return "invalid_seed";
    case errc::invalid_derivation: return "invalid_derivation";
    case errc::hardened_required: return "hardened_required";
    case errc::invalid_path: return "invalid_path";
    case errc::invalid_mnemonic_length: return "invalid_mnemonic_length";
    case errc::unknown_word: return "unknown_word";
    case errc::invalid_checksum: return "invalid_checksum";
    case errc::non_canonical: return "non_canonical";
    case errc::invalid_extended_key: return "invalid_extended_key";
    case errc::invalid_character: return "invalid_character";
    case errc::invalid_hrp: return "invalid_hrp";
    case errc::invalid_witness_version: return "invalid_witness_version";
    case errc::invalid_witness_program: return "invalid_witness_program";
    case errc::authentication_failed: return "authentication_failed";
    case errc::signing_fault: return "signing_fault";
    }
    return "unknown";
}

} // namespace snicholls::crypto

#endif /* snicholls_crypto_error_hpp */

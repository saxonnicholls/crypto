//
//  crypto.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

/// \file
/// \brief The umbrella header: every public header of snicholls-crypto. For applications; library code includes
/// only what it uses.
/// \ingroup crypto

/// \defgroup crypto snicholls-crypto
/// \brief Elliptic curves, signatures and wallet key derivation, constant-time where secrets are involved.

/// \defgroup secp256k1 secp256k1
/// \ingroup crypto
/// \brief The curve, ECDSA with RFC 6979 nonces and public-key recovery, BIP-340 Schnorr.

/// \defgroup address Addresses
/// \ingroup crypto
/// \brief Address and key text: base58 (any alphabet), base58check, bech32 and bech32m, segwit addresses.

/// \defgroup curve25519 Curve25519
/// \ingroup crypto
/// \brief The field and scalars of Curve25519, edwards25519, Ed25519 signatures and X25519 key agreement.

/// \defgroup rsa RSA
/// \ingroup crypto
/// \brief RSA signature verification: RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256 (RS256, PS256).

/// \defgroup wallet Wallets
/// \ingroup crypto
/// \brief BIP-39 mnemonics, BIP-32 and SLIP-10 derivation, and derivation paths.

#ifndef snicholls_crypto_crypto_hpp
#define snicholls_crypto_crypto_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>
#include <snicholls/crypto/version.hpp>
#include <snicholls/crypto/address/base58.hpp>
#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/address/bech32.hpp>
#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/bip39/wordlist.hpp>
#include <snicholls/crypto/curve25519/ed25519.hpp>
#include <snicholls/crypto/curve25519/edwards.hpp>
#include <snicholls/crypto/curve25519/field.hpp>
#include <snicholls/crypto/curve25519/scalar.hpp>
#include <snicholls/crypto/curve25519/x25519.hpp>
#include <snicholls/crypto/hd/bip32.hpp>
#include <snicholls/crypto/hd/path.hpp>
#include <snicholls/crypto/hd/slip10.hpp>
#include <snicholls/crypto/rsa/rsa.hpp>
#include <snicholls/crypto/secp256k1/ecdsa.hpp>
#include <snicholls/crypto/secp256k1/field.hpp>
#include <snicholls/crypto/secp256k1/keys.hpp>
#include <snicholls/crypto/secp256k1/point.hpp>
#include <snicholls/crypto/secp256k1/rfc6979.hpp>
#include <snicholls/crypto/secp256k1/scalar.hpp>
#include <snicholls/crypto/secp256k1/schnorr.hpp>

#endif /* snicholls_crypto_crypto_hpp */

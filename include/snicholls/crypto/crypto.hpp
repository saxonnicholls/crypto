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

#ifndef snicholls_crypto_crypto_hpp
#define snicholls_crypto_crypto_hpp

#include <snicholls/crypto/constant_time.hpp>
#include <snicholls/crypto/error.hpp>
#include <snicholls/crypto/secret.hpp>
#include <snicholls/crypto/version.hpp>
#include <snicholls/crypto/secp256k1/field.hpp>
#include <snicholls/crypto/secp256k1/point.hpp>
#include <snicholls/crypto/secp256k1/scalar.hpp>

#endif /* snicholls_crypto_crypto_hpp */

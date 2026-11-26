#!/usr/bin/env python3
#
#  oracle.py
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  The Python oracles: one JSON object per line on stdin, one answer per line on stdout, in order. Test-only, run
#  in docker/oracles by scripts/generate_oracle_fixtures.py and by the fuzz harness; nothing here is part of the
#  library. Every value is lower-case hex unless it is text (a mnemonic, a passphrase, a path, an address).
#
#      {"lib": "coincurve", "op": "ecdsa_sign", "sk": "...", "h": "..."}  ->  {"r": ..., "s": ..., "v": 0, "der": ...}
#      {"op": "version"}  ->  {"oracle": "python", "libs": {"coincurve": {"version": ..., "ops": [...]}, ...}}
#
#  An answer is the result's fields, {"error": "<why>"} when the library refused the input, or
#  {"unsupported": true} when the library has no such operation. The libraries:
#
#      coincurve      libsecp256k1 (bundled in the wheel): keys, ECDSA (RFC 6979, low-S), recovery, BIP-340
#      openssl        OpenSSL through cryptography: ECDSA on secp256k1 (RFC 6979 when OpenSSL is 3.2 or later),
#                     Ed25519, X25519, RSA (PKCS#1 v1.5 signing and verification, PSS verification, SPKI),
#                     P-256, P-384 (keys, ECDSA with SHA-384, ECDH), ChaCha20-Poly1305 and AES-GCM, and JOSE's
#                     ECDH-ES (ConcatKDFHash, key unwrap)
#      pynacl         libsodium: Ed25519, X25519
#      mnemonic       python-mnemonic, Trezor's BIP-39 reference
#      slip10         the SLIP-10 reference: BIP-32 (SLIP-10 on secp256k1 is BIP-32) and SLIP-10 Ed25519
#      base58         base58check
#      bip350_ref     Pieter Wuille's BIP-173 / BIP-350 reference code (segwit_addr.py, from the image)
#

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.join(os.environ.get("ORACLES_HOME", "/opt/oracles"), "python-ref"))

import base58 as base58_lib                                               # noqa: E402
import coincurve                                                          # noqa: E402
import cryptography                                                       # noqa: E402
import mnemonic as mnemonic_lib                                           # noqa: E402
import nacl                                                               # noqa: E402
import nacl.bindings                                                      # noqa: E402
import nacl.exceptions                                                    # noqa: E402
import segwit_addr                                                        # noqa: E402
import slip10 as slip10_lib                                               # noqa: E402
from cryptography.exceptions import InvalidSignature                     # noqa: E402
from cryptography.hazmat.primitives import hashes                        # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519, utils as asym_utils  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, rsa as rsa_lib  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def h(b):
    return bytes(b).hex()


def b(x):
    return bytes.fromhex(x)


class Refused(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------------
# coincurve (libsecp256k1)

def _cc_lib():
    from coincurve._libsecp256k1 import ffi, lib
    from coincurve.context import GLOBAL_CONTEXT
    return ffi, lib, GLOBAL_CONTEXT.ctx


def _cc_sig(compact):
    # A compact r || s into libsecp256k1's signature, as secp256k1_ecdsa_signature_parse_compact reads it: r or s
    # at or above n is refused there (the library would otherwise reduce it)
    ffi, lib, ctx = _cc_lib()
    sig = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_compact(ctx, sig, compact):
        raise Refused("parse_compact")
    return sig


def _cc_verify_raw(pub, hash32, sig):
    ffi, lib, ctx = _cc_lib()
    key = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, key, pub, len(pub)):
        raise Refused("pubkey_parse")
    return bool(lib.secp256k1_ecdsa_verify(ctx, sig, hash32, key))


def coincurve_op(q):
    op = q["op"]
    if op == "sec_pub":
        try:
            k = coincurve.PrivateKey(b(q["sk"]))
        except Exception as e:
            raise Refused(str(e))
        return {"c": h(k.public_key.format(True)), "u": h(k.public_key.format(False))}
    if op == "pub_parse":
        try:
            p = coincurve.PublicKey(b(q["pub"]))
        except Exception as e:
            raise Refused(str(e))
        return {"c": h(p.format(True))}
    if op == "ecdsa_sign":
        k = coincurve.PrivateKey(b(q["sk"]))
        rec = k.sign_recoverable(b(q["h"]), hasher=None)
        der = k.sign(b(q["h"]), hasher=None)
        return {"r": h(rec[:32]), "s": h(rec[32:64]), "v": rec[64], "der": h(der)}
    if op == "ecdsa_verify":
        # libsecp256k1 verifies only low-S; Bitcoin Core accepts a high-S signature where consensus allows it by
        # normalising first, which is how "accept" is answered here
        ffi, lib, ctx = _cc_lib()
        sig = _cc_sig(b(q["sig"]))
        if q.get("high_s") == "accept":
            lib.secp256k1_ecdsa_signature_normalize(ctx, sig, sig)
        return {"valid": _cc_verify_raw(b(q["pub"]), b(q["h"]), sig)}
    if op == "ecdsa_verify_der":
        ffi, lib, ctx = _cc_lib()
        der = b(q["der"])
        sig = ffi.new("secp256k1_ecdsa_signature *")
        if not lib.secp256k1_ecdsa_signature_parse_der(ctx, sig, der, len(der)):
            raise Refused("parse_der")
        out = ffi.new("unsigned char[64]")
        lib.secp256k1_ecdsa_signature_serialize_compact(ctx, out, sig)
        return {"rs": h(ffi.buffer(out, 64)), "valid": _cc_verify_raw(b(q["pub"]), b(q["h"]), sig)}
    if op == "ecdsa_recover":
        try:
            p = coincurve.PublicKey.from_signature_and_message(b(q["sig"]) + bytes([q["v"]]), b(q["h"]), hasher=None)
        except Exception as e:
            raise Refused(str(e))
        return {"c": h(p.format(True))}
    if op == "schnorr_sign":
        if len(b(q["m"])) != 32:
            return None   # coincurve signs 32-byte messages only (secp256k1_schnorrsig_sign32)
        k = coincurve.PrivateKey(b(q["sk"]))
        sig = k.sign_schnorr(b(q["m"]), b(q["aux"]))
        return {"sig": h(sig), "x": h(k.public_key_xonly.format())}
    if op == "schnorr_verify":
        if len(b(q["m"])) != 32:
            return None
        try:
            p = coincurve.PublicKeyXOnly(b(q["x"]))
        except Exception as e:
            raise Refused(str(e))
        return {"valid": bool(p.verify(b(q["sig"]), b(q["m"])))}
    return None


# ---------------------------------------------------------------------------------------------------------------
# OpenSSL, through cryptography

def _openssl_version():
    from cryptography.hazmat.backends.openssl.backend import backend
    return backend.openssl_version_text()


def _deterministic_available():
    try:
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        return True
    except TypeError:
        return False


def openssl_op(q):
    op = q["op"]
    if op == "ecdsa_sign":
        if not _deterministic_available():
            return None
        k = ec.derive_private_key(int(q["sk"], 16), ec.SECP256K1())
        der = k.sign(b(q["h"]), ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
        r, s = asym_utils.decode_dss_signature(der)
        return {"r": "%064x" % r, "s": "%064x" % s, "der": h(der)}   # OpenSSL does not normalise s
    if op in ("ecdsa_verify", "ecdsa_verify_der"):
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b(q["pub"]))
        except Exception as e:
            raise Refused(str(e))
        if op == "ecdsa_verify":
            rs = b(q["sig"])
            r, s = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
            if q.get("high_s") == "reject" and s > N // 2:
                return {"valid": False}
            if not (0 < r < N and 0 < s < N):
                return {"valid": False}
            der = asym_utils.encode_dss_signature(r, s)
        else:
            der = b(q["der"])
        try:
            pub.verify(der, b(q["h"]), ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
            return {"valid": True}
        except InvalidSignature:
            return {"valid": False}
    if op == "ed25519_sign":
        k = ed25519.Ed25519PrivateKey.from_private_bytes(b(q["seed"]))
        from cryptography.hazmat.primitives import serialization as ser
        pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        return {"pub": h(pub), "sig": h(k.sign(b(q["m"])))}
    if op == "ed25519_verify":
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(b(q["pub"]))
        except Exception as e:
            raise Refused(str(e))
        try:
            pub.verify(b(q["sig"]), b(q["m"]))
            return {"valid": True}
        except InvalidSignature:
            return {"valid": False}
    if op in ("chacha_seal", "chacha_open", "gcm_seal", "gcm_open"):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        c = (ChaCha20Poly1305 if op.startswith("chacha") else AESGCM)(b(q["k"]))
        if op.endswith("_seal"):
            out = c.encrypt(b(q["n"]), b(q["m"]), b(q["ad"]))
            return {"ct": h(out[:-16]), "tag": h(out[-16:])}
        try:
            return {"m": h(c.decrypt(b(q["n"]), b(q["ct"]) + b(q["tag"]), b(q["ad"])))}
        except InvalidSignature:
            raise Refused("authentication")
        except Exception as e:
            if type(e).__name__ == "InvalidTag":
                raise Refused("authentication")
            raise
    if op in ("jwe_ecdh_es_key", "jwe_open"):
        return _jwe_op(q)
    if op == "p256_pub":
        try:
            k = ec.derive_private_key(int(q["sk"], 16), ec.SECP256R1())
        except Exception as e:
            raise Refused(str(e))
        pub = k.public_key()
        return {"c": h(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)),
                "u": h(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))}
    if op == "p256_sign":
        k = ec.derive_private_key(int(q["sk"], 16), ec.SECP256R1())
        der = k.sign(b(q["h"]), ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
        r, s = asym_utils.decode_dss_signature(der)
        return {"r": "%064x" % r, "s": "%064x" % s}
    if op == "p256_pub_parse":
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b(q["pub"]))
        except Exception as e:
            raise Refused(str(e))
        return {"c": h(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))}
    if op == "p256_verify":
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b(q["pub"]))
        except Exception as e:
            raise Refused(str(e))
        rs = b(q["sig"])
        try:
            pub.verify(asym_utils.encode_dss_signature(int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")),
                       b(q["h"]), ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
            return {"valid": True}
        except InvalidSignature:
            return {"valid": False}
    if op.startswith("p384_"):
        return _p384_op(q)
    if op in ("rsa_verify_pkcs1", "rsa_verify_pss"):
        try:
            pub = rsa_lib.RSAPublicNumbers(int(q["e"], 16), int(q["n"], 16)).public_key()
        except Exception as e:
            raise Refused(str(e))
        pad = rsa_padding.PKCS1v15() if op == "rsa_verify_pkcs1" else \
            rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=q["salt"])
        try:
            pub.verify(b(q["sig"]), b(q["m"]), pad, hashes.SHA256())
            return {"valid": True}
        except InvalidSignature:
            return {"valid": False}
    if op == "rsa_sign_pkcs1":
        p_, q_, d_, e_, n_ = (int(q[k], 16) for k in ("p", "q", "d", "e", "n"))
        key = rsa_lib.RSAPrivateNumbers(p_, q_, d_, d_ % (p_ - 1), d_ % (q_ - 1), pow(q_, -1, p_),
                                        rsa_lib.RSAPublicNumbers(e_, n_)).private_key()
        return {"sig": h(key.sign(b(q["m"]), rsa_padding.PKCS1v15(), hashes.SHA256()))}
    if op == "rsa_parse_spki":
        try:
            k = serialization.load_der_public_key(b(q["der"]))
        except Exception as e:
            raise Refused(str(e))
        if not isinstance(k, rsa_lib.RSAPublicKey):
            raise Refused("not RSA")
        nums = k.public_numbers()
        return {"n": "%x" % nums.n, "e": "%x" % nums.e}
    if op == "x25519":
        try:
            out = x25519.X25519PrivateKey.from_private_bytes(b(q["k"])).exchange(
                x25519.X25519PublicKey.from_public_bytes(b(q["u"])))
        except Exception as e:
            raise Refused(str(e))
        return {"out": h(out)}
    return None


# ---------------------------------------------------------------------------------------------------------------
# libsodium, through PyNaCl

# JOSE's ECDH-ES (RFC 7518 4.6) from cryptography's parts: X25519 or ECDH on P-256, then ConcatKDFHash with the
# OtherInfo of RFC 7518 4.6.2 (AlgorithmID, PartyUInfo, PartyVInfo, each length-prefixed, then the key length in bits)
def _jwe_z(crv, rsk, epk):
    try:
        if crv == "X25519":
            return x25519.X25519PrivateKey.from_private_bytes(b(rsk)).exchange(x25519.X25519PublicKey.from_public_bytes(b(epk)))
        k = ec.derive_private_key(int(rsk, 16), ec.SECP256R1())
        return k.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b(epk)))
    except Exception as e:
        raise Refused(str(e))


def _jwe_kdf(z, alg, apu, apv, n):
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

    def field(x):
        return len(x).to_bytes(4, "big") + x
    other = field(alg.encode("ascii")) + field(apu) + field(apv) + (8 * n).to_bytes(4, "big")
    return ConcatKDFHash(algorithm=hashes.SHA256(), length=n, otherinfo=other).derive(z)


def _jwe_op(q):
    import base64
    if q["op"] == "jwe_ecdh_es_key":
        z = _jwe_z(q["crv"], q["rsk"], q["epk"])
        return {"k": h(_jwe_kdf(z, q["alg"], b(q["apu"]), b(q["apv"]), q["n"]))}
    # jwe_open: a compact JWE, ECDH-ES or ECDH-ES+A256KW with A256GCM, opened with the recipient's secret
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

    def d64(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    parts = q["jwe"].split(".")
    hdr = json.loads(d64(parts[0]))
    if hdr.get("enc") != "A256GCM" or hdr.get("alg") not in ("ECDH-ES", "ECDH-ES+A256KW"):
        return {"unsupported": True}
    epk = hdr["epk"]
    raw = d64(epk["x"]) if epk["crv"] == "X25519" else b"\x04" + d64(epk["x"]) + d64(epk["y"])
    if epk["crv"] != q["crv"]:
        raise Refused("curve")
    z = _jwe_z(q["crv"], q["rsk"], h(raw))
    apu, apv = d64(hdr.get("apu", "")), d64(hdr.get("apv", ""))
    if hdr["alg"] == "ECDH-ES":
        cek = _jwe_kdf(z, "A256GCM", apu, apv, 32)
    else:
        cek = aes_key_unwrap(_jwe_kdf(z, "ECDH-ES+A256KW", apu, apv, 32), d64(parts[1]))
    try:
        m = AESGCM(cek).decrypt(d64(parts[2]), d64(parts[3]) + d64(parts[4]), parts[0].encode("ascii"))
    except Exception:
        raise Refused("authentication")
    return {"m": h(m), "epk": h(raw)}


# P-384 through cryptography: keys, RFC 6979 signatures with SHA-384 (prehashed), verification, SEC1, ECDH
def _p384_op(q):
    op, curve = q["op"], ec.SECP384R1()

    def key(sk):
        try:
            return ec.derive_private_key(int(sk, 16), curve)
        except Exception as e:
            raise Refused(str(e))

    def pub(p):
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, b(p))
        except Exception as e:
            raise Refused(str(e))

    def enc(p, compressed):
        return h(p.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint if compressed
                                else serialization.PublicFormat.UncompressedPoint))
    if op == "p384_pub":
        k = key(q["sk"]).public_key()
        return {"c": enc(k, True), "u": enc(k, False)}
    if op == "p384_sign":
        der = key(q["sk"]).sign(b(q["h"]), ec.ECDSA(asym_utils.Prehashed(hashes.SHA384()), deterministic_signing=True))
        r, s = asym_utils.decode_dss_signature(der)
        return {"r": "%096x" % r, "s": "%096x" % s}
    if op == "p384_pub_parse":
        return {"c": enc(pub(q["pub"]), True)}
    if op == "p384_verify":
        p, rs = pub(q["pub"]), b(q["sig"])
        try:
            p.verify(asym_utils.encode_dss_signature(int.from_bytes(rs[:48], "big"), int.from_bytes(rs[48:], "big")),
                     b(q["h"]), ec.ECDSA(asym_utils.Prehashed(hashes.SHA384())))
            return {"valid": True}
        except InvalidSignature:
            return {"valid": False}
    if op == "p384_ecdh":
        return {"z": h(key(q["sk"]).exchange(ec.ECDH(), pub(q["pub"])))}
    return {"unsupported": True}


def _sodium_version():
    # PyNaCl links libsodium statically and exports neither sodium_version_string() nor the library version;
    # the AEGIS functions it carries date it to libsodium 1.0.19 or later
    from nacl._sodium import lib
    return "1.0.19 or later, bundled" if hasattr(lib, "crypto_aead_aegis256_encrypt") else "bundled"


def pynacl_op(q):
    op = q["op"]
    nb = nacl.bindings
    if op == "ed25519_sign":
        pk, sk = nb.crypto_sign_seed_keypair(b(q["seed"]))
        return {"pub": h(pk), "sig": h(nb.crypto_sign(b(q["m"]), sk)[:64])}
    if op == "ed25519_verify":
        pub, sig, m = b(q["pub"]), b(q["sig"]), b(q["m"])
        try:
            nb.crypto_sign_open(sig + m, pub)
            return {"valid": True}
        except nacl.exceptions.BadSignatureError:
            return {"valid": False}
        except Exception as e:
            raise Refused(str(e))
    if op in ("chacha_seal", "xchacha_seal"):
        f = nb.crypto_aead_chacha20poly1305_ietf_encrypt if op == "chacha_seal" else nb.crypto_aead_xchacha20poly1305_ietf_encrypt
        out = f(b(q["m"]), b(q["ad"]), b(q["n"]), b(q["k"]))
        return {"ct": h(out[:-16]), "tag": h(out[-16:])}
    if op in ("chacha_open", "xchacha_open"):
        f = nb.crypto_aead_chacha20poly1305_ietf_decrypt if op == "chacha_open" else nb.crypto_aead_xchacha20poly1305_ietf_decrypt
        try:
            return {"m": h(f(b(q["ct"]) + b(q["tag"]), b(q["ad"]), b(q["n"]), b(q["k"])))}
        except nacl.exceptions.CryptoError:
            raise Refused("authentication")
    if op == "x25519":
        try:
            return {"out": h(nb.crypto_scalarmult(b(q["k"]), b(q["u"])))}
        except Exception as e:
            raise Refused(str(e))
    return None


# ---------------------------------------------------------------------------------------------------------------
# python-mnemonic (BIP-39)

_MN = mnemonic_lib.Mnemonic("english")


def mnemonic_op(q):
    op = q["op"]
    if op == "bip39_from_entropy":
        try:
            return {"words": _MN.to_mnemonic(b(q["e"]))}
        except Exception as e:
            raise Refused(str(e))
    if op == "bip39_to_entropy":
        try:
            if not _MN.check(q["words"]):
                raise Refused("check")
            return {"e": h(_MN.to_entropy(q["words"]))}
        except Refused:
            raise
        except Exception as e:
            raise Refused(str(e))
    if op == "bip39_seed":
        return {"seed": h(mnemonic_lib.Mnemonic.to_seed(q["words"], q.get("pass", "")))}
    return None


# ---------------------------------------------------------------------------------------------------------------
# SLIP-10 reference (BIP-32 on secp256k1, SLIP-10 on Ed25519)

def slip10_op(q):
    op = q["op"]
    if op == "bip32":
        node = slip10_lib.SLIP10.from_seed(b(q["seed"]), curve_name="secp256k1")
        try:
            return {"xprv": node.get_xpriv_from_path(q["path"]), "xpub": node.get_xpub_from_path(q["path"])}
        except Exception as e:
            raise Refused(str(e))
    if op == "slip10_ed25519":
        node = slip10_lib.SLIP10.from_seed(b(q["seed"]), curve_name="ed25519")
        try:
            child = node.get_child_from_path(q["path"])
        except Exception as e:
            raise Refused(str(e))
        return {"key": h(child.get_privkey_from_path("m")), "chain": h(child.chaincode),
                "pub": h(child.get_pubkey_from_path("m")[-32:])}
    return None


# ---------------------------------------------------------------------------------------------------------------
# base58check and the BIP-173 / BIP-350 reference

def base58_op(q):
    op = q["op"]
    if op == "base58check_encode":
        return {"t": base58_lib.b58encode_check(b(q["p"])).decode()}
    if op == "base58check_decode":
        try:
            return {"p": h(base58_lib.b58decode_check(q["t"]))}
        except Exception as e:
            raise Refused(str(e))
    return None


def bip350_op(q):
    op = q["op"]
    if op == "segwit_encode":
        a = segwit_addr.encode(q["hrp"], q["ver"], list(b(q["prog"])))
        if a is None:
            raise Refused("encode")
        return {"addr": a}
    if op == "segwit_decode":
        ver, prog = segwit_addr.decode(q["hrp"], q["addr"])
        if ver is None:
            raise Refused("decode")
        return {"ver": ver, "prog": h(prog)}
    return None


LIBS = {
    "coincurve": (coincurve_op, lambda: coincurve.__version__,
                  ["sec_pub", "pub_parse", "ecdsa_sign", "ecdsa_verify", "ecdsa_verify_der", "ecdsa_recover",
                   "schnorr_sign", "schnorr_verify"]),
    "openssl": (openssl_op, lambda: "%s (cryptography %s)" % (_openssl_version(), cryptography.__version__),
                (["ecdsa_sign"] if _deterministic_available() else []) +
                ["ecdsa_verify", "ecdsa_verify_der", "ed25519_sign", "ed25519_verify", "x25519",
                 "rsa_sign_pkcs1", "rsa_verify_pkcs1", "rsa_verify_pss", "rsa_parse_spki",
                 "p256_pub", "p256_sign", "p256_verify", "p256_pub_parse", "chacha_seal", "chacha_open", "gcm_seal", "gcm_open",
                 "jwe_ecdh_es_key", "jwe_open", "p384_pub", "p384_sign", "p384_pub_parse", "p384_verify", "p384_ecdh"]),
    "pynacl": (pynacl_op, lambda: "libsodium %s (PyNaCl %s)" % (_sodium_version(), nacl.__version__),
               ["ed25519_sign", "ed25519_verify", "x25519", "chacha_seal", "chacha_open", "xchacha_seal", "xchacha_open"]),
    "mnemonic": (mnemonic_op, lambda: mnemonic_lib.__version__ if hasattr(mnemonic_lib, "__version__") else "0.21",
                 ["bip39_from_entropy", "bip39_to_entropy", "bip39_seed"]),
    "slip10": (slip10_op, lambda: _dist_version("slip10"), ["bip32", "slip10_ed25519"]),
    "base58": (base58_op, lambda: _dist_version("base58"), ["base58check_encode", "base58check_decode"]),
    "bip350_ref": (bip350_op, lambda: "sipa/bech32 " + open(os.path.join(os.path.dirname(segwit_addr.__file__),
                                                                         "COMMIT")).read().strip()[:12],
                   ["segwit_encode", "segwit_decode"]),
}


def _dist_version(name):
    from importlib.metadata import version
    return version(name)


def answer(q):
    if q.get("op") == "version":
        return {"oracle": "python", "libs": {k: {"version": v[1](), "ops": v[2]} for k, v in LIBS.items()}}
    lib = LIBS.get(q.get("lib"))
    if lib is None or q.get("op") not in lib[2]:
        return {"unsupported": True}
    try:
        out = lib[0](q)
    except Refused as e:
        return {"error": str(e) or "refused"}
    return {"unsupported": True} if out is None else out


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        q = json.loads(line)
        try:
            a = answer(q)
        except Exception:
            a = {"crash": traceback.format_exc(limit=3)}
        if "id" in q:
            a["id"] = q["id"]
        sys.stdout.write(json.dumps(a, separators=(",", ":")) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()

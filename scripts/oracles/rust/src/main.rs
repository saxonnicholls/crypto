//
//  main.rs
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The Rust oracles: one JSON object per line on stdin, one answer per line on stdout, in order (the protocol of
//  scripts/oracles/python/oracle.py). Test-only, built in docker/oracles against Cargo.lock; nothing here is part
//  of the library. The libraries:
//
//      k256            RustCrypto's k256: keys, ECDSA (RFC 6979), recovery, BIP-340
//      secp256k1_rs    rust-secp256k1, the Rust bindings to libsecp256k1 (its own vendored copy)
//      dalek           ed25519-dalek (verify, the RFC 8032 rule) and x25519-dalek
//      dalek_strict    ed25519-dalek's verify_strict
//      bip32_rs        the bip32 crate (on k256)
//      bip39_rs        the bip39 crate (rust-bitcoin)
//      bech32_rs       the bech32 crate (rust-bitcoin): segwit addresses
//      bs58_rs         bs58 with base58check
//      slip10_rs       slip10_ed25519
//

use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};
use std::str::FromStr;

struct Refused(String);
type Answer = Result<Value, Refused>;

fn r<E: std::fmt::Debug>(e: E) -> Refused {
    Refused(format!("{e:?}"))
}

fn bytes(q: &Value, k: &str) -> Vec<u8> {
    hex::decode(q[k].as_str().unwrap_or("")).expect("hex")
}

fn arr<const N: usize>(q: &Value, k: &str) -> Result<[u8; N], Refused> {
    bytes(q, k).try_into().map_err(|_| Refused(format!("{k}: not {N} bytes")))
}

fn text<'a>(q: &'a Value, k: &str) -> &'a str {
    q[k].as_str().unwrap_or("")
}

// ---------------------------------------------------------------------------------------------------------------
// k256

fn k256_op(op: &str, q: &Value) -> Option<Answer> {
    use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    Some((|| -> Answer {
        match op {
            "sec_pub" => {
                let sk = SigningKey::from_slice(&bytes(q, "sk")).map_err(r)?;
                let vk = sk.verifying_key();
                Ok(json!({"c": hex::encode(vk.to_sec1_bytes()),
                          "u": hex::encode(vk.to_sec1_point(false).as_bytes())}))
            }
            "pub_parse" => {
                let vk = VerifyingKey::from_sec1_bytes(&bytes(q, "pub")).map_err(r)?;
                Ok(json!({"c": hex::encode(vk.to_sec1_bytes())}))
            }
            "ecdsa_sign" => {
                let sk = SigningKey::from_slice(&bytes(q, "sk")).map_err(r)?;
                let (sig, id) = sk.sign_prehash_recoverable(&bytes(q, "h"));
                let rs = sig.to_bytes();
                Ok(json!({"r": hex::encode(&rs[..32]), "s": hex::encode(&rs[32..]), "v": id.to_byte(),
                          "der": hex::encode(sig.to_der().as_bytes())}))
            }
            "ecdsa_verify" => {
                let vk = VerifyingKey::from_sec1_bytes(&bytes(q, "pub")).map_err(r)?;
                let Ok(mut sig) = Signature::from_slice(&bytes(q, "sig")) else { return Ok(json!({"valid": false})) };
                // k256 verifies low-S only; "accept" is answered after its normalize_s
                if text(q, "high_s") == "accept" {
                    sig = sig.normalize_s();
                }
                Ok(json!({"valid": vk.verify_prehash(&bytes(q, "h"), &sig).is_ok()}))
            }
            "ecdsa_verify_der" => {
                let vk = VerifyingKey::from_sec1_bytes(&bytes(q, "pub")).map_err(r)?;
                let sig = Signature::from_der(&bytes(q, "der")).map_err(r)?;
                Ok(json!({"rs": hex::encode(sig.to_bytes()), "valid": vk.verify_prehash(&bytes(q, "h"), &sig).is_ok()}))
            }
            "ecdsa_recover" => {
                let sig = Signature::from_slice(&bytes(q, "sig")).map_err(r)?;
                let id = RecoveryId::from_byte(q["v"].as_u64().unwrap_or(9) as u8).ok_or(Refused("recid".into()))?;
                let vk = VerifyingKey::recover_from_prehash(&bytes(q, "h"), &sig, id).map_err(r)?;
                Ok(json!({"c": hex::encode(vk.to_sec1_bytes())}))
            }
            "schnorr_sign" => {
                let sk = k256::schnorr::SigningKey::from_bytes(&arr::<32>(q, "sk")?.into()).map_err(r)?;
                let sig = sk.sign_raw(&bytes(q, "m"), &arr::<32>(q, "aux")?).map_err(r)?;
                Ok(json!({"sig": hex::encode(sig.to_bytes()), "x": hex::encode(sk.verifying_key().to_bytes())}))
            }
            "schnorr_verify" => {
                let vk = k256::schnorr::VerifyingKey::from_bytes(&arr::<32>(q, "x")?.into()).map_err(r)?;
                let Ok(sig) = k256::schnorr::Signature::try_from(bytes(q, "sig").as_slice()) else {
                    return Ok(json!({"valid": false}));
                };
                Ok(json!({"valid": vk.verify_raw(&bytes(q, "m"), &sig).is_ok()}))
            }
            _ => Err(Refused("unsupported".into())),
        }
    })())
}

// ---------------------------------------------------------------------------------------------------------------
// rust-secp256k1 (libsecp256k1)

fn secp_op(op: &str, q: &Value) -> Option<Answer> {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
    use secp256k1::{Keypair, Message, PublicKey, SecretKey, XOnlyPublicKey};
    Some((|| -> Answer {
        match op {
            "sec_pub" => {
                let sk = SecretKey::from_secret_bytes(arr::<32>(q, "sk")?).map_err(r)?;
                let pk = PublicKey::from_secret_key(&sk);
                Ok(json!({"c": hex::encode(pk.serialize()), "u": hex::encode(pk.serialize_uncompressed())}))
            }
            "pub_parse" => {
                let pk = PublicKey::from_slice(&bytes(q, "pub")).map_err(r)?;
                Ok(json!({"c": hex::encode(pk.serialize())}))
            }
            "ecdsa_sign" => {
                let sk = SecretKey::from_secret_bytes(arr::<32>(q, "sk")?).map_err(r)?;
                let msg = Message::from_digest(arr::<32>(q, "h")?);
                let (id, rs) = RecoverableSignature::sign_ecdsa_recoverable(msg, &sk).serialize_compact();
                let der = secp256k1::ecdsa::sign(msg, &sk).serialize_der();
                Ok(json!({"r": hex::encode(&rs[..32]), "s": hex::encode(&rs[32..]), "v": u8::from(id),
                          "der": hex::encode(&der[..])}))
            }
            "ecdsa_verify" => {
                let pk = PublicKey::from_slice(&bytes(q, "pub")).map_err(r)?;
                // from_compact refuses r or s at or above n
                let Ok(mut sig) = Signature::from_compact(&bytes(q, "sig")) else { return Ok(json!({"valid": false})) };
                if text(q, "high_s") == "accept" {
                    sig.normalize_s();
                }
                Ok(json!({"valid": sig.verify(Message::from_digest(arr::<32>(q, "h")?), &pk).is_ok()}))
            }
            "ecdsa_verify_der" => {
                let pk = PublicKey::from_slice(&bytes(q, "pub")).map_err(r)?;
                let sig = Signature::from_der(&bytes(q, "der")).map_err(r)?;
                Ok(json!({"rs": hex::encode(sig.serialize_compact()),
                          "valid": sig.verify(Message::from_digest(arr::<32>(q, "h")?), &pk).is_ok()}))
            }
            "ecdsa_recover" => {
                let id = RecoveryId::try_from(q["v"].as_i64().unwrap_or(9) as i32).map_err(r)?;
                let sig = RecoverableSignature::from_compact(&bytes(q, "sig"), id).map_err(r)?;
                let pk = sig.recover(Message::from_digest(arr::<32>(q, "h")?)).map_err(r)?;
                Ok(json!({"c": hex::encode(pk.serialize())}))
            }
            "schnorr_sign" => {
                let kp = Keypair::from_secret_bytes(arr::<32>(q, "sk")?).map_err(r)?;
                let sig = secp256k1::schnorr::sign_with_aux_rand(&bytes(q, "m"), &kp, &arr::<32>(q, "aux")?);
                Ok(json!({"sig": hex::encode(sig.to_byte_array()), "x": hex::encode(kp.x_only_public_key().0.to_byte_array())}))
            }
            "schnorr_verify" => {
                let pk = XOnlyPublicKey::from_byte_array(arr::<32>(q, "x")?).map_err(r)?;
                let sig = secp256k1::schnorr::Signature::from_byte_array(arr::<64>(q, "sig")?);
                Ok(json!({"valid": secp256k1::schnorr::verify(&sig, &bytes(q, "m"), &pk).is_ok()}))
            }
            _ => Err(Refused("unsupported".into())),
        }
    })())
}

// ---------------------------------------------------------------------------------------------------------------
// ed25519-dalek and x25519-dalek

fn dalek_op(op: &str, q: &Value, strict: bool) -> Option<Answer> {
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    Some((|| -> Answer {
        match (op, strict) {
            ("ed25519_sign", false) => {
                let sk = SigningKey::from_bytes(&arr::<32>(q, "seed")?);
                use ed25519_dalek::Signer;
                Ok(json!({"pub": hex::encode(sk.verifying_key().to_bytes()),
                          "sig": hex::encode(sk.sign(&bytes(q, "m")).to_bytes())}))
            }
            ("ed25519_verify", _) => {
                let vk = VerifyingKey::from_bytes(&arr::<32>(q, "pub")?).map_err(r)?;
                let sig = Signature::from_bytes(&arr::<64>(q, "sig")?);
                let m = bytes(q, "m");
                let ok = if strict { vk.verify_strict(&m, &sig).is_ok() } else {
                    use ed25519_dalek::Verifier;
                    vk.verify(&m, &sig).is_ok()
                };
                Ok(json!({"valid": ok}))
            }
            ("x25519", false) => {
                let k = x25519_dalek::StaticSecret::from(arr::<32>(q, "k")?);
                let shared = k.diffie_hellman(&x25519_dalek::PublicKey::from(arr::<32>(q, "u")?));
                if !shared.was_contributory() {
                    return Err(Refused("non-contributory (all-zero) result".into()));
                }
                Ok(json!({"out": hex::encode(shared.as_bytes())}))
            }
            _ => Err(Refused("unsupported".into())),
        }
    })())
}

// ---------------------------------------------------------------------------------------------------------------
// BIP-32, BIP-39, SLIP-10 and the address encodings

fn bip32_op(op: &str, q: &Value) -> Option<Answer> {
    Some((|| -> Answer {
        if op == "path_parse" {
            let path = bip32::DerivationPath::from_str(text(q, "path")).map_err(r)?;
            let indices: Vec<String> = path.iter().map(|c| u32::from(c).to_string()).collect();
            return Ok(json!({"indices": indices.join(",")}));
        }
        if op != "bip32" {
            return Err(Refused("unsupported".into()));
        }
        let path = bip32::DerivationPath::from_str(text(q, "path")).map_err(r)?;
        let key = bip32::XPrv::derive_from_path(&bytes(q, "seed"), &path).map_err(r)?;
        Ok(json!({"xprv": key.to_string(bip32::Prefix::XPRV).as_str(),
                  "xpub": key.public_key().to_string(bip32::Prefix::XPUB)}))
    })())
}

fn bip39_op(op: &str, q: &Value) -> Option<Answer> {
    Some((|| -> Answer {
        match op {
            "bip39_from_entropy" => {
                let m = bip39::Mnemonic::from_entropy(&bytes(q, "e")).map_err(r)?;
                Ok(json!({"words": m.to_string()}))
            }
            "bip39_to_entropy" => {
                let m = bip39::Mnemonic::parse_normalized(text(q, "words")).map_err(r)?;
                Ok(json!({"e": hex::encode(m.to_entropy())}))
            }
            "bip39_seed" => {
                let m = bip39::Mnemonic::parse_normalized(text(q, "words")).map_err(r)?;
                Ok(json!({"seed": hex::encode(m.to_seed_normalized(text(q, "pass")))}))
            }
            _ => Err(Refused("unsupported".into())),
        }
    })())
}

fn slip10_op(op: &str, q: &Value) -> Option<Answer> {
    Some((|| -> Answer {
        if op != "slip10_ed25519" {
            return Err(Refused("unsupported".into()));
        }
        // slip10_ed25519 takes the indices without the hardened bit and hardens every one, as SLIP-10 requires
        let mut indexes = Vec::new();
        for (n, part) in text(q, "path").split('/').enumerate() {
            if n == 0 {
                if part != "m" { return Err(Refused("path".into())); }
                continue;
            }
            let i = part.strip_suffix('\'').ok_or(Refused("non-hardened".into()))?;
            indexes.push(i.parse::<u32>().map_err(r)?);
        }
        let key = slip10_ed25519::derive_ed25519_private_key(&bytes(q, "seed"), &indexes);
        let pk = ed25519_dalek::SigningKey::from_bytes(&key).verifying_key();
        Ok(json!({"key": hex::encode(key), "pub": hex::encode(pk.to_bytes())}))
    })())
}

fn bech32_op(op: &str, q: &Value) -> Option<Answer> {
    Some((|| -> Answer {
        match op {
            "segwit_encode" => {
                let hrp = bech32::Hrp::parse(text(q, "hrp")).map_err(r)?;
                let ver = bech32::Fe32::try_from(q["ver"].as_u64().unwrap_or(99) as u8).map_err(r)?;
                Ok(json!({"addr": bech32::segwit::encode(hrp, ver, &bytes(q, "prog")).map_err(r)?}))
            }
            "segwit_decode" => {
                let (hrp, ver, prog) = bech32::segwit::decode(text(q, "addr")).map_err(r)?;
                if hrp.to_lowercase() != text(q, "hrp") {
                    return Err(Refused("hrp".into()));
                }
                Ok(json!({"ver": ver.to_u8(), "prog": hex::encode(prog)}))
            }
            _ => Err(Refused("unsupported".into())),
        }
    })())
}

fn bs58_op(op: &str, q: &Value) -> Option<Answer> {
    Some((|| -> Answer {
        match op {
            "base58check_encode" => Ok(json!({"t": bs58::encode(bytes(q, "p")).with_check().into_string()})),
            "base58check_decode" => {
                let p = bs58::decode(text(q, "t")).with_check(None).into_vec().map_err(r)?;
                Ok(json!({"p": hex::encode(p)}))
            }
            _ => Err(Refused("unsupported".into())),
        }
    })())
}

// ---------------------------------------------------------------------------------------------------------------

type OpFn = fn(&str, &Value) -> Option<Answer>;

const LIBS: &[(&str, &str, OpFn, &[&str])] = &[
    ("k256", "k256 0.14.0", k256_op,
     &["sec_pub", "pub_parse", "ecdsa_sign", "ecdsa_verify", "ecdsa_verify_der", "ecdsa_recover", "schnorr_sign", "schnorr_verify"]),
    ("secp256k1_rs", "secp256k1 0.33.1 (secp256k1-sys 0.14.1)", secp_op,
     &["sec_pub", "pub_parse", "ecdsa_sign", "ecdsa_verify", "ecdsa_verify_der", "ecdsa_recover", "schnorr_sign", "schnorr_verify"]),
    ("dalek", "ed25519-dalek 3.0.0, x25519-dalek 3.0.0", |op, q| dalek_op(op, q, false),
     &["ed25519_sign", "ed25519_verify", "x25519"]),
    ("dalek_strict", "ed25519-dalek 3.0.0 (verify_strict)", |op, q| dalek_op(op, q, true), &["ed25519_verify"]),
    ("bip32_rs", "bip32 0.6.0", bip32_op, &["bip32", "path_parse"]),
    ("bip39_rs", "bip39 3.0.0", bip39_op, &["bip39_from_entropy", "bip39_to_entropy", "bip39_seed"]),
    ("slip10_rs", "slip10_ed25519 0.1.3", slip10_op, &["slip10_ed25519"]),
    ("bech32_rs", "bech32 0.12.0", bech32_op, &["segwit_encode", "segwit_decode"]),
    ("bs58_rs", "bs58 0.5.1", bs58_op, &["base58check_encode", "base58check_decode"]),
];

fn answer(q: &Value) -> Value {
    let op = text(q, "op");
    if op == "version" {
        let mut libs = Map::new();
        for (name, version, _, ops) in LIBS {
            libs.insert(name.to_string(), json!({"version": version, "ops": ops}));
        }
        return json!({"oracle": "rust", "libs": libs});
    }
    let lib = text(q, "lib");
    let Some((_, _, f, ops)) = LIBS.iter().find(|l| l.0 == lib) else { return json!({"unsupported": true}) };
    if !ops.contains(&op) {
        return json!({"unsupported": true});
    }
    match std::panic::catch_unwind(|| f(op, q)) {
        Ok(Some(Ok(v))) => v,
        Ok(Some(Err(Refused(e)))) => json!({"error": e}),
        Ok(None) => json!({"unsupported": true}),
        Err(_) => json!({"crash": "panic"}),
    }
}

fn main() {
    // A panic inside an operation is answered {"crash": ...}; any panic is also reported on stderr, so an oracle
    // that dies says why
    std::panic::set_hook(Box::new(|info| eprintln!("rust oracle: {info}")));
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        if line.trim().is_empty() {
            continue;
        }
        let q: Value = serde_json::from_str(&line).expect("json");
        let mut a = answer(&q);
        if let Some(id) = q.get("id") {
            a["id"] = id.clone();
        }
        writeln!(out, "{a}").expect("stdout");
        out.flush().expect("stdout");
    }
}

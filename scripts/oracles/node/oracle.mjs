//
//  oracle.mjs
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The Node oracles: one JSON object per line on stdin, one answer per line on stdout, in order (the protocol of
//  scripts/oracles/python/oracle.py). Test-only, run in docker/oracles against the packages of package-lock.json;
//  nothing here is part of the library. The libraries:
//
//      noble_secp256k1   @noble/secp256k1 (what ethers and viem build on): keys, ECDSA, recovery, BIP-340
//      noble_ed25519     @noble/curves ed25519 with RFC 8032 verification (zip215: false)
//      noble_zip215      @noble/curves ed25519 with its default, ZIP-215 verification
//      noble_x25519      @noble/curves x25519
//      noble_p384        @noble/curves p384: keys, RFC 6979 signatures with SHA-384, verification, SEC1, ECDH
//      ethers            ethers v6: ECDSA (SigningKey), ecrecover addresses, BIP-39 and BIP-32 (HDNodeWallet)
//      bitcoinjs         bip32 on tiny-secp256k1, bitcoinjs-lib addresses, bs58check
//      scure_bip39       @scure/bip39
//      ed25519_hd_key    ed25519-hd-key: SLIP-10 Ed25519
//      node_crypto       Node's built-in crypto (its bundled OpenSSL): RSA PKCS#1 v1.5 and PSS, SPKI
//      jose              panva's jose: whole JWEs, ECDH-ES and ECDH-ES+A256KW with A256GCM on X25519 and P-256
//

import * as secp from "@noble/secp256k1";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { p256, p384 } from "@noble/curves/nist.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as bip39 from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { BIP32Factory } from "bip32";
import * as bitcoin from "bitcoinjs-lib";
import bs58check from "bs58check";
import * as hdkey from "ed25519-hd-key";
import { ethers } from "ethers";
import * as jose from "jose";
import * as ecc from "tiny-secp256k1";
import { constants, createCipheriv, createDecipheriv, createECDH, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";

secp.hashes.sha256 = sha256;
secp.hashes.hmacSha256 = (k, m) => hmac(sha256, k, m);
const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const hex = (u) => Buffer.from(u).toString("hex");
const bytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const pad = (n) => n.toString(16).padStart(64, "0");

class Refused extends Error {}

function rsaVerify(q, options) {
  const b64 = (h) => Buffer.from(h.length % 2 ? "0" + h : h, "hex").toString("base64url");
  const key = refuse(() => createPublicKey({ format: "jwk", key: { kty: "RSA", n: b64(q.n), e: b64(q.e) } }));
  let valid;
  try {
    valid = cryptoVerify("sha256", bytes(q.m), { key, ...options }, bytes(q.sig));
  } catch {
    valid = false;
  }
  return { valid };
}
const refuse = (f) => {
  try {
    return f();
  } catch (e) {
    throw new Refused(String(e && e.message ? e.message : e));
  }
};

// Read from node_modules directly: not every package exports its package.json
const version = (name) =>
  JSON.parse(readFileSync(join(import.meta.dirname, "node_modules", name, "package.json"), "utf8")).version;

// Key objects from raw bytes: X25519 (the u-coordinate; the secret as PKCS#8) and P-256 (SEC1; the secret as a
// SEC1 ECPrivateKey without its public key, which OpenSSL computes)
const b64u = (u) => Buffer.from(u).toString("base64url");
function joseKey(crv, pub, secret) {
  if (secret)
    return crv === "X25519"
      ? createPrivateKey({ format: "der", type: "pkcs8", key: Buffer.from("302e020100300506032b656e04220420" + secret, "hex") })
      : createPrivateKey({ format: "der", type: "sec1", key: Buffer.from("30310201010420" + secret + "a00a06082a8648ce3d030107", "hex") });
  const u = bytes(pub);
  return createPublicKey({ format: "jwk", key: crv === "X25519" ? { kty: "OKP", crv, x: b64u(u) }
    : { kty: "EC", crv, x: b64u(u.slice(1, 33)), y: b64u(u.slice(33)) } });
}

const LIBS = {
  noble_secp256k1: {
    name: "@noble/secp256k1",
    ops: {
      sec_pub: (q) => {
        const sk = bytes(q.sk);
        refuse(() => {
          if (!secp.utils.isValidSecretKey(sk)) throw new Error("invalid secret key");
        });
        return { c: hex(secp.getPublicKey(sk, true)), u: hex(secp.getPublicKey(sk, false)) };
      },
      pub_parse: (q) => ({ c: hex(refuse(() => secp.Point.fromBytes(bytes(q.pub)).toBytes(true))) }),
      ecdsa_sign: (q) => {
        const raw = secp.sign(bytes(q.h), bytes(q.sk), { prehash: false, format: "recovered" });
        const sig = secp.Signature.fromBytes(raw, "recovered");
        return { r: pad(sig.r), s: pad(sig.s), v: sig.recovery };
      },
      ecdsa_verify: (q) => {
        const pub = bytes(q.pub);
        refuse(() => secp.Point.fromBytes(pub));
        const lowS = q.high_s !== "accept";
        let valid;
        try {
          valid = secp.verify(bytes(q.sig), bytes(q.h), pub, { prehash: false, lowS });
        } catch {
          valid = false; // r or s out of range: noble throws while reading the signature
        }
        return { valid };
      },
      ecdsa_recover: (q) => {
        const rs = bytes(q.sig);
        const sig = new Uint8Array(65);
        sig[0] = q.v;
        sig.set(rs, 1);
        return { c: hex(refuse(() => secp.recoverPublicKey(sig, bytes(q.h), { prehash: false }))) };
      },
      schnorr_sign: (q) => {
        const sk = bytes(q.sk);
        return { sig: hex(secp.schnorr.sign(bytes(q.m), sk, bytes(q.aux))), x: hex(secp.schnorr.getPublicKey(sk)) };
      },
      schnorr_verify: (q) => ({ valid: secp.schnorr.verify(bytes(q.sig), bytes(q.m), bytes(q.x)) }),
    },
  },
  noble_p256: {
    name: "@noble/curves",
    ops: {
      p256_pub: (q) => {
        const sk = bytes(q.sk);
        refuse(() => {
          if (!p256.utils.isValidSecretKey(sk)) throw new Error("invalid secret key");
        });
        return { c: hex(p256.getPublicKey(sk, true)), u: hex(p256.getPublicKey(sk, false)) };
      },
      p256_sign: (q) => {
        const sig = p256.Signature.fromBytes(p256.sign(bytes(q.h), bytes(q.sk), { prehash: false, lowS: false }));
        return { r: pad(sig.r), s: pad(sig.s) };
      },
      p256_pub_parse: (q) => ({ c: hex(refuse(() => p256.Point.fromBytes(bytes(q.pub)).toBytes(true))) }),
      p256_verify: (q) => {
        refuse(() => p256.Point.fromBytes(bytes(q.pub)));
        let valid;
        try {
          valid = p256.verify(bytes(q.sig), bytes(q.h), bytes(q.pub), { prehash: false, lowS: false });
        } catch {
          valid = false;
        }
        return { valid };
      },
    },
  },
  noble_p384: {
    name: "@noble/curves",
    ops: {
      p384_pub: (q) => {
        const sk = bytes(q.sk);
        refuse(() => {
          if (!p384.utils.isValidSecretKey(sk)) throw new Error("invalid secret key");
        });
        return { c: hex(p384.getPublicKey(sk, true)), u: hex(p384.getPublicKey(sk, false)) };
      },
      p384_sign: (q) => {
        const sig = p384.Signature.fromBytes(p384.sign(bytes(q.h), bytes(q.sk), { prehash: false, lowS: false }));
        return { r: sig.r.toString(16).padStart(96, "0"), s: sig.s.toString(16).padStart(96, "0") };
      },
      p384_pub_parse: (q) => ({ c: hex(refuse(() => p384.Point.fromBytes(bytes(q.pub)).toBytes(true))) }),
      p384_verify: (q) => {
        refuse(() => p384.Point.fromBytes(bytes(q.pub)));
        let valid;
        try {
          valid = p384.verify(bytes(q.sig), bytes(q.h), bytes(q.pub), { prehash: false, lowS: false });
        } catch {
          valid = false;
        }
        return { valid };
      },
      // the shared point, compressed: its x-coordinate after the prefix byte
      p384_ecdh: (q) => ({ z: hex(refuse(() => p384.getSharedSecret(bytes(q.sk), bytes(q.pub), true)).slice(1)) }),
    },
  },
  noble_ed25519: {
    name: "@noble/curves",
    ops: {
      ed25519_sign: (q) => {
        const seed = bytes(q.seed);
        return { pub: hex(ed25519.getPublicKey(seed)), sig: hex(ed25519.sign(bytes(q.m), seed)) };
      },
      ed25519_verify: (q) => {
        let valid;
        try {
          valid = ed25519.verify(bytes(q.sig), bytes(q.m), bytes(q.pub), { zip215: false });
        } catch {
          valid = false;
        }
        return { valid };
      },
    },
  },
  noble_zip215: {
    name: "@noble/curves",
    ops: {
      ed25519_verify: (q) => {
        let valid;
        try {
          valid = ed25519.verify(bytes(q.sig), bytes(q.m), bytes(q.pub), { zip215: true });
        } catch {
          valid = false;
        }
        return { valid };
      },
    },
  },
  noble_x25519: {
    name: "@noble/curves",
    ops: {
      x25519: (q) => ({ out: hex(refuse(() => x25519.getSharedSecret(bytes(q.k), bytes(q.u)))) }),
    },
  },
  ethers: {
    name: "ethers",
    ops: {
      sec_pub: (q) => {
        // ethers checks the range only when the key is first used, not in the constructor
        return refuse(() => {
          const k = new ethers.SigningKey("0x" + q.sk);
          return { c: k.compressedPublicKey.slice(2), u: k.publicKey.slice(2) };
        });
      },
      ecdsa_sign: (q) => {
        const sig = new ethers.SigningKey("0x" + q.sk).sign("0x" + q.h);
        return { r: sig.r.slice(2), s: sig.s.slice(2), v: sig.v - 27 };
      },
      ecdsa_recover: (q) => {
        if (q.v > 1) return { unsupported: true }; // ethers' v is 27 or 28: recovery ids 2 and 3 have no v
        return refuse(() => {
          const sig = ethers.Signature.from({ r: "0x" + q.sig.slice(0, 64), s: "0x" + q.sig.slice(64), v: 27 + q.v });
          return { c: ethers.SigningKey.computePublicKey(ethers.SigningKey.recoverPublicKey("0x" + q.h, sig), true).slice(2) };
        });
      },
      // Ethereum's ecrecover: the address of the key recovered from a 65-byte r || s || v signature, v = 27 or 28
      eth_ecrecover: (q) => {
        const raw = bytes(q.sig65);
        const sig = refuse(() =>
          ethers.Signature.from({ r: "0x" + q.sig65.slice(0, 64), s: "0x" + q.sig65.slice(64, 128), v: raw[64] }),
        );
        return { addr: refuse(() => ethers.recoverAddress("0x" + q.h, sig)).slice(2).toLowerCase() };
      },
      eth_address: (q) => ({ addr: ethers.computeAddress("0x" + q.pub).slice(2).toLowerCase() }),
      bip39_from_entropy: (q) => ({ words: refuse(() => ethers.Mnemonic.fromEntropy("0x" + q.e).phrase) }),
      bip39_to_entropy: (q) => ({ e: refuse(() => ethers.Mnemonic.fromPhrase(q.words).entropy).slice(2) }),
      bip39_seed: (q) => ({ seed: ethers.Mnemonic.fromPhrase(q.words, q.pass || "").computeSeed().slice(2) }),
      bip32: (q) => {
        const node = refuse(() => ethers.HDNodeWallet.fromSeed("0x" + q.seed).derivePath(q.path));
        return { xprv: node.extendedKey, xpub: node.neuter().extendedKey };
      },
    },
  },
  bitcoinjs: {
    name: "bitcoinjs-lib",
    ops: {
      bip32: (q) => {
        const node = refuse(() => bip32.fromSeed(Buffer.from(q.seed, "hex")).derivePath(q.path));
        return { xprv: node.toBase58(), xpub: node.neutered().toBase58() };
      },
      base58check_encode: (q) => ({ t: bs58check.encode(bytes(q.p)) }),
      base58check_decode: (q) => ({ p: hex(refuse(() => bs58check.decode(q.t))) }),
      segwit_encode: (q) => ({ addr: refuse(() => bitcoin.address.toBech32(bytes(q.prog), q.ver, q.hrp)) }),
      segwit_decode: (q) => {
        const d = refuse(() => bitcoin.address.fromBech32(q.addr));
        if (d.prefix !== q.hrp) throw new Refused("prefix");
        return { ver: d.version, prog: hex(d.data) };
      },
      // The standard addresses of one public key: P2PKH, P2SH-P2WPKH (BIP-49), P2WPKH (BIP-84), and P2TR with the
      // key as the BIP-86 internal key (the output key tweaked by bitcoinjs)
      addresses: (q) => {
        const pubkey = bytes(q.pub);
        const network = q.testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
        const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network });
        return {
          p2pkh: bitcoin.payments.p2pkh({ pubkey, network }).address,
          p2sh_p2wpkh: bitcoin.payments.p2sh({ redeem: p2wpkh, network }).address,
          p2wpkh: p2wpkh.address,
          p2tr: bitcoin.payments.p2tr({ internalPubkey: pubkey.slice(1, 33), network }).address,
          p2tr_output: hex(bitcoin.payments.p2tr({ internalPubkey: pubkey.slice(1, 33), network }).pubkey),
        };
      },
    },
  },
  node_crypto: {
    name: "node",
    ops: {
      // RSA through Node's own crypto (its bundled OpenSSL): keys as JWK, hex fields from the request
      rsa_sign_pkcs1: (q) => {
        const b64 = (h) => Buffer.from(h.length % 2 ? "0" + h : h, "hex").toString("base64url");
        const big = (h) => BigInt("0x" + h);
        const hx = (v) => v.toString(16);
        const p = big(q.p), qq = big(q.q), d = big(q.d);
        const inv = (a, m) => {
          let [r0, r1, s0, s1] = [a % m, m, 1n, 0n];
          while (r1) { const t = r0 / r1; [r0, r1] = [r1, r0 - t * r1]; [s0, s1] = [s1, s0 - t * s1]; }
          return ((s0 % m) + m) % m;
        };
        const key = createPrivateKey({
          format: "jwk",
          key: { kty: "RSA", n: b64(q.n), e: b64(q.e), d: b64(q.d), p: b64(q.p), q: b64(q.q),
                 dp: b64(hx(d % (p - 1n))), dq: b64(hx(d % (qq - 1n))), qi: b64(hx(inv(qq, p))) },
        });
        return { sig: hex(cryptoSign("sha256", bytes(q.m), { key, padding: constants.RSA_PKCS1_PADDING })) };
      },
      rsa_verify_pkcs1: (q) => rsaVerify(q, { padding: constants.RSA_PKCS1_PADDING }),
      rsa_verify_pss: (q) => rsaVerify(q, { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: q.salt }),
      gcm_seal: (q) => {
        const c = createCipheriv(`aes-${q.k.length * 4}-gcm`, bytes(q.k), bytes(q.n), { authTagLength: 16 });
        c.setAAD(bytes(q.ad));
        const ct = Buffer.concat([c.update(bytes(q.m)), c.final()]);
        return { ct: hex(ct), tag: hex(c.getAuthTag()) };
      },
      gcm_open: (q) => {
        const d = createDecipheriv(`aes-${q.k.length * 4}-gcm`, bytes(q.k), bytes(q.n), { authTagLength: 16 });
        d.setAAD(bytes(q.ad));
        d.setAuthTag(bytes(q.tag));
        return { m: hex(refuse(() => Buffer.concat([d.update(bytes(q.ct)), d.final()]))) };
      },
      chacha_seal: (q) => {
        const c = createCipheriv("chacha20-poly1305", bytes(q.k), bytes(q.n), { authTagLength: 16 });
        c.setAAD(bytes(q.ad), { plaintextLength: q.m.length / 2 });
        const ct = Buffer.concat([c.update(bytes(q.m)), c.final()]);
        return { ct: hex(ct), tag: hex(c.getAuthTag()) };
      },
      chacha_open: (q) => {
        const d = createDecipheriv("chacha20-poly1305", bytes(q.k), bytes(q.n), { authTagLength: 16 });
        d.setAAD(bytes(q.ad), { plaintextLength: q.ct.length / 2 });
        d.setAuthTag(bytes(q.tag));
        return { m: hex(refuse(() => Buffer.concat([d.update(bytes(q.ct)), d.final()]))) };
      },
      // ES256 as JOSE signs it: Node hashes the message itself; the signature is r || s (IEEE P1363)
      p256_verify: (q) => {
        const u = bytes(q.pub);
        if (u.length !== 65) return { unsupported: true };
        const key = refuse(() => createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256",
          x: Buffer.from(u.slice(1, 33)).toString("base64url"), y: Buffer.from(u.slice(33)).toString("base64url") } }));
        let valid;
        try {
          valid = cryptoVerify("sha256", bytes(q.m), { key, dsaEncoding: "ieee-p1363" }, bytes(q.sig));
        } catch {
          valid = false;
        }
        return { valid };
      },
      // ES384 as JOSE signs it (Node hashes the message with SHA-384), uncompressed keys
      p384_verify: (q) => {
        const u = bytes(q.pub);
        if (u.length !== 97) return { unsupported: true };
        const key = refuse(() => createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-384",
          x: Buffer.from(u.slice(1, 49)).toString("base64url"), y: Buffer.from(u.slice(49)).toString("base64url") } }));
        let valid;
        try {
          valid = cryptoVerify("sha384", bytes(q.m), { key, dsaEncoding: "ieee-p1363" }, bytes(q.sig));
        } catch {
          valid = false;
        }
        return { valid };
      },
      p384_ecdh: (q) => {
        const e = createECDH("secp384r1");
        e.setPrivateKey(Buffer.from(q.sk, "hex"));
        return { z: hex(refuse(() => e.computeSecret(Buffer.from(q.pub, "hex")))) };
      },
      rsa_parse_spki: (q) => {
        const k = refuse(() => createPublicKey({ key: Buffer.from(q.der, "hex"), format: "der", type: "spki" }));
        if (k.asymmetricKeyType !== "rsa") throw new Refused("not RSA");
        const j = k.export({ format: "jwk" });
        const h = (x) => Buffer.from(x, "base64url").toString("hex").replace(/^0+/, "");
        return { n: h(j.n), e: h(j.e) };
      },
    },
  },
  jose: {
    name: "jose",
    ops: {
      // A compact JWE to the recipient's key, every random choice fixed (the ephemeral key, the IV and, with key
      // wrapping, the CEK) so the answer is deterministic
      jwe_ecdh_es: async (q) => {
        const params = { epk: joseKey(q.crv, null, q.esk) };
        if (q.apu) params.apu = bytes(q.apu);
        if (q.apv) params.apv = bytes(q.apv);
        const e = new jose.CompactEncrypt(bytes(q.m)).setProtectedHeader({ alg: q.alg, enc: "A256GCM" })
          .setKeyManagementParameters(params).setInitializationVector(bytes(q.iv));
        if (q.cek) e.setContentEncryptionKey(bytes(q.cek));
        return { jwe: await e.encrypt(joseKey(q.crv, q.rpub)) };
      },
    },
  },
  scure_bip39: {
    name: "@scure/bip39",
    ops: {
      bip39_from_entropy: (q) => ({ words: refuse(() => bip39.entropyToMnemonic(bytes(q.e), english)) }),
      bip39_to_entropy: (q) => ({ e: hex(refuse(() => bip39.mnemonicToEntropy(q.words, english))) }),
      bip39_seed: (q) => ({ seed: hex(bip39.mnemonicToSeedSync(q.words, q.pass || "")) }),
    },
  },
  ed25519_hd_key: {
    name: "ed25519-hd-key",
    ops: {
      slip10_ed25519: (q) => {
        const k = refuse(() => hdkey.derivePath(q.path, q.seed));
        return { key: hex(k.key), chain: hex(k.chainCode), pub: hex(hdkey.getPublicKey(k.key, false)) };
      },
    },
  },
};

async function answer(q) {
  if (q.op === "version") {
    const libs = {};
    for (const [k, v] of Object.entries(LIBS)) libs[k] = { version: v.name === "node" ? "" : version(v.name), ops: Object.keys(v.ops) };
    libs.noble_secp256k1.version = version("@noble/secp256k1");
    libs.node_crypto.version = `Node ${process.version}, OpenSSL ${process.versions.openssl}`;
    libs.bitcoinjs.version = `bitcoinjs-lib ${version("bitcoinjs-lib")}, bip32 ${version("bip32")}, ` +
      `tiny-secp256k1 ${version("tiny-secp256k1")}, bs58check ${version("bs58check")}`;
    return { oracle: "node", node: process.version, libs };
  }
  const lib = LIBS[q.lib];
  const f = lib && lib.ops[q.op];
  if (!f) return { unsupported: true };
  try {
    return await f(q);
  } catch (e) {
    if (e instanceof Refused) return { error: e.message || "refused" };
    return { crash: String(e && e.stack ? e.stack : e) };
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  const q = JSON.parse(line);
  const a = await answer(q);
  if ("id" in q) a.id = q.id;
  process.stdout.write(JSON.stringify(a) + "\n");
}

/**
 * carnac.js — narrow Carnac digest signing contract.
 *
 * A backwards-compatible add-on to the existing POST /sign and POST /verify
 * routes. Carnac supplies a precomputed SHA-256 digest of its own payload and
 * asks this service to bind + sign exactly that digest with the SAME genuine
 * ML-DSA-65 engine used everywhere else (src/key.js). No mock signatures, no
 * fake fallback, no alternate algorithm.
 *
 * What is signed: a canonical binding to the digest — SHA-256 over the
 * canonical JSON of { algo, object, payload_sha256 } — so the served signature
 * is inseparable from BOTH the caller's digest AND the algorithm label. Any
 * tamper of the digest, algorithm, signature, or public key fails verification.
 *
 * Wire shape (flat string fields, what Carnac consumes):
 *   sign   in : { payload_sha256:<64 hex>, algo:<string> }
 *          out: { signature:<b64>, public_key:<b64>, algo:<label> }
 *   verify in : { payload_sha256, signature, public_key, algo }
 *          out: { valid:boolean, algo:<label|null> }
 *
 * Security: the private key never leaves src/key.js and is never returned or
 * logged. Callers only ever see the public key and the signature.
 */
import crypto from 'crypto';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from './typed.js';

// The single normalized algorithm label Carnac expects back. ml-dsa-65 in any
// casing normalizes to this; anything else is rejected (no fallback).
export const CARNAC_ALGO_LABEL = process.env.CARNAC_ALGO_LABEL || 'ML-DSA-65';

/**
 * Normalize the requested algorithm. Accepts the two required casings
 * (ml-dsa-65 / ML-DSA-65) and, defensively, any casing of the configured
 * label. Returns the configured canonical label, or null for anything else —
 * a genuinely different algorithm is never permitted.
 */
export function normalizeAlgo(algo) {
  if (typeof algo !== 'string') return null;
  const a = algo.trim().toLowerCase();
  if (a === 'ml-dsa-65' || a === CARNAC_ALGO_LABEL.toLowerCase()) return CARNAC_ALGO_LABEL;
  return null;
}

export function isValidSha256Hex(d) {
  return typeof d === 'string' && /^[0-9a-f]{64}$/i.test(d);
}

// Canonical binding message bound to the caller's digest + normalized algo.
function bindingMessage(payloadSha256Lower, algoLabel) {
  const binding = {
    object: 'carnac.digest.binding',
    algo: algoLabel,
    payload_sha256: payloadSha256Lower,
  };
  return sha256(utf8ToBytes(canonicalize(binding)));
}

/**
 * signDigestBinding — validate + sign a canonical binding to the digest with
 * the genuine ML-DSA-65 signer. Returns flat string fields only. Throws on a
 * malformed digest or unsupported algorithm (never falls back).
 */
export function signDigestBinding(payload_sha256, algo, signer) {
  const norm = normalizeAlgo(algo);
  if (!norm) throw new Error('unsupported_algo');
  if (!isValidSha256Hex(payload_sha256)) throw new Error('invalid_payload_sha256');
  const msg = bindingMessage(payload_sha256.toLowerCase(), norm);
  const sig = signer.sign(msg);
  return {
    signature: Buffer.from(sig).toString('base64'),
    public_key: signer.publicKeyB64,
    algo: norm,
  };
}

/**
 * verifyDigestBinding — independent genuine ML-DSA-65 verification. Returns
 * { valid, algo }. Any tamper (digest, signature, key, algorithm) yields
 * valid:false. Malformed inputs fail closed rather than throwing.
 */
export function verifyDigestBinding(payload_sha256, signature, public_key, algo, verifyFn) {
  const norm = normalizeAlgo(algo);
  if (!norm) return { valid: false, algo: null };
  if (!isValidSha256Hex(payload_sha256)
    || typeof signature !== 'string' || !signature
    || typeof public_key !== 'string' || !public_key) {
    return { valid: false, algo: norm };
  }
  let ok = false;
  try {
    const msg = bindingMessage(payload_sha256.toLowerCase(), norm);
    const sig = Uint8Array.from(Buffer.from(signature, 'base64'));
    const pub = Uint8Array.from(Buffer.from(public_key, 'base64'));
    ok = verifyFn(sig, msg, pub) === true;
  } catch (_) {
    ok = false;
  }
  return { valid: ok, algo: norm };
}

// Whether internal-token auth is configured for digest signing.
export function authConfigured() {
  return !!process.env.HIVE_INTERNAL_TOKEN;
}

/**
 * checkInternalToken — constant-time check of the X-Hive-Internal-Token header
 * against HIVE_INTERNAL_TOKEN. When no token is configured this returns true so
 * existing behavior is preserved for existing clients.
 */
export function checkInternalToken(provided) {
  const expected = process.env.HIVE_INTERNAL_TOKEN;
  if (!expected) return true;
  if (typeof provided !== 'string' || provided.length === 0) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

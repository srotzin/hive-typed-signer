/**
 * upstream.js — Shared envelope for the seven upstream pre-effect receipt types.
 *
 * The seven Upstream Signed Pre-Effect Attestation (USPA) primitives all follow
 * the same discipline: bind a small structured payload plus a canonical envelope
 * into ONE ML-DSA-65 signature, produce a deterministic root a third party can
 * recompute, and expose a freshness window.
 *
 * The seven primitives and their docket numbers:
 *
 *   HC-2026-016  Provenance-Bonded Sandbox (PBS)      — provisioning attestation
 *   HC-2026-017  Refusal Ledger                       — policy-mutation receipts
 *   HC-2026-018  Howler                               — intent-formation alarms
 *   HC-2026-019  Perimeter Bond                       — exploit-class reach guard
 *   HC-2026-020  Diurnal Bond                         — temporal-risk bonding
 *   HC-2026-021  Egress Bond                          — exfil pre-commit
 *   HC-2026-022  Forensic Rail                        — bonded post-incident analysis
 *
 * Envelope shape (identical across all seven):
 *   {
 *     version:       'usap.v1',
 *     receipt_type:  string,           // 'pbs.manifest', 'howler.drift', etc.
 *     receipt_id:    hex,              // 128-bit random
 *     run_id:        string,           // caller-supplied run correlator
 *     tenant_id:     string,
 *     issuer_kid:    string,           // signer key id
 *     issued_at:     int (unix sec),
 *     expires_at:    int (unix sec),
 *     payload_root:  hex,              // Merkle root over the receipt-specific payload
 *     payload:       object,           // the receipt-type-specific declared body
 *     sig_alg:       'ml-dsa-65',
 *     sig:           hex,
 *   }
 *
 * Signature is over `canonicalize({...envelope without sig})`.
 * Verification: recompute payload_root from carried payload, recompute the
 * canonical envelope-without-sig, verify ML-DSA-65 signature, check freshness.
 *
 * Patent Pending HC-2026-016 through HC-2026-022 (a common signed-envelope
 * apparatus for a plurality of upstream pre-effect attestation primitives
 * emitted at distinct stages of an autonomous agent execution lifecycle).
 */

import { canonicalize, hashHex, resolveSuite, merkleRoot } from './typed.js';
import { bytesToHex } from '@noble/hashes/utils';
import { randomBytes } from 'crypto';

export const USAP_VERSION = 'usap.v1';
export const USAP_SIG_ALG = 'ml-dsa-65';

/** Per-receipt-type default freshness in seconds. */
export const DEFAULT_TTL = {
  'pbs.manifest':        3600,          // 1 hour
  'pbs.attestation':      900,          // 15 min
  'refusal.mutation':  31536000,        // 1 year (append-only history)
  'refusal.binding':       300,         // 5 min at read time
  'howler.drift':          60,          // 60 sec (must be fresh in the loop)
  'howler.capability':     60,
  'howler.contamination':  60,
  'perimeter.manifest':  3600,
  'perimeter.attempt':     30,
  'diurnal.regime':      3600,
  'diurnal.attestation':  600,
  'egress.manifest':     3600,
  'egress.measurement':    30,
  'forensic.credential': 86400,
  'forensic.analysis':    300,
};

/**
 * Drop keys whose value is undefined, recursively.
 *
 * Every primitive builds its payload by passing optional caller fields straight
 * through, so an omitted field arrives as an explicit `undefined` key. That key
 * is real to Object.keys at signing time but disappears the moment the envelope
 * is JSON-serialized to an HTTP client. The verifier would then recompute
 * payload_root over a smaller key set and report payload_root_mismatch on a
 * receipt that was never tampered with. Pruning here makes the signed payload
 * byte-identical to the payload that travels, so signing and verifying agree
 * across the wire.
 */
export function pruneUndefined(value) {
  if (Array.isArray(value)) return value.map(pruneUndefined);
  if (value && typeof value === 'object' && !(value instanceof Date)) {
    const out = {};
    for (const k of Object.keys(value)) {
      if (value[k] === undefined) continue;
      out[k] = pruneUndefined(value[k]);
    }
    return out;
  }
  return value;
}

/** Compute a Merkle root over a payload's canonical field-value leaves. */
export function payloadRoot(payload, suite) {
  const s = suite || resolveSuite('sha-256');
  const src = payload || {};
  const keys = Object.keys(src).filter(k => src[k] !== undefined).sort();
  if (!keys.length) return '0'.repeat(s.digest_len * 2);
  const leaves = keys.map(k =>
    hashHex(canonicalize({ k, v: src[k] }), s));
  return merkleRoot(leaves, s);
}

/** Build the canonical envelope-without-sig ready for signing / verifying. */
export function envelopeToSign(env) {
  const { sig, ...rest } = env;
  return canonicalize(rest);
}

/** Mint a random 128-bit receipt id. */
export function newReceiptId() {
  return bytesToHex(randomBytes(16));
}

/**
 * signUpstreamReceipt — the one function every upstream primitive uses.
 *
 * @param {string} receipt_type  e.g. 'pbs.manifest'
 * @param {object} payload       receipt-type-specific declared body
 * @param {object} meta          { run_id, tenant_id, ttl_seconds? }
 * @param {object} signer        { kid, sign(bytes) -> Uint8Array }
 * @param {object} opts          { hashSuite?, now? }
 */
export function signUpstreamReceipt(receipt_type, payload, meta, signer, opts = {}) {
  if (!receipt_type || typeof receipt_type !== 'string') throw new Error('missing_receipt_type');
  if (!payload || typeof payload !== 'object') throw new Error('missing_payload');
  if (!meta || !meta.run_id || !meta.tenant_id) throw new Error('missing_meta');
  if (!signer || typeof signer.sign !== 'function') throw new Error('missing_signer');

  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const now = Number.isFinite(opts.now) ? opts.now : Math.floor(Date.now() / 1000);
  const ttl = Number.isFinite(meta.ttl_seconds)
    ? meta.ttl_seconds
    : (DEFAULT_TTL[receipt_type] || 300);

  // Sign exactly what will travel. See pruneUndefined above.
  payload = pruneUndefined(payload);

  const env = {
    version:       USAP_VERSION,
    receipt_type,
    receipt_id:    newReceiptId(),
    run_id:        String(meta.run_id),
    tenant_id:     String(meta.tenant_id),
    issuer_kid:    signer.kid || (signer.publicKeyHex ? 'did:hive:pk:' + signer.publicKeyHex.slice(0, 16) : 'unknown'),
    issued_at:     now,
    expires_at:    now + ttl,
    payload_root:  payloadRoot(payload, suite),
    payload,
    sig_alg:       USAP_SIG_ALG,
  };

  const toSign = envelopeToSign(env);
  const sigBytes = signer.sign(new TextEncoder().encode(toSign));
  env.sig = bytesToHex(sigBytes);
  return env;
}

/**
 * verifyUpstreamReceipt — deterministic re-check.
 *
 * @param {object} env             the signed envelope
 * @param {string} expected_type   the receipt_type we require
 * @param {function} verifyFn      ML-DSA-65 verify(pubKey, msg, sig) -> bool
 * @param {Uint8Array} pubBytes    the signer's public key
 * @param {object} opts            { now?, hashSuite?, allow_expired? }
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyUpstreamReceipt(env, expected_type, verifyFn, pubBytes, opts = {}) {
  try {
    if (!env || typeof env !== 'object') return { ok: false, reason: 'no_envelope' };
    if (env.version !== USAP_VERSION) return { ok: false, reason: 'bad_version' };
    if (env.receipt_type !== expected_type) return { ok: false, reason: 'type_mismatch' };
    if (env.sig_alg !== USAP_SIG_ALG) return { ok: false, reason: 'bad_sig_alg' };
    if (!env.sig) return { ok: false, reason: 'missing_sig' };

    const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
    const recomputed = payloadRoot(env.payload, suite);
    if (recomputed !== env.payload_root) return { ok: false, reason: 'payload_root_mismatch' };

    const toSign = envelopeToSign(env);
    const sigBytes = new Uint8Array(env.sig.match(/../g).map(x => parseInt(x, 16)));
    // verifyFn(sigBytes, msgBytes, pubBytes) matches key.js verifyFn signature
    const ok = verifyFn(sigBytes, new TextEncoder().encode(toSign), pubBytes);
    if (!ok) return { ok: false, reason: 'bad_signature' };

    if (!opts.allow_expired) {
      const now = Number.isFinite(opts.now) ? opts.now : Math.floor(Date.now() / 1000);
      if (now < env.issued_at - 5) return { ok: false, reason: 'not_yet_valid' };
      if (now > env.expires_at) return { ok: false, reason: 'expired' };
    }

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: 'verify_exception:' + e.message };
  }
}

/**
 * gateOnReceipts — Carnac Gateway-style aggregate policy.
 * Given a required set of (type, receipt) pairs, refuse execution unless every
 * receipt verifies fresh. Returns { allow: bool, refusals: [{type, reason}] }.
 */
export function gateOnReceipts(required, verifyFn, pubBytes, opts = {}) {
  const refusals = [];
  for (const { type, receipt } of required) {
    const r = verifyUpstreamReceipt(receipt, type, verifyFn, pubBytes, opts);
    if (!r.ok) refusals.push({ type, reason: r.reason });
  }
  return { allow: refusals.length === 0, refusals };
}

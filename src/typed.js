/**
 * typed.js — Real ML-DSA-65 typed-fragment signing + verify (JS port).
 *
 * Mirrors the proven Python module modal_typed_integration.py:
 *   - fragment_type selection axis
 *   - pre-stored canon digest per fragment (SHA-256 over canonical JSON)
 *   - agg_mode='linear' (default): ONE SHA-256 over sorted attested digests
 *   - bind: SHA-256(base_canon || agg_root || policy_digest) => 32-byte payload
 *   - ONE ML-DSA-65 signature over the payload (NOT one per fragment)
 *
 * Real post-quantum primitive: @noble/post-quantum ml_dsa65 (NIST FIPS 204).
 * No mock signatures. No Ed25519. The signature verifies under the published
 * ML-DSA-65 public key.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha256';
import { sha384 } from '@noble/hashes/sha512.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

/**
 * Hash suites. SHA-256 is the default (128-bit post-quantum preimage margin
 * under Grover). SHA-384 is offered for ULTRA-LONG-LIFE receipts (~192-bit
 * post-quantum margin) — receipts meant to remain unforgeable for decades, where
 * Grover's halving of preimage security on SHA-256 is a concern. Dossier item 10.
 *
 * The suite is recorded in the receipt envelope (hash_suite) so an independent
 * verifier recomputes every digest with the matching function. SHA-256 omits the
 * field for wire-compatibility with existing receipts.
 */
export const HASH_SUITES = {
  'sha-256': { fn: sha256, digest_len: 32, pq_preimage_bits: 128 },
  'sha-384': { fn: sha384, digest_len: 48, pq_preimage_bits: 192 },
};

export function resolveSuite(name) {
  const s = HASH_SUITES[(name || 'sha-256').toLowerCase()];
  if (!s) throw new Error('unknown hash_suite: ' + name);
  return s;
}

// ---- canonical JSON (sorted keys, no insignificant whitespace) ----
export function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

// Hash helper bound to a suite (defaults to SHA-256 for back-compat).
export function hashHex(strOrBytes, suite) {
  const fn = (suite && suite.fn) || sha256;
  const b = typeof strOrBytes === 'string' ? utf8ToBytes(strOrBytes) : strOrBytes;
  return bytesToHex(fn(b));
}

export function sha256hex(strOrBytes) {
  const b = typeof strOrBytes === 'string' ? utf8ToBytes(strOrBytes) : strOrBytes;
  return bytesToHex(sha256(b));
}

// ---- fragment classification (deterministic default) ----
export const FRAGMENT_TYPES = ['reasoning', 'tool_call', 'retrieval', 'final', 'system', 'decomposition'];

export function classifyFragment(text, hint) {
  const t = (text || '').toLowerCase();
  if (hint && FRAGMENT_TYPES.includes(hint)) return hint;
  if (/\b(final answer|in conclusion|therefore the answer)\b/.test(t)) return 'final';
  if (/\b(call|invoke|api|tool|function)\b/.test(t)) return 'tool_call';
  if (/\b(according to|source|retrieved|reference|\[\d+\])\b/.test(t)) return 'retrieval';
  if (/\b(system|policy|guard|instruction)\b/.test(t)) return 'system';
  return 'reasoning';
}

// Build typed fragments from an array of {text, type?} with pre-stored canon digests.
// suite (optional) selects the hash function; defaults to SHA-256.
export function buildFragments(items, suite) {
  return items.map((it, i) => {
    const ftype = classifyFragment(it.text, it.type);
    const canonObj = {
      fragment_id: it.id || `f${i + 1}`,
      fragment_type: ftype,
      text_hash: hashHex(it.text || '', suite),
      index: i,
    };
    const canonStr = canonicalize(canonObj);
    return {
      fragment_id: canonObj.fragment_id,
      fragment_type: ftype,
      text_hash: canonObj.text_hash,
      index: i,
      canon: canonStr,
      canon_digest: hashHex(canonStr, suite),
    };
  });
}

export function policyDigest(signTypes, absenceBound = 0, suite) {
  return hashHex(canonicalize({ absence_bound: absenceBound, sign_types: [...signTypes].sort() }), suite);
}

// ---- aggregation roots (suite-aware: digest slot width = suite.digest_len) ----
export function linearRoot(sortedDigestsHex, suite) {
  const fn = (suite && suite.fn) || sha256;
  const dl = (suite && suite.digest_len) || 32;
  const concat = new Uint8Array(sortedDigestsHex.length * dl);
  sortedDigestsHex.forEach((d, i) => concat.set(hexToBytes(d), i * dl));
  return bytesToHex(fn(concat));
}

export function merkleRoot(sortedDigestsHex, suite) {
  if (sortedDigestsHex.length === 0) return '';
  const fn = (suite && suite.fn) || sha256;
  const dl = (suite && suite.digest_len) || 32;
  let nodes = [...sortedDigestsHex];
  while (nodes.length > 1) {
    const nxt = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const a = nodes[i];
      const b = i + 1 < nodes.length ? nodes[i + 1] : nodes[i];
      const pair = new Uint8Array(dl * 2);
      pair.set(hexToBytes(a), 0);
      pair.set(hexToBytes(b), dl);
      nxt.push(bytesToHex(fn(pair)));
    }
    nodes = nxt;
  }
  return nodes[0];
}

// base envelope canon (constant per signer/version)
export function baseCanonDigest(baseFields, suite) {
  return hashHex(canonicalize(baseFields), suite);
}

/**
 * signTyped — the hot path. Returns the envelope + timing.
 * signer: { sign(msgBytes)->sigBytes, publicKeyB64, scheme, version }
 */
export function signTyped(fragments, policy, signer, opts = {}) {
  if (typeof opts === 'boolean') opts = { useMerkle: opts };
  const useMerkle = !!opts.useMerkle;
  const suiteName = (opts.hashSuite || 'sha-256').toLowerCase();
  const suite = resolveSuite(suiteName);
  const temporal = opts.temporal || null;
  const dl = suite.digest_len;
  const t0 = process.hrtime.bigint();
  const signTypeSet = new Set(policy.sign_types);
  const attestedDigests = [];
  const fragsOut = [];
  for (const f of fragments) {
    const attested = signTypeSet.has(f.fragment_type);
    if (attested) attestedDigests.push(f.canon_digest);
    fragsOut.push({
      fragment_id: f.fragment_id,
      fragment_type: f.fragment_type,
      canon_digest: f.canon_digest,
      attested,
    });
  }
  attestedDigests.sort();
  const aggRoot = useMerkle ? merkleRoot(attestedDigests, suite) : linearRoot(attestedDigests, suite);
  const aggMode = useMerkle ? 'merkle' : 'linear';

  const baseFields = {
    object: 'afir.attestation',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
  };
  const canonDigest = baseCanonDigest(baseFields, suite);
  const polDigest = policyDigest(policy.sign_types, policy.absence_bound || 0, suite);

  // item 5: a temporal commitment is bound into the signed payload so the time
  // proof cannot be altered without breaking the signature. Digest is over the
  // canonical temporal object (which carries no secret).
  const zero = '0'.repeat(dl * 2);
  const temporalDigest = temporal ? hashHex(canonicalize(temporal), suite) : zero;

  // bind base || agg || policy [|| temporal] -> one payload digest (suite-wide)
  const slots = temporal ? 4 : 3;
  const bind = new Uint8Array(dl * slots);
  bind.set(hexToBytes(canonDigest), 0);
  bind.set(hexToBytes(aggRoot || zero), dl);
  bind.set(hexToBytes(polDigest), dl * 2);
  if (temporal) bind.set(hexToBytes(temporalDigest), dl * 3);
  const payloadHex = bytesToHex(suite.fn(bind));
  const payloadBytes = hexToBytes(payloadHex);

  const tSign0 = process.hrtime.bigint();
  const sigBytes = signer.sign(payloadBytes);
  const tSign1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    merkle_root: aggRoot,     // wire-compat field name preserved
    agg_mode: aggMode,
    agg_root: aggRoot,
    policy_id: policy.policy_id || 'default',
    policy_digest: polDigest,
    fragment_count: fragments.length,
    attested: attestedDigests.length,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    fragments: fragsOut,
    issued_at: new Date().toISOString(),
    patent_pending: 'HC-2026-001',
  };
  // item 10: record hash_suite only when non-default — preserves wire-compat for
  // the existing SHA-256 receipt archive.
  if (suiteName !== 'sha-256') envelope.hash_suite = suiteName;
  // item 5: carry the temporal proof in the envelope; its digest is bound above.
  if (temporal) envelope.temporal = temporal;
  // QPuF: embed the trust block (quantum entropy + PuF device binding) if the
  // signer carries one. Reveals no secret; lets a verifier confirm the chain.
  if (signer.trust) envelope.trust = signer.trust;
  const t1 = process.hrtime.bigint();
  return {
    envelope,
    timing_us: {
      sign_us: Number(tSign1 - tSign0) / 1000,
      total_us: Number(t1 - t0) / 1000,
    },
  };
}

/**
 * verifyTyped — independent reconstruction + ML-DSA-65 signature check.
 * fragmentsCanon: the canonical fragment objects (fragment_id, fragment_type,
 *   text_hash, index) so the verifier recomputes digests independently.
 * verifyFn(sigBytes, msgBytes, pubBytes) -> bool
 */
export function verifyTyped(envelope, fragmentsCanon, verifyFn, pubBytes) {
  const t0 = process.hrtime.bigint();
  const reasons = [];
  // item 10: the verifier reads the suite the receipt was signed under (default
  // SHA-256 when the field is absent) and recomputes every digest with it.
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName], verify_us: 0 }; }
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);
  // infer attested types from envelope.fragments marked attested
  const attestedIds = new Set(envelope.fragments.filter(f => f.attested).map(f => f.fragment_id));

  // recompute digests independently from canonical objects
  const recomputed = [];
  for (const fo of fragmentsCanon) {
    const canonObj = {
      fragment_id: fo.fragment_id,
      fragment_type: fo.fragment_type,
      text_hash: fo.text_hash,
      index: fo.index,
    };
    const dig = hashHex(canonicalize(canonObj), suite);
    if (attestedIds.has(fo.fragment_id)) recomputed.push(dig);
  }
  recomputed.sort();
  const aggMode = envelope.agg_mode || 'linear';
  const recRoot = aggMode === 'merkle' ? merkleRoot(recomputed, suite) : linearRoot(recomputed, suite);
  if (recRoot !== (envelope.agg_root || envelope.merkle_root)) reasons.push('agg_root_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
  };
  const canonDigest = baseCanonDigest(baseFields, suite);
  const polDigest = envelope.policy_digest || '';

  // item 5: recompute the temporal digest from the carried temporal object and
  // bind it exactly as signing did. Any edit to envelope.temporal breaks this.
  const hasTemporal = !!envelope.temporal;
  const temporalDigest = hasTemporal ? hashHex(canonicalize(envelope.temporal), suite) : zero;

  // suite-length guard: every digest slot must be exactly dl bytes. A downgrade
  // attack (e.g. relabel a SHA-384 receipt as sha-256) yields wrong-width digests
  // here — fail closed instead of throwing.
  const slotHex = (h) => {
    const v = h || zero;
    return v.length === dl * 2 ? v : null;
  };
  const cD = slotHex(canonDigest), rR = slotHex(recRoot), pD = slotHex(polDigest);
  const tD = hasTemporal ? slotHex(temporalDigest) : zero;
  if (cD === null || rR === null || pD === null || tD === null) {
    reasons.push('hash_suite_length_mismatch');
    const t1b = process.hrtime.bigint();
    return { valid: false, reasons, scheme: envelope.sig_scheme, agg_mode: aggMode, verify_us: Number(t1b - t0) / 1000 };
  }
  const slots = hasTemporal ? 4 : 3;
  const bind = new Uint8Array(dl * slots);
  bind.set(hexToBytes(cD), 0);
  bind.set(hexToBytes(rR), dl);
  bind.set(hexToBytes(pD), dl * 2);
  if (hasTemporal) bind.set(hexToBytes(tD), dl * 3);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== envelope.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(envelope.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) {
    reasons.push('signature_error:' + e.message);
  }
  if (!sigOk) reasons.push('signature_invalid');

  const t1 = process.hrtime.bigint();
  return {
    valid: reasons.length === 0,
    reasons,
    scheme: envelope.sig_scheme,
    agg_mode: aggMode,
    verify_us: Number(t1 - t0) / 1000,
  };
}

export { ml_dsa65 };

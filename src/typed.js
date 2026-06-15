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
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

// ---- canonical JSON (sorted keys, no insignificant whitespace) ----
export function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
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
export function buildFragments(items) {
  return items.map((it, i) => {
    const ftype = classifyFragment(it.text, it.type);
    const canonObj = {
      fragment_id: it.id || `f${i + 1}`,
      fragment_type: ftype,
      text_hash: sha256hex(it.text || ''),
      index: i,
    };
    const canonStr = canonicalize(canonObj);
    return {
      fragment_id: canonObj.fragment_id,
      fragment_type: ftype,
      text_hash: canonObj.text_hash,
      index: i,
      canon: canonStr,
      canon_digest: sha256hex(canonStr),
    };
  });
}

export function policyDigest(signTypes, absenceBound = 0) {
  return sha256hex(canonicalize({ absence_bound: absenceBound, sign_types: [...signTypes].sort() }));
}

// ---- aggregation roots ----
export function linearRoot(sortedDigestsHex) {
  const concat = new Uint8Array(sortedDigestsHex.length * 32);
  sortedDigestsHex.forEach((d, i) => concat.set(hexToBytes(d), i * 32));
  return bytesToHex(sha256(concat));
}

export function merkleRoot(sortedDigestsHex) {
  if (sortedDigestsHex.length === 0) return '';
  let nodes = [...sortedDigestsHex];
  while (nodes.length > 1) {
    const nxt = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const a = nodes[i];
      const b = i + 1 < nodes.length ? nodes[i + 1] : nodes[i];
      const pair = new Uint8Array(64);
      pair.set(hexToBytes(a), 0);
      pair.set(hexToBytes(b), 32);
      nxt.push(bytesToHex(sha256(pair)));
    }
    nodes = nxt;
  }
  return nodes[0];
}

// base envelope canon (constant per signer/version)
export function baseCanonDigest(baseFields) {
  return sha256hex(canonicalize(baseFields));
}

/**
 * signTyped — the hot path. Returns the envelope + timing.
 * signer: { sign(msgBytes)->sigBytes, publicKeyB64, scheme, version }
 */
export function signTyped(fragments, policy, signer, useMerkle = false) {
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
  const aggRoot = useMerkle ? merkleRoot(attestedDigests) : linearRoot(attestedDigests);
  const aggMode = useMerkle ? 'merkle' : 'linear';

  const baseFields = {
    object: 'afir.attestation',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
  };
  const canonDigest = baseCanonDigest(baseFields);
  const polDigest = policyDigest(policy.sign_types, policy.absence_bound || 0);

  // bind base || agg || policy -> 32-byte payload
  const bind = new Uint8Array(96);
  bind.set(hexToBytes(canonDigest), 0);
  bind.set(hexToBytes(aggRoot || '0'.repeat(64)), 32);
  bind.set(hexToBytes(polDigest), 64);
  const payloadHex = bytesToHex(sha256(bind));
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
  const signTypeSet = new Set();
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
    const dig = sha256hex(canonicalize(canonObj));
    if (attestedIds.has(fo.fragment_id)) recomputed.push(dig);
  }
  recomputed.sort();
  const aggMode = envelope.agg_mode || 'linear';
  const recRoot = aggMode === 'merkle' ? merkleRoot(recomputed) : linearRoot(recomputed);
  if (recRoot !== (envelope.agg_root || envelope.merkle_root)) reasons.push('agg_root_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
  };
  const canonDigest = baseCanonDigest(baseFields);
  const polDigest = envelope.policy_digest || '';
  const bind = new Uint8Array(96);
  bind.set(hexToBytes(canonDigest), 0);
  bind.set(hexToBytes(recRoot || '0'.repeat(64)), 32);
  bind.set(hexToBytes(polDigest || '0'.repeat(64)), 64);
  const payloadHex = bytesToHex(sha256(bind));
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

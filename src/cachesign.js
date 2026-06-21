/**
 * cachesign.js — AFiR KV Cache Signing (P3).
 *
 * Signs KV-cache prefix entries at write time so the exact prefix a model
 * reused is provable after the fact. Binds the vLLM-compatible SHA-256 prefix
 * hash, the block/token span it covers, the model identity, and an optional
 * parent_cache_receipt for provenance across turns — into ONE ML-DSA-65
 * signature under the published demo key.
 *
 * Rides the identical typed-signer discipline (canonicalize -> hash -> bind
 * one payload -> single PQ signature -> independent recompute + verify). No
 * mock signatures, no Ed25519.
 *
 * What it signs, per cache write:
 *   - prefix_hash          : caller-supplied vLLM SHA-256 prefix hash (hex)
 *   - block_ids            : ordered cache block ids covered (optional)
 *   - token_span           : { start, end } token offsets covered (optional)
 *   - model_id             : model the cache belongs to
 *   - parent_cache_receipt : prior cache receipt payload_digest (chain, optional)
 *
 * Trust model: zero-secret verification. Only the published ML-DSA-65 public
 * key and the receipt are needed; the verifier recomputes the prefix-commitment
 * root, rebinds, and checks the one signature.
 *
 * Patent Pending.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * prefixCommitment — bind the prefix hash + the ordered block ids + token span
 * into a single commitment root, so any change to which blocks/tokens the
 * prefix covered is detectable.
 */
export function prefixCommitment(prefix_hash, block_ids, token_span, suite) {
  const s = suite || resolveSuite('sha-256');
  const leaves = [];
  leaves.push(hashHex(canonicalize({ k: 'prefix', v: String(prefix_hash) }), s));
  (block_ids || []).forEach((b, i) => {
    leaves.push(hashHex(canonicalize({ k: 'block', i, v: b }), s));
  });
  if (token_span) {
    leaves.push(hashHex(canonicalize({ k: 'span', v: token_span }), s));
  }
  return merkleRoot(leaves, s);
}

/**
 * signCacheEntry — seal a single KV-cache prefix write.
 *   base || H(prefix_root || parent_link) -> one payload -> one ML-DSA-65 sig.
 *
 * entry = {
 *   model_id, prefix_hash,
 *   block_ids?:[...], token_span?:{start,end},
 *   parent_cache_receipt?  (prior receipt payload_digest, hex)
 * }
 */
export function signCacheEntry(entry, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  if (!entry || !entry.prefix_hash) throw new Error('missing_prefix_hash');
  if (!entry.model_id) throw new Error('missing_model_id');

  const prefix_root = prefixCommitment(
    entry.prefix_hash, entry.block_ids, entry.token_span, suite,
  );

  const baseFields = {
    object: 'sigr.cache.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    model_id: String(entry.model_id),
    prefix_hash: String(entry.prefix_hash),
    prefix_root,
    block_count: Array.isArray(entry.block_ids) ? entry.block_ids.length : 0,
    token_span: entry.token_span || null,
    parent_cache_receipt: entry.parent_cache_receipt || null,
    // ARSC: a cache write is a Sink-tier (low-liability) provenance event; a
    // chained write referencing a parent rises to Float (carries history).
    arsc_tier: entry.parent_cache_receipt ? 'float' : 'sink',
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  // bind H(prefix_root || parent_link) so the covered prefix + chain link are
  // in the signed payload directly. parent_link defaults to zero when absent.
  const parentLink = entry.parent_cache_receipt
    ? hashHex(String(entry.parent_cache_receipt), suite)
    : '0'.repeat(dl * 2);
  const pair = new Uint8Array(dl * 2);
  pair.set(hexToBytes(prefix_root), 0);
  pair.set(hexToBytes(parentLink), dl);
  const stateDigest = bytesToHex(suite.fn(pair));

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(stateDigest), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    block_ids: entry.block_ids || [],
    state_digest: stateDigest,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  if (signer.trust) envelope.trust = signer.trust;

  return { envelope, timing_us: { sign_us: Number(t1 - t0) / 1000 } };
}

/**
 * verifyCacheEntry — independent reconstruction + single signature check.
 *   1. recompute prefix_root from carried prefix_hash + block_ids + token_span
 *   2. recompute state_digest from (prefix_root || parent_link)
 *   3. recompute base + payload, verify the one signature
 */
export function verifyCacheEntry(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  // 1. recompute prefix root
  const recRoot = prefixCommitment(
    envelope.prefix_hash, envelope.block_ids, envelope.token_span, suite,
  );
  if (recRoot !== envelope.prefix_root) reasons.push('prefix_root_mismatch');

  // 2. recompute base + state
  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    model_id: envelope.model_id,
    prefix_hash: envelope.prefix_hash,
    prefix_root: envelope.prefix_root,
    block_count: envelope.block_count,
    token_span: envelope.token_span || null,
    parent_cache_receipt: envelope.parent_cache_receipt || null,
    arsc_tier: envelope.arsc_tier,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const parentLink = envelope.parent_cache_receipt
    ? hashHex(String(envelope.parent_cache_receipt), suite)
    : '0'.repeat(dl * 2);
  const pair = new Uint8Array(dl * 2);
  pair.set(hexToBytes(envelope.prefix_root || '0'.repeat(dl * 2)), 0);
  pair.set(hexToBytes(parentLink), dl);
  const stateDigest = bytesToHex(suite.fn(pair));
  if (stateDigest !== envelope.state_digest) reasons.push('state_digest_mismatch');

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(stateDigest), dl);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== envelope.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(envelope.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return {
    valid: reasons.length === 0,
    reasons,
    model_id: envelope.model_id,
    prefix_hash: envelope.prefix_hash,
  };
}

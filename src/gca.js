/**
 * gca.js — GCA: Per-Claim Grounding Attestation.
 *
 * Spec §1. ARSC produces ONE grounding score for an answer. GCA goes per-claim:
 * it signs the binding between EACH individual assertion in the answer and the
 * specific source span that supports it — OR signs that NO supporting span exists
 * (`support: null`, made visible and signed).
 *
 * The honest line (the entire design constraint — spec §1.2):
 *   - It proves SUPPORT, not TRUTH. A claim bound to a source span is *supported*;
 *     whether the source itself is correct is OUT OF SCOPE. GCA never claims the
 *     claim is correct.
 *   - An UNSUPPORTED claim becomes visible and signed (`support: null`). We are not
 *     saying it is false — we are saying *this assertion has no grounding in the
 *     retrieved sources, and that fact is now part of the signed record*.
 *   - Novel because nobody signs claim-level support bindings. Everyone scores
 *     answers in aggregate; GCA makes the *per-claim support map* a verifiable
 *     artifact (spec §1.2).
 *
 * What it signs:
 *   - answer_id        : identity of the answer this claim-map is FOR
 *   - method_hash      : identity of the grounding/extraction method used
 *   - claims[]         : per claim: { claim_id, claim_hash, support, support_strength }
 *                        support = 0x<source-span hash> when grounded, or null when
 *                        unsupported. support_strength is an INTEGER in basis points
 *                        (0..10000) to avoid float drift in the signed value.
 *   - claims_root      : merkle root over the per-claim leaf digests (the exact map)
 *
 * Float discipline: support_strength is real-valued (0.0..1.0) in the spec, but to
 * keep the signed value exact we carry it as an integer in basis points
 * (support_strength_bp, 0..10000). The caller may pass either `support_strength`
 * (0..1 float) or `support_strength_bp` (integer); we normalize to bp and bind the
 * integer. No on-chain math is done on it here.
 *
 * Rides ARSC (spec §4): claim-level grounding is an extension of the grounding
 * score already computed. ARSC tier: Critical (grounding is latency-sensitive,
 * answer-time) — carried as arsc_tier: 'critical'.
 *
 * Trust model: zero-secret verification. Only the published ML-DSA-65 public key
 * and the receipt are needed; the verifier recomputes every per-claim leaf digest,
 * re-derives the claims_root, re-binds the base, and checks the single signature.
 * A tampered claim, a swapped support span, an altered support_strength, or a
 * silently-dropped unsupported claim all break verification.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, bind-one-payload,
 * SIGNER/verifyFn — identical discipline to consensus.js / reward.js.
 *
 * Patent Pending (signing a per-claim binding between each asserted claim in a
 * model output and a supporting source span, or a signed indication of absence of
 * support, such that an unsupported claim is rendered visible in a verifiable
 * record without asserting the claim is false — spec §5 GCA independent claim).
 * Internal docket only; not yet assigned a number.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * normalizeStrength — accept a 0..1 float (`support_strength`) or an integer in
 * basis points (`support_strength_bp`) and return an integer 0..10000. Unsupported
 * claims are pinned to 0. Keeps the signed value exact and settlement-safe.
 */
export function normalizeStrength(claim) {
  if (claim.support === null || claim.support === undefined) return 0;
  if (claim.support_strength_bp !== undefined && claim.support_strength_bp !== null) {
    const bp = Math.round(Number(claim.support_strength_bp));
    return Math.max(0, Math.min(10000, bp | 0));
  }
  const f = Number(claim.support_strength);
  if (Number.isNaN(f)) return 0;
  return Math.max(0, Math.min(10000, Math.round(f * 10000)));
}

/**
 * normalizeClaim — canonical per-claim record. `support` is either a hex span hash
 * (grounded) or null (unsupported — visible, signed). The leaf digest commits to
 * the whole record so neither the claim, its support, nor its strength can be
 * altered without breaking the claims_root.
 */
export function normalizeClaim(raw, idx, suite) {
  const claim_id = raw.claim_id !== undefined ? raw.claim_id : idx + 1;
  const claim_hash = raw.claim_hash || hashHex(canonicalize(raw.claim ?? null), suite);
  const hasSupport = raw.support !== null && raw.support !== undefined;
  const support = hasSupport ? raw.support : null;     // null = UNSUPPORTED, visible + signed
  const support_strength_bp = normalizeStrength({ ...raw, support });
  return {
    object: 'sigr.gca.claim',
    claim_id,
    claim_hash,
    support,                                            // 0x<span hash> | null
    support_strength_bp,                                // integer basis points 0..10000
  };
}

/**
 * claimLeaf — the per-claim leaf digest fed into the claims_root merkle.
 */
export function claimLeaf(claimRecord, suite) {
  return hashHex(canonicalize(claimRecord), suite);
}

/**
 * signGca — seal a per-claim grounding-support map. Binds:
 *   base || claims_root -> one payload -> one ML-DSA-65 sig.
 *
 * gca = {
 *   answer_id?,
 *   method_hash,                              // identity of the grounding method
 *   claims: [
 *     { claim_id?, claim?|claim_hash, support: '0x...'|null, support_strength?|support_strength_bp? },
 *     ...
 *   ]
 * }
 *
 * The receipt EXPOSES the unsupported count and the support-strength variance so
 * downstream GiTM can read the grounding-anomaly signal directly from the signed
 * record (spec §1.3) without re-deriving it.
 */
export function signGca(gca, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  if (!gca.method_hash) throw new Error('missing_method_hash');
  const rawClaims = Array.isArray(gca.claims) ? gca.claims : [];
  if (rawClaims.length === 0) throw new Error('no_claims');

  // normalize every claim — support: null is preserved, visible, and signed.
  const claims = rawClaims.map((c, i) => normalizeClaim(c, i, suite));
  const leaves = claims.map(c => claimLeaf(c, suite)).sort();
  const claims_root = merkleRoot(leaves, suite);

  // honest exposed signals (anomaly inputs for GiTM — NOT truth judgments)
  const unsupported_count = claims.filter(c => c.support === null).length;
  const strengths = claims.map(c => c.support_strength_bp);
  const mean = strengths.reduce((a, b) => a + b, 0) / strengths.length;
  // population variance in bp^2, carried as an integer to stay exact
  const variance_bp2 = Math.round(
    strengths.reduce((a, b) => a + (b - mean) * (b - mean), 0) / strengths.length,
  );

  const baseFields = {
    object: 'sigr.gca.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    answer_id: gca.answer_id || 'unspecified',
    method_hash: gca.method_hash,
    claim_count: claims.length,
    unsupported_count,                       // visible: how many claims have no grounding
    support_variance_bp2: variance_bp2,      // visible: how uneven support is across claims
    claims_root,
    asserts: 'support_not_truth',            // BINDING: GCA proves support, never correctness
    arsc_tier: 'critical',                   // answer-time grounding
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(claims_root), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    claims,                                  // full per-claim map carried for re-derivation
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
 * verifyGca — independent recompute + single signature check.
 *   - re-derive every per-claim leaf and the claims_root, confirm match
 *   - re-derive the exposed unsupported_count / support_variance from the carried map
 *   - re-bind base + claims_root, recompute payload, verify the one signature
 * A tampered claim, swapped support span, altered support_strength, or a dropped
 * unsupported claim all break verification.
 */
export function verifyGca(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  const claims = Array.isArray(envelope.claims) ? envelope.claims : [];
  if (claims.length === 0) reasons.push('no_claims');

  // re-derive claims_root from the carried per-claim map
  const leaves = claims.map(c => claimLeaf(c, suite)).sort();
  const recRoot = merkleRoot(leaves, suite);
  if (recRoot !== envelope.claims_root) reasons.push('claims_root_mismatch');
  if (claims.length !== envelope.claim_count) reasons.push('claim_count_mismatch');

  // re-derive the exposed honesty signals and confirm they were not misreported
  const recUnsupported = claims.filter(c => c.support === null).length;
  if (recUnsupported !== envelope.unsupported_count) reasons.push('unsupported_count_mismatch');
  const strengths = claims.map(c => c.support_strength_bp);
  const mean = strengths.length ? strengths.reduce((a, b) => a + b, 0) / strengths.length : 0;
  const recVar = strengths.length
    ? Math.round(strengths.reduce((a, b) => a + (b - mean) * (b - mean), 0) / strengths.length)
    : 0;
  if (recVar !== envelope.support_variance_bp2) reasons.push('support_variance_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    answer_id: envelope.answer_id,
    method_hash: envelope.method_hash,
    claim_count: envelope.claim_count,
    unsupported_count: envelope.unsupported_count,
    support_variance_bp2: envelope.support_variance_bp2,
    claims_root: envelope.claims_root,
    asserts: envelope.asserts,
    arsc_tier: envelope.arsc_tier,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.claims_root), dl);
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
    answer_id: envelope.answer_id,
    claim_count: envelope.claim_count,
    unsupported_count: envelope.unsupported_count,
    claims_root: envelope.claims_root,
    asserts: envelope.asserts,
  };
}

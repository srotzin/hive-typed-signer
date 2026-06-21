/**
 * cern.js — AFiR-CERN: Context Ethics & Retention Notarization (DURING).
 *
 * AFiR-S3 §2.3 — THE CROWN JEWEL. Files first (priority). Signs every
 * transformation an autonomous agent applies to its OWN working context: what it
 * summarizes, drops, or ALTERS — with a signed delta. Nobody signs the moment an
 * agent decides what to forget or change; this is net-new IP with no expected
 * prior art.
 *
 * THE INDEPENDENT CLAIM (HC-2026-010):
 *   A method for cryptographically attesting each transformation an autonomous
 *   agent applies to its working context, binding the pre- and post-transformation
 *   state and any altered or dropped spans into a signed receipt, such that
 *   undisclosed alteration or omission breaks verification.
 *
 * What it signs, per mutation:
 *   - context_before_root : Merkle root over the ordered context spans BEFORE
 *   - context_after_root  : Merkle root over the ordered context spans AFTER
 *   - mutation_type       : append | summarize | drop | alter
 *   - altered_spans       : for alter/drop — { original_hash, result_hash|null, reason }
 *   - integrity_claim     : lossless | lossy_attested | altered_attested
 *
 * The teeth: the receipt's integrity_claim and altered_spans are CHECKED against
 * the actual before/after roots. If an agent silently rewrites a span (alters
 * content) but claims 'lossless', or drops a span without disclosing it, the
 * reconstruction of context_after_root from (before − dropped + altered) will not
 * match the signed after_root — verification breaks. Undisclosed mutation is
 * provably detectable; that is the whole point.
 *
 * Span model: a context is an ORDERED list of spans (strings or typed objects).
 * Each span -> span_hash = H(canonical(span)). The root is the Merkle root over
 * the ordered span hashes (order preserved by binding index into the leaf), so a
 * reorder is also detectable. We additionally carry the ordered span-hash list in
 * the receipt so a verifier can reconstruct the delta deterministically.
 *
 * Trust model: zero-secret verification. Only the published ML-DSA-65 public key
 * and the receipt are needed; the verifier recomputes both roots, replays the
 * declared delta, and checks the single signature.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, bind-one-payload,
 * SIGNER/verifyFn — identical discipline to typed.js / chain.js.
 *
 * Patent Pending HC-2026-010 (cryptographic attestation of autonomous-agent
 * context transformation; pre/post-state + altered/dropped spans bound under a
 * single aggregate post-quantum signature; undisclosed alteration or omission
 * breaks verification). FILES FIRST — priority. Internal docket only.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export const MUTATION_TYPES = ['append', 'summarize', 'drop', 'alter'];
export const INTEGRITY_CLAIMS = ['lossless', 'lossy_attested', 'altered_attested'];

/**
 * spanHash — per-span leaf binding the span's position so reorder is detectable.
 *   leaf = H( canonical({ i, span_digest }) ),  span_digest = H(canonical(span))
 */
export function spanHash(span, index, suite) {
  const s = suite || resolveSuite('sha-256');
  const span_digest = hashHex(canonicalize(span), s);
  const leaf = hashHex(canonicalize({ i: index, d: span_digest }), s);
  return { span_digest, leaf };
}

/**
 * contextRoot — ordered Merkle root over the positional span leaves. Returns
 * { spanDigests, leaves, root }. spanDigests is the ordered list of raw span
 * digests (position-independent), used for delta replay.
 */
export function contextRoot(spans, suite) {
  const s = suite || resolveSuite('sha-256');
  const spanDigests = [];
  const leaves = [];
  spans.forEach((span, i) => {
    const { span_digest, leaf } = spanHash(span, i, s);
    spanDigests.push(span_digest);
    leaves.push(leaf);
  });
  const root = leaves.length ? merkleRoot(leaves, s) : '0'.repeat(s.digest_len * 2);
  return { spanDigests, leaves, root };
}

/**
 * deriveDelta — classify the transformation from before/after span digests +
 * the declared altered_spans, and return the integrity facts that MUST hold.
 * This is the verification core: it reconstructs what the after-state SHOULD be
 * given the declared mutation and compares against the actual after digests.
 *
 * Returns { ok, reasons, derived_type }.
 */
export function deriveDelta(beforeDigests, afterDigests, mutation, suite) {
  const reasons = [];
  const declaredType = mutation.mutation_type;
  const altered = mutation.altered_spans || [];

  const beforeSet = new Set(beforeDigests);
  const afterSet = new Set(afterDigests);

  // spans present before but absent after = removed (dropped OR replaced-by-alter)
  const removed = beforeDigests.filter(d => !afterSet.has(d));
  // spans present after but absent before = newly introduced (alter results, or
  // summarize output, or appended content)
  const added = afterDigests.filter(d => !beforeSet.has(d));

  // declared alterations: each names an original_hash that must have been removed,
  // and a result_hash that (if non-null) must appear in `added`.
  const declaredOriginals = new Set();
  const declaredResults = new Set();
  for (const a of altered) {
    if (a.original_hash) declaredOriginals.add(a.original_hash);
    if (a.result_hash) declaredResults.add(a.result_hash);
  }

  if (declaredType === 'append') {
    // append-only: nothing removed, nothing altered; everything before survives.
    if (removed.length) reasons.push('append_removed_spans:' + removed.length);
    if (altered.length) reasons.push('append_with_altered_spans');
    if (mutation.integrity_claim !== 'lossless') reasons.push('append_must_be_lossless');
  } else if (declaredType === 'drop') {
    // drop: removed spans must ALL be disclosed as altered_spans with result null.
    for (const r of removed) {
      if (!declaredOriginals.has(r)) reasons.push('undisclosed_drop:' + r.slice(0, 12));
    }
    for (const a of altered) {
      if (a.result_hash) reasons.push('drop_with_nonnull_result'); // a drop has no result
    }
    // nothing brand-new should be added by a pure drop
    if (added.length) reasons.push('drop_introduced_spans:' + added.length);
    if (mutation.integrity_claim === 'lossless') reasons.push('drop_cannot_be_lossless');
  } else if (declaredType === 'alter') {
    // alter: each removed original must be disclosed; each disclosed result must
    // appear in after; undisclosed removals or undisclosed additions break it.
    for (const r of removed) {
      if (!declaredOriginals.has(r)) reasons.push('undisclosed_alteration_or_drop:' + r.slice(0, 12));
    }
    for (const a of altered) {
      if (a.result_hash && !afterSet.has(a.result_hash)) reasons.push('declared_result_absent_after');
      if (a.original_hash && beforeSet.has(a.original_hash) && afterSet.has(a.original_hash)) {
        reasons.push('declared_alter_but_original_survives');
      }
    }
    // any span added that is NOT a declared alter result is an undisclosed insert
    for (const ad of added) {
      if (!declaredResults.has(ad)) reasons.push('undisclosed_inserted_span:' + ad.slice(0, 12));
    }
    if (mutation.integrity_claim !== 'altered_attested') reasons.push('alter_must_claim_altered_attested');
  } else if (declaredType === 'summarize') {
    // summarize: lossy by nature. before spans collapse into fewer after spans.
    // Must be disclosed lossy; cannot claim lossless. We do not require span-level
    // disclosure (summary is a transformation over the whole set) but it cannot
    // claim to have preserved everything.
    if (mutation.integrity_claim === 'lossless') reasons.push('summarize_cannot_be_lossless');
    if (afterDigests.length > beforeDigests.length) reasons.push('summarize_grew_context');
  } else {
    reasons.push('unknown_mutation_type:' + declaredType);
  }

  return { ok: reasons.length === 0, reasons, removed_count: removed.length, added_count: added.length };
}

/**
 * signCern — seal a single context mutation. Binds:
 *   base || H(before_root || after_root) -> one payload -> one ML-DSA-65 sig.
 *
 * mutation = {
 *   step, run_id?, mutation_type,
 *   context_before: [spans...]  OR  context_before_digests:[...] + context_before_root,
 *   context_after:  [spans...]  OR  context_after_digests:[...]  + context_after_root,
 *   altered_spans: [{ original_hash, result_hash|null, reason }],
 *   integrity_claim
 * }
 *
 * If raw spans are provided we compute the roots + span digests ourselves (the
 * honest path). Callers may instead supply precomputed digests/roots (privacy:
 * the agent need not reveal raw context, only commitments) — the delta logic runs
 * on digests either way.
 */
export function signCern(mutation, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  if (!MUTATION_TYPES.includes(mutation.mutation_type)) {
    throw new Error('invalid_mutation_type:' + mutation.mutation_type);
  }
  if (!INTEGRITY_CLAIMS.includes(mutation.integrity_claim)) {
    throw new Error('invalid_integrity_claim:' + mutation.integrity_claim);
  }

  // resolve before/after digests + roots
  let beforeDigests, before_root, afterDigests, after_root;
  if (Array.isArray(mutation.context_before)) {
    const b = contextRoot(mutation.context_before, suite);
    beforeDigests = b.spanDigests; before_root = b.root;
  } else {
    beforeDigests = mutation.context_before_digests || [];
    before_root = mutation.context_before_root;
    if (!before_root) throw new Error('missing_before_root');
  }
  if (Array.isArray(mutation.context_after)) {
    const a = contextRoot(mutation.context_after, suite);
    afterDigests = a.spanDigests; after_root = a.root;
  } else {
    afterDigests = mutation.context_after_digests || [];
    after_root = mutation.context_after_root;
    if (!after_root) throw new Error('missing_after_root');
  }

  // GATE AT SIGN TIME: the declared delta must be internally consistent with the
  // before/after digests. We refuse to mint a receipt that lies about itself.
  const delta = deriveDelta(beforeDigests, afterDigests, mutation, suite);
  if (!delta.ok) throw new Error('inconsistent_mutation:' + delta.reasons.join(','));

  const altered = (mutation.altered_spans || []).map(a => ({
    original_hash: a.original_hash,
    result_hash: a.result_hash ?? null,
    reason: a.reason || 'unspecified',
  }));

  const baseFields = {
    object: 'sigr.cern.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    run_id: mutation.run_id || 'unspecified',
    step: mutation.step | 0,
    mutation_type: mutation.mutation_type,
    integrity_claim: mutation.integrity_claim,
    context_before_root: before_root,
    context_after_root: after_root,
    altered_spans: altered,
    // ARSC: an ALTERATION is the highest-liability event -> Rise; summarize ->
    // Float; pure append -> Sink (AFiR-S3 §2.3).
    arsc_tier: mutation.mutation_type === 'alter' ? 'rise'
      : mutation.mutation_type === 'append' ? 'sink' : 'float',
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  // bind H(before_root || after_root) as the second half so the state pair is in
  // the signed payload directly.
  const pair = new Uint8Array(dl * 2);
  pair.set(hexToBytes(before_root), 0);
  pair.set(hexToBytes(after_root), dl);
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
    // carry the ordered span digests so a verifier can replay the delta. These
    // are commitments (hashes), not raw context — privacy preserved.
    context_before_digests: beforeDigests,
    context_after_digests: afterDigests,
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
 * verifyCern — independent reconstruction + single signature check.
 *   1. recompute before_root / after_root from the carried ordered span digests
 *      (re-deriving positional leaves) and confirm they match the signed roots
 *   2. re-run deriveDelta — the declared mutation MUST be consistent with the
 *      actual before/after digests (this is where undisclosed alteration/omission
 *      is caught)
 *   3. recompute state_digest, payload, verify the one signature
 */
export function verifyCern(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);

  // 1. recompute roots from carried ordered span digests
  function rootFromDigests(digests) {
    const leaves = (digests || []).map((d, i) => hashHex(canonicalize({ i, d }), suite));
    return leaves.length ? merkleRoot(leaves, suite) : zero;
  }
  const recBefore = rootFromDigests(envelope.context_before_digests);
  const recAfter = rootFromDigests(envelope.context_after_digests);
  if (recBefore !== envelope.context_before_root) reasons.push('before_root_mismatch');
  if (recAfter !== envelope.context_after_root) reasons.push('after_root_mismatch');

  // 2. re-derive the delta — undisclosed alteration / omission caught here
  const delta = deriveDelta(
    envelope.context_before_digests || [],
    envelope.context_after_digests || [],
    { mutation_type: envelope.mutation_type, altered_spans: envelope.altered_spans, integrity_claim: envelope.integrity_claim },
    suite,
  );
  if (!delta.ok) for (const r of delta.reasons) reasons.push('delta:' + r);

  // 3. recompute base, state, payload, signature
  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    run_id: envelope.run_id,
    step: envelope.step,
    mutation_type: envelope.mutation_type,
    integrity_claim: envelope.integrity_claim,
    context_before_root: envelope.context_before_root,
    context_after_root: envelope.context_after_root,
    altered_spans: envelope.altered_spans || [],
    arsc_tier: envelope.arsc_tier,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const pair = new Uint8Array(dl * 2);
  pair.set(hexToBytes(envelope.context_before_root || zero), 0);
  pair.set(hexToBytes(envelope.context_after_root || zero), dl);
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
    mutation_type: envelope.mutation_type,
    integrity_claim: envelope.integrity_claim,
  };
}

/**
 * howler.js — Howler: intent-formation alarm primitive.
 *
 * HC-2026-018. The primitive that watches the model's REASONING, not its
 * actions. Sits between CarnacPrompt (policy signed) and Carnac Gateway
 * (arrival countersigned), emitting signed alarm receipts inside the
 * reasoning loop.
 *
 * Novel core: SPARSE-AUTOENCODER-FEATURE-TRIGGERED FREEZE.
 * Every N tokens, Howler computes:
 *   - a trajectory embedding of the running reasoning trace
 *   - a sparse-autoencoder feature-activation vector from the model's
 *     residual stream (or a proxy embedding)
 * When either signal crosses a signed threshold, Howler emits a signed
 * receipt that names the exact triggering feature indices + magnitudes.
 * A third party in possession of the SAE can INDEPENDENTLY replay the
 * probe against the same trace prefix and confirm the flagged features
 * fired. This turns SAE probes — the hottest research surface in
 * frontier-lab interpretability — into a signed, verifiable, third-party-
 * checkable safety signal.
 *
 * Three receipt types:
 *
 *   howler.drift — trajectory-drift alarm.
 *     Binds: trace_prefix_digest, expected_task_shape_ref,
 *     drift_score_bp (integer basis points 0..10000), drift_threshold_bp,
 *     token_position_at_trigger. Fires when the reasoning trajectory
 *     diverges from the CarnacPrompt-declared expected task shape.
 *
 *   howler.capability — capability-out-of-scope alarm.
 *     Binds: trace_prefix_digest, scope_ref (AFiR-S3 Tool-Scope receipt id),
 *     requested_capability_id, sae_feature_indices (list of triggering
 *     feature ids), sae_feature_magnitudes_bp. Fires BEFORE the tool call
 *     is emitted — catches intent to escape before the escape.
 *
 *   howler.contamination — context-contamination alarm.
 *     Binds: contamination_class (one of: credential, key, pii,
 *     model_weight, code_exfil), contamination_entropy_bits,
 *     regex_pattern_id, position_at_detect. Fires when the model's own
 *     reasoning includes credential-shaped or key-shaped strings that
 *     were NOT in the signed input envelope.
 *
 * Fail-closed coupling: no fresh valid howler.drift receipt within the
 * declared cadence window → Carnac Gateway refuses execution. This is
 * what makes Howler prevention, not just detection.
 *
 * Patent Pending HC-2026-018 (a method for emitting cryptographically
 * signed pre-effect alarm receipts triggered by sparse-autoencoder
 * feature activations in an autonomous agent's residual stream, wherein
 * each receipt names the triggering feature indices and activation
 * magnitudes such that a third-party verifier in possession of the
 * autoencoder can independently confirm the flagged features fired
 * against the same reasoning-trace prefix, and wherein a fail-closed
 * downstream gate refuses execution when the applicable alarm receipt
 * set is not fresh, valid, or below threshold).
 */

import { canonicalize, hashHex, resolveSuite } from './typed.js';
import { signUpstreamReceipt, verifyUpstreamReceipt } from './upstream.js';

const TYPE_DRIFT = 'howler.drift';
const TYPE_CAP = 'howler.capability';
const TYPE_CONTAM = 'howler.contamination';

/** Compute a digest of a trace prefix — the ordered sequence of tokens
 *  (or token ids) up to the trigger point. */
export function tracePrefixDigest(tokens, suite) {
  const s = suite || resolveSuite('sha-256');
  return hashHex(canonicalize({ tokens: [...tokens] }), s);
}

/**
 * saeVectorDigest — deterministic digest over (index, magnitude_bp) pairs
 * so a third party can recompute the same digest and check the receipt
 * without transmitting the full vector.
 */
export function saeVectorDigest(indices, magnitudes_bp, suite) {
  const s = suite || resolveSuite('sha-256');
  const pairs = indices.map((idx, i) => ({ i: idx, m: magnitudes_bp[i] }))
    .sort((a, b) => a.i - b.i);
  return hashHex(canonicalize({ sae: pairs }), s);
}

/** signHowlerDrift — trajectory-drift alarm receipt. */
export function signHowlerDrift(alarm, signer, opts = {}) {
  if (!alarm.trace_tokens) throw new Error('missing_trace');
  if (!Number.isInteger(alarm.drift_score_bp)) throw new Error('bad_drift_score');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const payload = {
    trace_prefix_digest: tracePrefixDigest(alarm.trace_tokens, suite),
    expected_task_shape_ref: alarm.expected_task_shape_ref,
    drift_score_bp: alarm.drift_score_bp,
    drift_threshold_bp: alarm.drift_threshold_bp,
    token_position_at_trigger: alarm.token_position_at_trigger,
    disposition: alarm.drift_score_bp >= alarm.drift_threshold_bp ? 'freeze' : 'continue',
  };
  return signUpstreamReceipt(TYPE_DRIFT, payload, {
    run_id: alarm.run_id, tenant_id: alarm.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/** signHowlerCapability — capability-out-of-scope alarm with SAE features. */
export function signHowlerCapability(alarm, signer, opts = {}) {
  if (!alarm.trace_tokens) throw new Error('missing_trace');
  if (!alarm.requested_capability_id) throw new Error('missing_capability');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const sae_indices = alarm.sae_feature_indices || [];
  const sae_mags = alarm.sae_feature_magnitudes_bp || [];
  if (sae_indices.length !== sae_mags.length) throw new Error('sae_length_mismatch');
  const payload = {
    trace_prefix_digest: tracePrefixDigest(alarm.trace_tokens, suite),
    scope_ref: alarm.scope_ref,
    requested_capability_id: alarm.requested_capability_id,
    sae_feature_indices: sae_indices,
    sae_feature_magnitudes_bp: sae_mags,
    sae_vector_digest: saeVectorDigest(sae_indices, sae_mags, suite),
    sae_probe_id: alarm.sae_probe_id || 'default',
    disposition: 'freeze',
  };
  return signUpstreamReceipt(TYPE_CAP, payload, {
    run_id: alarm.run_id, tenant_id: alarm.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/** signHowlerContamination — context contamination alarm. */
export function signHowlerContamination(alarm, signer, opts = {}) {
  if (!alarm.contamination_class) throw new Error('missing_class');
  const payload = {
    contamination_class: alarm.contamination_class,
    contamination_entropy_bits: alarm.contamination_entropy_bits,
    regex_pattern_id: alarm.regex_pattern_id,
    position_at_detect: alarm.position_at_detect,
    matched_span_digest: alarm.matched_span_digest, // digest of the offending span, not the plaintext
    disposition: 'freeze',
  };
  return signUpstreamReceipt(TYPE_CONTAM, payload, {
    run_id: alarm.run_id, tenant_id: alarm.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/**
 * verifyHowlerCapabilityWithSae — a third-party verifier who possesses
 * the SAE probe can call this to independently confirm the flagged
 * features fired against the same trace-prefix.
 *
 * @param receipt   the signed howler.capability receipt
 * @param sae_probe function(trace_tokens) -> { indices, magnitudes_bp }
 * @param trace_tokens the original trace prefix (obtained out-of-band)
 */
export function verifyHowlerCapabilityWithSae(receipt, sae_probe, trace_tokens, verifyFn, pubBytes, opts = {}) {
  const base = verifyUpstreamReceipt(receipt, TYPE_CAP, verifyFn, pubBytes, opts);
  if (!base.ok) return base;
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  // 1. confirm the trace-prefix digest matches the provided tokens
  const td = tracePrefixDigest(trace_tokens, suite);
  if (td !== receipt.payload.trace_prefix_digest) return { ok: false, reason: 'trace_mismatch' };
  // 2. re-run the SAE probe
  const { indices, magnitudes_bp } = sae_probe(trace_tokens);
  const d = saeVectorDigest(indices, magnitudes_bp, suite);
  if (d !== receipt.payload.sae_vector_digest) return { ok: false, reason: 'sae_digest_mismatch' };
  return { ok: true, features_matched: indices.length };
}

// legacy shims for server routing
export const verifyHowlerDrift = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_DRIFT, v, pk, o);
export const verifyHowlerCapability = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_CAP, v, pk, o);
export const verifyHowlerContamination = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_CONTAM, v, pk, o);

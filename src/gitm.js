/**
 * gitm.js — GiTM: Glitch in the Matrix.
 *
 * Spec §2. A SIGNED ANOMALY FLAG computed by cross-checking the provenance signals
 * ALREADY produced across the stack for one or more receipts. It is NOT a new
 * measurement of the content; it is a *consistency check across existing signed
 * measurements*. When the instruments disagree with each other or with the expected
 * pattern, that is a glitch.
 *
 * THE HONEST LINE (the entire design constraint — spec §0, §2.5, §3 — carry verbatim):
 *   - A GiTM is a property of the PROVENANCE, not the content. It NEVER asserts the
 *     output is false.
 *   - It asserts that the *proof of how the output was produced exhibits an anomaly*
 *     and recommends re-running to triangulate.
 *   - NOT hallucination detection. NOT a truth oracle. NOT a content judgment. NOT a
 *     rejection. The severity score is an ANOMALY score, NEVER a truth probability.
 *   - The `asserts: "provenance_anomaly_only"` field is a BINDING declaration that
 *     this receipt makes no claim about truth, only about signal consistency. It is
 *     what makes the primitive legally and epistemically safe.
 *
 * The glitch sources (all from EXISTING signed signals — spec §2.2):
 *   - grounding_anomaly        : from GCA / ARSC — high-consequence claims unsupported,
 *                                or support wildly uneven across claims
 *   - identity_flicker         : from MiR / MiR+ — model identity / attestation weaker
 *                                than the task warrants, or shifted mid-session
 *   - chain_irregularity       : from CERN / chain — attested alteration, unexpected
 *                                context mutation, or provenance depth off pattern
 *   - cross_run_divergence     : from re-run comparison — same query re-run yields
 *                                materially different provenance signatures
 *   - under_attested_high_stakes : from MiR+ / consequence — an L0 self-attested
 *                                identity (or low settlement tier) on a high-stakes answer
 *
 * Float discipline: every signal and the composite severity are carried as INTEGERS
 * in basis points (0..10000) so the signed anomaly score is exact. `severity_bp` is
 * a weighted mean of the active signal bp values. The caller may pass `severity_bp`
 * (integer) or `severity` (0..1 float); we normalize to bp and bind the integer.
 *
 * Rides SiGR (spec §4): the GiTM receipt is a SiGR variant, anchored, zero-secret
 * verifiable. ARSC tier: Critical (answer-time cross-check) — arsc_tier: 'critical'.
 *
 * The output is NOT a verdict. It is a PROTOCOL: anomaly detected -> re-run N times
 * (default 3, scaled by severity) and triangulate. Divergence across re-runs is a
 * *provable* claim ("the answer is unstable"); "the answer is false" is not.
 *
 * Trust model: zero-secret verification. Only the published ML-DSA-65 public key and
 * the receipt are needed; the verifier recomputes the trigger decision, the composite
 * severity, the recommended rerun count, re-binds the base, and checks the single
 * signature. A misreported severity, a hidden glitch type, or a tampered
 * recommendation all break verification.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, bind-one-payload, SIGNER/verifyFn —
 * identical discipline to consensus.js / reward.js / gca.js.
 *
 * Patent Pending (a method for generating a signed anomaly flag by cross-checking a
 * plurality of provenance signals associated with one or more inference receipts and,
 * responsive to the flag, invoking a triangulation protocol that re-executes the
 * query and compares provenance signatures across executions to produce a signed
 * finding of stability or instability, wherein the method asserts an anomaly in
 * provenance and NOT a truth value of the output — spec §5 GiTM independent claim).
 * Internal docket only; not yet assigned a number.
 */
import {
  canonicalize, hashHex, resolveSuite,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Recognized glitch types (spec §2.2). Order is canonical; output is sorted.
export const GLITCH_TYPES = [
  'grounding_anomaly',
  'identity_flicker',
  'chain_irregularity',
  'cross_run_divergence',
  'under_attested_high_stakes',
];

// Maps each glitch type to the signal key (in basis points 0..10000) that drives it.
const SIGNAL_FOR_GLITCH = {
  grounding_anomaly: 'grounding_anomaly_bp',
  identity_flicker: 'identity_flicker_bp',
  chain_irregularity: 'chain_irregularity_bp',
  cross_run_divergence: 'cross_run_divergence_bp',
  under_attested_high_stakes: 'under_attested_high_stakes_bp',
};

/**
 * toBp — accept a 0..1 float OR an explicit integer basis-points value and return an
 * integer clamped to 0..10000.
 */
export function toBp(floatVal, bpVal) {
  if (bpVal !== undefined && bpVal !== null) {
    return Math.max(0, Math.min(10000, Math.round(Number(bpVal)) | 0));
  }
  const f = Number(floatVal);
  if (Number.isNaN(f)) return 0;
  return Math.max(0, Math.min(10000, Math.round(f * 10000)));
}

/**
 * normalizeSignals — pull every supported provenance signal out of the input into a
 * canonical integer-bp signal map. Each signal is the strength (0..10000) of one
 * glitch source. Missing signals are 0 (not present). The caller supplies these from
 * the upstream signed receipts (GCA, MiR, CERN, re-run comparison) — GiTM does not
 * re-measure content, only cross-checks.
 */
export function normalizeSignals(input) {
  const s = input.signals || input;
  return {
    grounding_anomaly_bp: toBp(s.grounding_anomaly, s.grounding_anomaly_bp),
    identity_flicker_bp: toBp(s.identity_flicker, s.identity_flicker_bp),
    chain_irregularity_bp: toBp(s.chain_irregularity, s.chain_irregularity_bp),
    cross_run_divergence_bp: toBp(s.cross_run_divergence, s.cross_run_divergence_bp),
    under_attested_high_stakes_bp: toBp(s.under_attested_high_stakes, s.under_attested_high_stakes_bp),
  };
}

/**
 * computeGitm — the deterministic anomaly decision. Pure; same result provider-side
 * and verifier-side. A glitch type is ACTIVE when its signal exceeds `trigger_bp`
 * (default 2000 = 0.20). `severity_bp` is the MEAN of the ACTIVE signal values (an
 * anomaly score, NOT a truth probability). The recommended rerun count scales with
 * severity: 3 baseline, +1 above 6000bp, +1 above 8000bp (capped at 5). When no
 * glitch is active, GiTM does not trigger and recommends 0 reruns.
 */
export function computeGitm(signals, params = {}) {
  const trigger_bp = params.trigger_bp !== undefined ? (params.trigger_bp | 0) : 2000;

  const active = [];
  const activeVals = [];
  for (const gt of GLITCH_TYPES) {
    const v = signals[SIGNAL_FOR_GLITCH[gt]] || 0;
    if (v >= trigger_bp) { active.push(gt); activeVals.push(v); }
  }
  active.sort();

  const triggered = active.length > 0;
  const severity_bp = triggered
    ? Math.round(activeVals.reduce((a, b) => a + b, 0) / activeVals.length)
    : 0;

  let reruns = 0;
  if (triggered) {
    reruns = 3;
    if (severity_bp >= 6000) reruns += 1;
    if (severity_bp >= 8000) reruns += 1;
    if (reruns > 5) reruns = 5;
  }

  return {
    triggered,
    glitch_types: active,
    severity_bp,
    trigger_bp,
    reruns,
  };
}

/**
 * signGitm — seal a cross-signal anomaly flag. Binds:
 *   base || decision_digest -> one payload -> one ML-DSA-65 sig.
 *
 * gitm = {
 *   subject_id?,                              // the answer / receipt this flag is FOR
 *   claims_root_ref?,                         // 0x<GCA claims_root> the grounding signal came from
 *   signals: {                               // from upstream signed receipts (floats 0..1 or *_bp ints)
 *     grounding_anomaly, identity_flicker, chain_irregularity,
 *     cross_run_divergence, under_attested_high_stakes
 *   },
 *   trigger_bp?                              // override the 2000bp default
 * }
 *
 * The receipt NEVER asserts truth. `asserts: "provenance_anomaly_only"` is bound into
 * the signed base. severity_bp is an anomaly score. The recommendation is a protocol,
 * not a verdict.
 */
export function signGitm(gitm, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const signals = normalizeSignals(gitm);
  const decision = computeGitm(signals, { trigger_bp: gitm.trigger_bp });

  const recommendation = decision.triggered
    ? {
        action: 'triangulate',
        reruns: decision.reruns,
        rationale: 'provenance signals unstable; re-run and compare claim-support maps',
      }
    : {
        action: 'none',
        reruns: 0,
        rationale: 'provenance signals within expected bounds; no anomaly detected',
      };

  // the decision record binds the full anomaly computation so it cannot be misreported
  const decisionRecord = {
    object: 'sigr.gitm.decision',
    triggered: decision.triggered,
    glitch_types: decision.glitch_types,
    severity_bp: decision.severity_bp,
    trigger_bp: decision.trigger_bp,
    signals,
    recommendation,
  };
  const decisionDigest = hashHex(canonicalize(decisionRecord), suite);

  const baseFields = {
    object: 'sigr.gitm.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    subject_id: gitm.subject_id || 'unspecified',
    claims_root_ref: gitm.claims_root_ref || null,   // the GCA root the grounding signal rode in on
    triggered: decision.triggered,
    severity_bp: decision.severity_bp,               // anomaly score (NOT truth) in basis points
    decision_digest: decisionDigest,
    asserts: 'provenance_anomaly_only',              // BINDING: never asserts falsity
    arsc_tier: 'critical',
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(decisionDigest), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    decision: decisionRecord,                        // full computation carried for re-derivation
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
 * verifyGitm — independent recompute + single signature check.
 *   - RE-RUN computeGitm from the carried signals, confirm trigger / severity / reruns
 *   - re-derive the decision_digest, confirm it matches the signed value
 *   - confirm the binding asserts: "provenance_anomaly_only" is intact
 *   - re-bind base + decision_digest, recompute payload, verify the one signature
 * A misreported severity, a hidden glitch type, an inflated rerun count, or a tampered
 * recommendation all break verification.
 */
export function verifyGitm(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  // the binding non-truth declaration MUST be intact
  if (envelope.asserts !== 'provenance_anomaly_only') reasons.push('asserts_declaration_tampered');

  const carried = envelope.decision || {};
  const signals = carried.signals || {};

  // RE-RUN the anomaly decision from the carried signals
  const recDecision = computeGitm(signals, { trigger_bp: carried.trigger_bp });
  if (recDecision.triggered !== carried.triggered) reasons.push('triggered_mismatch');
  if (recDecision.severity_bp !== carried.severity_bp) reasons.push('severity_mismatch');
  const recGlitch = [...recDecision.glitch_types].sort();
  const carGlitch = [...(carried.glitch_types || [])].sort();
  if (canonicalize(recGlitch) !== canonicalize(carGlitch)) reasons.push('glitch_types_mismatch');
  if (recDecision.reruns !== (carried.recommendation ? carried.recommendation.reruns : undefined)) {
    reasons.push('rerun_count_mismatch');
  }

  // the top-level severity / triggered must match the decision record
  if (envelope.severity_bp !== carried.severity_bp) reasons.push('top_severity_mismatch');
  if (envelope.triggered !== carried.triggered) reasons.push('top_triggered_mismatch');

  // re-derive the decision digest from the carried record
  const recDecisionDigest = hashHex(canonicalize(carried), suite);
  if (recDecisionDigest !== envelope.decision_digest) reasons.push('decision_digest_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    subject_id: envelope.subject_id,
    claims_root_ref: envelope.claims_root_ref,
    triggered: envelope.triggered,
    severity_bp: envelope.severity_bp,
    decision_digest: envelope.decision_digest,
    asserts: envelope.asserts,
    arsc_tier: envelope.arsc_tier,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.decision_digest), dl);
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
    triggered: envelope.triggered,
    severity_bp: envelope.severity_bp,
    glitch_types: carried.glitch_types || [],
    recommendation: carried.recommendation,
    asserts: envelope.asserts,
  };
}

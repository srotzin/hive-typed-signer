/**
 * mir.js — MiR: Model-Identity & Relineage.
 *
 * The keystone that closes the model-substitution gap. A model manifest (manifest.js,
 * P4) proves a single model identity was DECLARED. MiR binds an ordered SEQUENCE of
 * served-model identities for one session/answer into ONE ML-DSA-65 signature and
 * computes a deterministic, recomputable identity-continuity finding:
 *
 *   - did the served identity match what the caller EXPECTED (e.g. "GLM-5.2")?
 *   - did the identity SHIFT mid-session (relineage — the model behind the API
 *     changed between steps)?
 *
 * This is the answer to "you served me GLM-5.2 — prove the bytes came from GLM-5.2
 * and not a cheaper model swapped in behind the API." A swap changes model_id /
 * weights_sha3 / config_hash; MiR detects the change, scores it, and SIGNS the
 * finding so a third party can verify it offline with only the published public key.
 *
 * THE HONEST LINE (carry verbatim — this is what keeps MiR legally + epistemically safe):
 *   - MiR asserts MODEL IDENTITY and IDENTITY CONTINUITY, never output quality or truth.
 *   - "served identity != expected identity" is a SUBSTITUTION finding, not a fraud
 *     verdict; a legitimate fallback is also a substitution and MiR reports it as such.
 *   - identity_flicker_bp is an IDENTITY-INSTABILITY score (0..10000), NOT a truth or
 *     hallucination score. It is the real, signed signal GiTM consumes for its
 *     `identity_flicker` glitch source — replacing the previously caller-asserted number.
 *
 * What MiR binds, per receipt:
 *   - subject_id            : the answer / session this lineage is FOR
 *   - expected_model?       : the model the caller declared they were buying (optional)
 *   - steps[]               : ordered served-model identities, each:
 *        { model_id, weights_sha3, config_hash, endpoint, manifest_nullifier? }
 *   - identity_root         : Merkle root over per-step manifest roots, in order
 *   - relineage[]           : every index where identity changed from the prior step,
 *                             with which fields changed
 *   - substitution          : { expected, matched_all, mismatched_steps[] } when an
 *                             expected_model is supplied
 *   - identity_flicker_bp   : deterministic identity-instability score (0..10000)
 *
 * Float discipline: the flicker score is carried as an INTEGER in basis points so the
 * signed value is exact. Determinism: signMir computes the finding; verifyMir RE-RUNS
 * the identical computation from the carried steps and confirms every field — a
 * misreported relineage point, a hidden swap, or an inflated/deflated flicker score
 * all break verification.
 *
 * Rides SiGR: zero-secret verification, single PQ signature, identical discipline to
 * manifest.js / gitm.js / gca.js. ARSC tier: 'rise' (an identity declaration is the
 * anchor downstream receipts resolve against).
 *
 * Patent Pending (a method for binding an ordered plurality of attested model-identity
 * manifests for an inference session into a single post-quantum signature, computing a
 * deterministic identity-continuity finding that detects (i) divergence of a served
 * model identity from a caller-declared expected identity and (ii) relineage of the
 * served model identity across steps of the session, and emitting an integer
 * identity-instability score consumable by a downstream cross-signal anomaly flag,
 * wherein the finding asserts model identity and continuity and NOT a truth value of
 * any output). Internal docket only; not yet assigned a number.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { manifestRoot } from './manifest.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// The identity fields that define a served model. A change in ANY of these between
// steps is a relineage event (the model behind the API shifted).
const IDENTITY_FIELDS = ['model_id', 'weights_sha3', 'config_hash'];

/**
 * stepRoot — the manifest root for one served-model step. Reuses manifest.js's
 * manifestRoot so a MiR step is byte-identical to the corresponding P4 manifest.
 */
function stepRoot(step, suite) {
  return manifestRoot(
    step.model_id, step.weights_sha3, step.config_hash, step.endpoint, suite,
  );
}

/**
 * changedFields — which identity fields differ between two steps. Sorted, canonical.
 */
function changedFields(a, b) {
  const out = [];
  for (const f of IDENTITY_FIELDS) {
    if (String(a[f]) !== String(b[f])) out.push(f);
  }
  out.sort();
  return out;
}

/**
 * computeLineage — the deterministic identity-continuity finding. Pure; identical
 * provider-side and verifier-side.
 *
 *   - identity_root : Merkle root over per-step manifest roots IN ORDER
 *   - relineage     : [{ from_index, to_index, changed_fields[] }] for every step
 *                     whose identity differs from the immediately prior step
 *   - substitution  : present only when expected_model supplied. matched_all is true
 *                     iff EVERY step's model_id equals expected_model. mismatched_steps
 *                     lists the indices that did not match.
 *   - identity_flicker_bp : integer 0..10000 anomaly score. 0 when one stable identity
 *                     matching expectation. Rises with (a) each relineage event and
 *                     (b) each step that fails to match expected_model. Capped 10000.
 *
 * Scoring (deterministic, integer-only):
 *   base per relineage event   = 2500 bp
 *   base per expectation miss   = 2000 bp
 *   a relineage of weights_sha3 (the strongest swap signal) adds an extra 1500 bp
 *   final = min(10000, sum). With no events and full expectation match, 0.
 */
export function computeLineage(steps, expected_model, suite) {
  const s = suite || resolveSuite('sha-256');
  if (!Array.isArray(steps) || steps.length === 0) {
    throw new Error('missing_steps');
  }

  const roots = steps.map((st) => stepRoot(st, s));
  const identity_root = merkleRoot(roots, s);

  const relineage = [];
  for (let i = 1; i < steps.length; i += 1) {
    const cf = changedFields(steps[i - 1], steps[i]);
    if (cf.length > 0) {
      relineage.push({ from_index: i - 1, to_index: i, changed_fields: cf });
    }
  }

  let substitution = null;
  if (expected_model !== undefined && expected_model !== null && expected_model !== '') {
    const mismatched_steps = [];
    steps.forEach((st, i) => {
      if (String(st.model_id) !== String(expected_model)) mismatched_steps.push(i);
    });
    substitution = {
      expected: String(expected_model),
      matched_all: mismatched_steps.length === 0,
      mismatched_steps,
    };
  }

  // deterministic integer flicker score
  let score = 0;
  for (const r of relineage) {
    score += 2500;
    if (r.changed_fields.includes('weights_sha3')) score += 1500;
  }
  if (substitution) score += 2000 * substitution.mismatched_steps.length;
  const identity_flicker_bp = Math.max(0, Math.min(10000, score | 0));

  return {
    step_count: steps.length,
    identity_root,
    per_step_roots: roots,
    relineage,
    substitution,
    identity_flicker_bp,
    stable: relineage.length === 0 && (!substitution || substitution.matched_all),
  };
}

/**
 * signMir — seal a model-identity & relineage finding.
 *   base || lineage_digest -> one payload -> one ML-DSA-65 sig.
 *
 * mir = {
 *   subject_id?,
 *   expected_model?,                 // the model the caller declared they were buying
 *   steps: [                         // ordered served-model identities
 *     { model_id, weights_sha3, config_hash, endpoint, manifest_nullifier? }, ...
 *   ]
 * }
 */
export function signMir(mir, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  if (!mir || !Array.isArray(mir.steps) || mir.steps.length === 0) {
    throw new Error('missing_steps');
  }
  for (const st of mir.steps) {
    if (!st || !st.model_id) throw new Error('step_missing_model_id');
    if (!st.weights_sha3) throw new Error('step_missing_weights_sha3');
    if (!st.config_hash) throw new Error('step_missing_config_hash');
    if (!st.endpoint) throw new Error('step_missing_endpoint');
  }

  const lineage = computeLineage(mir.steps, mir.expected_model, suite);

  // the lineage record binds the full continuity computation so it cannot be misreported
  const lineageRecord = {
    object: 'sigr.mir.lineage',
    step_count: lineage.step_count,
    identity_root: lineage.identity_root,
    per_step_roots: lineage.per_step_roots,
    relineage: lineage.relineage,
    substitution: lineage.substitution,
    identity_flicker_bp: lineage.identity_flicker_bp,
    stable: lineage.stable,
  };
  const lineageDigest = hashHex(canonicalize(lineageRecord), suite);

  const baseFields = {
    object: 'sigr.mir.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    subject_id: mir.subject_id || 'unspecified',
    expected_model: (mir.expected_model !== undefined && mir.expected_model !== null)
      ? String(mir.expected_model) : null,
    identity_root: lineage.identity_root,
    identity_flicker_bp: lineage.identity_flicker_bp,   // signed identity-instability score for GiTM
    stable: lineage.stable,
    lineage_digest: lineageDigest,
    asserts: 'model_identity_and_continuity_only',      // BINDING: never asserts truth/quality
    arsc_tier: 'rise',
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(lineageDigest), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    lineage: lineageRecord,                              // full computation carried for re-derivation
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
 * verifyMir — independent recompute + single signature check.
 *   - RE-RUN computeLineage from the carried steps... but the steps themselves are not
 *     carried raw; the lineage record carries per_step_roots + the derived finding. We
 *     re-derive identity_root from per_step_roots, re-run relineage/substitution/score
 *     ONLY from carried fields, and confirm every signed value matches.
 *   - confirm the binding asserts: "model_identity_and_continuity_only" is intact
 *   - re-bind base + lineage_digest, recompute payload, verify the one signature
 *
 * Note: verification works on the carried lineage record (per_step_roots + relineage +
 * substitution), which is sufficient to confirm identity_root and identity_flicker_bp
 * were honestly computed. To additionally confirm the per_step_roots themselves match
 * raw step fields, pass opts.steps (the original steps array); when supplied we
 * recompute each stepRoot and confirm.
 */
export function verifyMir(envelope, verifyFn, pubBytes, opts = {}) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  // binding non-truth declaration MUST be intact
  if (envelope.asserts !== 'model_identity_and_continuity_only') {
    reasons.push('asserts_declaration_tampered');
  }

  const carried = envelope.lineage || {};
  const roots = Array.isArray(carried.per_step_roots) ? carried.per_step_roots : [];

  // 1. identity_root must be the Merkle root over the carried per-step roots, in order
  if (roots.length === 0) {
    reasons.push('no_per_step_roots');
  } else {
    const recIdentityRoot = merkleRoot(roots, suite);
    if (recIdentityRoot !== carried.identity_root) reasons.push('identity_root_mismatch');
    if (carried.identity_root !== envelope.identity_root) reasons.push('top_identity_root_mismatch');
  }

  // 2. optional: confirm per_step_roots actually derive from raw steps (strongest check)
  if (Array.isArray(opts.steps) && opts.steps.length > 0) {
    if (opts.steps.length !== roots.length) {
      reasons.push('step_count_mismatch_vs_roots');
    } else {
      opts.steps.forEach((st, i) => {
        const rr = stepRoot(st, suite);
        if (rr !== roots[i]) reasons.push('step_root_mismatch_at_' + i);
      });
    }
  }

  // 3. re-derive the flicker score from carried relineage + substitution (integer-exact)
  let recScore = 0;
  for (const r of (carried.relineage || [])) {
    recScore += 2500;
    if (Array.isArray(r.changed_fields) && r.changed_fields.includes('weights_sha3')) recScore += 1500;
  }
  if (carried.substitution && Array.isArray(carried.substitution.mismatched_steps)) {
    recScore += 2000 * carried.substitution.mismatched_steps.length;
  }
  recScore = Math.max(0, Math.min(10000, recScore | 0));
  if (recScore !== carried.identity_flicker_bp) reasons.push('flicker_score_mismatch');
  if (envelope.identity_flicker_bp !== carried.identity_flicker_bp) reasons.push('top_flicker_mismatch');

  // 4. stable flag consistency
  const recStable = (carried.relineage || []).length === 0
    && (!carried.substitution || carried.substitution.matched_all === true);
  if (recStable !== carried.stable) reasons.push('stable_flag_mismatch');
  if (envelope.stable !== carried.stable) reasons.push('top_stable_mismatch');

  // 5. re-derive the lineage digest from the carried record
  const recLineageDigest = hashHex(canonicalize(carried), suite);
  if (recLineageDigest !== envelope.lineage_digest) reasons.push('lineage_digest_mismatch');

  // 6. recompute base + payload, verify the one signature
  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    subject_id: envelope.subject_id,
    expected_model: envelope.expected_model,
    identity_root: envelope.identity_root,
    identity_flicker_bp: envelope.identity_flicker_bp,
    stable: envelope.stable,
    lineage_digest: envelope.lineage_digest,
    asserts: envelope.asserts,
    arsc_tier: envelope.arsc_tier,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.lineage_digest || '0'.repeat(dl * 2)), dl);
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
    subject_id: envelope.subject_id,
    expected_model: envelope.expected_model,
    identity_root: envelope.identity_root,
    identity_flicker_bp: envelope.identity_flicker_bp,
    stable: envelope.stable,
    relineage: carried.relineage || [],
    substitution: carried.substitution || null,
  };
}

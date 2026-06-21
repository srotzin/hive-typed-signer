// GiTM tests: anomaly decision math (pure), trigger threshold, severity = mean of
// active signals (NOT truth), rerun scaling by severity, no-trigger path, sign+verify,
// asserts="provenance_anomaly_only" tamper detection, severity/glitch tamper detection.
import { SIGNER, verifyFn } from '../src/key.js';
import {
  signGitm, verifyGitm, computeGitm, normalizeSignals, toBp, GLITCH_TYPES,
} from '../src/gitm.js';
import { hashHex, resolveSuite } from '../src/typed.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;
const S = resolveSuite('sha-256');

section('gitm: bp normalization');
{
  eq(toBp(0.74), 7400, 'float 0.74 -> 7400bp');
  eq(toBp(undefined, 6300), 6300, 'explicit bp passthrough');
  eq(toBp(5), 10000, 'clamps above 1.0');
}

section('gitm: decision math (pure) — severity is mean of ACTIVE signals, not truth');
{
  // two signals above 2000bp trigger threshold: grounding 0.74, cross_run 0.63
  const sig = normalizeSignals({
    signals: { grounding_anomaly: 0.74, cross_run_divergence: 0.63, identity_flicker: 0.05 },
  });
  const d = computeGitm(sig);
  ok(d.triggered, 'triggered when signals exceed threshold');
  eq(d.glitch_types.length, 2, 'two glitch types active (identity 0.05 below 0.20 threshold)');
  ok(d.glitch_types.includes('grounding_anomaly') && d.glitch_types.includes('cross_run_divergence'),
     'correct glitch types active');
  eq(d.severity_bp, Math.round((7400 + 6300) / 2), 'severity = mean of active signals (6850bp)');
  eq(d.reruns, 4, 'reruns 3 baseline +1 above 6000bp severity');
}

section('gitm: no-trigger path (all signals within bounds)');
{
  const sig = normalizeSignals({ signals: { grounding_anomaly: 0.1, identity_flicker: 0.05 } });
  const d = computeGitm(sig);
  ok(!d.triggered, 'no trigger when all below threshold');
  eq(d.severity_bp, 0, 'severity 0 when not triggered');
  eq(d.reruns, 0, 'no reruns recommended when stable');
}

section('gitm: rerun scaling by severity');
{
  // all five maxed -> severity 10000bp -> 5 reruns (capped)
  const hi = computeGitm(normalizeSignals({ signals: {
    grounding_anomaly: 1, identity_flicker: 1, chain_irregularity: 1,
    cross_run_divergence: 1, under_attested_high_stakes: 1,
  } }));
  eq(hi.severity_bp, 10000, 'all-maxed severity 10000bp');
  eq(hi.reruns, 5, 'reruns capped at 5');
}

section('gitm: sign + verify happy path');
{
  const gitm = {
    subject_id: 'ans-1',
    claims_root_ref: hashHex('gca-root', S),
    signals: { grounding_anomaly: 0.74, cross_run_divergence: 0.63 },
  };
  const { envelope } = signGitm(gitm, SIGNER);
  const v = verifyGitm(envelope, verifyFn, PUB);
  ok(v.valid, 'honest GiTM verifies; reasons=' + v.reasons.join(','));
  eq(envelope.asserts, 'provenance_anomaly_only', 'binding non-truth declaration present');
  ok(envelope.triggered, 'triggered surfaced at top level');
  eq(envelope.decision.recommendation.action, 'triangulate', 'recommends triangulation, not a verdict');
  ok(envelope.claims_root_ref === gitm.claims_root_ref, 'GCA root reference carried');
}

section('gitm: untriggered receipt is still a valid signed record');
{
  const { envelope } = signGitm({ signals: { grounding_anomaly: 0.1 } }, SIGNER);
  ok(verifyGitm(envelope, verifyFn, PUB).valid, 'stable (untriggered) GiTM verifies');
  eq(envelope.decision.recommendation.action, 'none', 'no triangulation when stable');
}

section('gitm: tamper detection');
{
  const { envelope } = signGitm({
    signals: { grounding_anomaly: 0.74, cross_run_divergence: 0.63 },
  }, SIGNER);

  // 1. tamper the binding non-truth declaration -> rejected
  const t1 = JSON.parse(JSON.stringify(envelope));
  t1.asserts = 'output_is_false';
  const v1 = verifyGitm(t1, verifyFn, PUB);
  ok(!v1.valid, 'tampered asserts declaration detected');
  ok(v1.reasons.includes('asserts_declaration_tampered'), 'asserts tamper flagged: ' + v1.reasons.join(','));

  // 2. inflate the severity score -> recompute mismatch
  const t2 = JSON.parse(JSON.stringify(envelope));
  t2.decision.severity_bp = 10000;
  t2.severity_bp = 10000;
  ok(!verifyGitm(t2, verifyFn, PUB).valid, 'inflated severity detected');

  // 3. hide a glitch type -> recompute mismatch
  const t3 = JSON.parse(JSON.stringify(envelope));
  t3.decision.glitch_types = ['grounding_anomaly'];
  ok(!verifyGitm(t3, verifyFn, PUB).valid, 'hidden glitch type detected');

  // 4. inflate the rerun recommendation -> mismatch
  const t4 = JSON.parse(JSON.stringify(envelope));
  t4.decision.recommendation.reruns = 99;
  ok(!verifyGitm(t4, verifyFn, PUB).valid, 'inflated rerun count detected');
}

section('gitm: fail-closed on bad input');
{
  let threw = false;
  try { signGitm({}, SIGNER); } catch (e) { threw = true; }
  // empty signals normalizes to all-zero -> untriggered, still signs a valid stable record.
  ok(!threw, 'empty input signs a stable (untriggered) record rather than throwing');
  const { envelope } = signGitm({}, SIGNER);
  ok(!envelope.triggered, 'empty signals -> not triggered');
}

summary('gitm');

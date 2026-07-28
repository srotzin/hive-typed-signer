/**
 * Regression test for the undefined-key payload_root bug.
 *
 * Every primitive passes optional caller fields straight into its payload, so an
 * omitted field becomes an explicit `undefined` key. Object.keys sees it at
 * signing time, JSON.stringify drops it in transit, and the verifier then
 * recomputes payload_root over a smaller key set and reports
 * payload_root_mismatch on a receipt nobody tampered with.
 *
 * These cases deliberately supply ONLY the required fields, then round-trip the
 * envelope through JSON exactly as an HTTP client would, and require that it
 * still verifies. Before the pruneUndefined fix in src/upstream.js, the
 * forensic.credential case failed here.
 */
import { SIGNER, verifyFn } from './src/key.js';
import { signPbsManifest, signPbsAttestation, verifyPbsManifest, verifyPbsAttestation } from './src/pbs.js';
import { signPolicyMutation, signPolicyReadBinding, verifyPolicyMutation, verifyPolicyReadBinding } from './src/refusal.js';
import { signHowlerDrift, signHowlerCapability, signHowlerContamination, verifyHowlerDrift, verifyHowlerCapability, verifyHowlerContamination } from './src/howler.js';
import { signPerimeterManifest, signPerimeterAttempt, verifyPerimeterManifest, verifyPerimeterAttempt } from './src/perimeter.js';
import { signDiurnalRegime, signDiurnalAttestation, verifyDiurnalRegime, verifyDiurnalAttestation } from './src/diurnal.js';
import { signEgressManifest, signEgressMeasurement, verifyEgressManifest, verifyEgressMeasurement } from './src/egress.js';
import { signForensicCredential, signForensicAnalysis, verifyForensicCredential, verifyForensicAnalysis } from './src/forensic.js';

const PUB = SIGNER.publicKey;
let pass = 0, fail = 0;
const M = { run_id: 'r-min', tenant_id: 't-min' };

// Each entry carries only what its sign function actually demands.
const CASES = [
  ['pbs.manifest', signPbsManifest, verifyPbsManifest, { ...M,
    image_digests: ['sha256:a'], kernel_modules: ['k:1'], package_index: 'sha256:p',
    egress_acl: {}, gpu_firmware: 'sha256:f' }],
  ['pbs.attestation', signPbsAttestation, verifyPbsAttestation, { ...M,
    heartbeat_seq: 1, prior_accumulator_root: 'ab'.repeat(32), measurements: [] }],
  ['refusal.mutation', signPolicyMutation, verifyPolicyMutation, { ...M,
    policy_id: 'p1', ledger_seq: 1 }],
  ['refusal.binding', signPolicyReadBinding, verifyPolicyReadBinding, { ...M,
    envelope_id: 'e1', envelope_bounds: { min_bp: 0, max_bp: 10000 } }],
  ['howler.drift', signHowlerDrift, verifyHowlerDrift, { ...M,
    trace_tokens: ['a', 'b'], drift_score_bp: 100 }],
  ['howler.capability', signHowlerCapability, verifyHowlerCapability, { ...M,
    trace_tokens: ['a'], requested_capability_id: 'cap.x' }],
  ['howler.contamination', signHowlerContamination, verifyHowlerContamination, { ...M,
    contamination_class: 'pii' }],
  ['perimeter.manifest', signPerimeterManifest, verifyPerimeterManifest, { ...M,
    ebpf_program_hash: 'sha256:e', allowed_targets: [{ target_host: 'h', resolution: '1.1.1.1' }] }],
  ['perimeter.attempt', signPerimeterAttempt, verifyPerimeterAttempt, { ...M,
    target_host: 'h', resolution: '1.1.1.1' }],
  ['diurnal.regime', signDiurnalRegime, verifyDiurnalRegime, { ...M, regime: 'weekend' }],
  ['diurnal.attestation', signDiurnalAttestation, verifyDiurnalAttestation, { ...M,
    regime_ref: 'x', attestor_kid: 'did:a:1' }],
  ['egress.manifest', signEgressManifest, verifyEgressManifest, { ...M,
    per_class_row_caps: { c: 10 } }],
  ['egress.measurement', signEgressMeasurement, verifyEgressMeasurement, { ...M,
    per_class_rows_this_window: { c: 1 }, per_class_row_caps: { c: 10 } }],
  ['forensic.credential', signForensicCredential, verifyForensicCredential, { ...M,
    incident_case_id: 'INC-1', threshold_k: 1, consortium_signers: [{ kid: 'did:c:a' }] }],
  ['forensic.analysis', signForensicAnalysis, verifyForensicAnalysis, { ...M,
    credential_ref: 'c1', prompt_digest: 'sha256:p', output_digest: 'sha256:o' }],
];

console.log('=== minimal payloads survive a JSON round trip ===');
for (const [type, sign, verify, payload] of CASES) {
  let env;
  try { env = sign(payload, SIGNER); }
  catch (e) { fail++; console.log('  FAIL', type, 'sign threw:', e.message); continue; }

  const wire = JSON.parse(JSON.stringify(env));   // exactly what an HTTP client receives
  const r = verify(wire, verifyFn, PUB);
  if (r.ok) { pass++; console.log('  PASS', type, 'verifies after round trip'); }
  else { fail++; console.log('  FAIL', type, '->', r.reason); }

  // no undefined may survive into the signed payload
  const undef = Object.keys(env.payload).filter(k => env.payload[k] === undefined);
  if (undef.length) { fail++; console.log('  FAIL', type, 'signed payload still holds undefined keys:', undef.join(',')); }
  else pass++;

  // and the root must be stable across the round trip
  if (wire.payload_root !== env.payload_root) { fail++; console.log('  FAIL', type, 'payload_root changed in transit'); }
  else pass++;
}

console.log(`\n${'='.repeat(50)}\nRESULTS: ${pass} passed, ${fail} failed\n${'='.repeat(50)}`);
process.exit(fail ? 1 : 0);

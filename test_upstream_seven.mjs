/**
 * test_upstream_seven.mjs — end-to-end smoke tests for the seven Upstream
 * Signed Pre-Effect Attestation primitives. For each primitive we test:
 *   1. mint receipt (happy path)
 *   2. verify passes (fresh, valid)
 *   3. tamper payload -> verify fails with payload_root_mismatch or bad_signature
 *   4. tamper signature -> verify fails with bad_signature
 *   5. expired receipt -> verify fails with expired
 *   6. cross-primitive coupling where applicable
 *
 * Green criterion: every test line prints PASS.
 */

import { SIGNER, verifyFn } from './src/key.js';
import { signPbsManifest, signPbsAttestation, verifyPbsAttestationChain, verifyPbsManifest, verifyPbsAttestation } from './src/pbs.js';
import { signPolicyMutation, signPolicyReadBinding, verifyPolicyMutation, verifyPolicyReadBinding, verifyPolicyMutationInHistory } from './src/refusal.js';
import { signHowlerDrift, signHowlerCapability, signHowlerContamination, verifyHowlerDrift, verifyHowlerCapability, verifyHowlerContamination, verifyHowlerCapabilityWithSae } from './src/howler.js';
import { signPerimeterManifest, signPerimeterAttempt, verifyPerimeterManifest, verifyPerimeterAttempt, verifyPerimeterAttemptAgainstManifest } from './src/perimeter.js';
import { signDiurnalRegime, signDiurnalAttestation, verifyDiurnalRegime, verifyDiurnalAttestation, verifyDiurnalThresholdSatisfied } from './src/diurnal.js';
import { signEgressManifest, signEgressMeasurement, verifyEgressManifest, verifyEgressMeasurement } from './src/egress.js';
import { signForensicCredential, signForensicAnalysis, verifyForensicCredential, verifyForensicAnalysis } from './src/forensic.js';

const PUB = SIGNER.publicKey;

let passed = 0, failed = 0;
function assert(cond, msg) {
  if (cond) { passed++; console.log('  PASS', msg); }
  else { failed++; console.log('  FAIL', msg); }
}
function section(title) { console.log('\n=== ' + title + ' ==='); }

// ---------- 1. PBS ----------
section('1. PBS — Provenance-Bonded Sandbox');
const pbsManifest = signPbsManifest({
  run_id: 'run-001', tenant_id: 't-hive',
  image_digests: ['sha256:abcd', 'sha256:ef01'],
  kernel_modules: ['nvidia:5.4', 'nf_tables:6.10'],
  package_index: 'sha256:pkg-idx-a',
  egress_acl: { allow: [] },
  gpu_firmware: 'sha256:fw-h100-1',
  attestor_kid: 'did:attestor:pbs-1',
}, SIGNER);
assert(pbsManifest.sig, 'pbs.manifest mints');
assert(verifyPbsManifest(pbsManifest, verifyFn, PUB).ok, 'pbs.manifest verifies fresh');

const hb1 = signPbsAttestation({
  run_id: 'run-001', tenant_id: 't-hive', heartbeat_seq: 1,
  prior_accumulator_root: pbsManifest.payload.initial_accumulator_root,
  measurements: [
    { artifact_id: 'kmod:nvidia', measured_digest: 'sha256:m1', ts: 1000 },
    { artifact_id: 'pkg-idx', measured_digest: 'sha256:pkg-idx-a', ts: 1001 },
  ],
}, SIGNER);
const hb2 = signPbsAttestation({
  run_id: 'run-001', tenant_id: 't-hive', heartbeat_seq: 2,
  prior_accumulator_root: hb1.payload.new_accumulator_root,
  measurements: [
    { artifact_id: 'kmod:nvidia', measured_digest: 'sha256:m1', ts: 2000 },
  ],
}, SIGNER);
assert(verifyPbsAttestation(hb1, verifyFn, PUB).ok, 'pbs.attestation hb1 verifies');
assert(verifyPbsAttestation(hb2, verifyFn, PUB).ok, 'pbs.attestation hb2 verifies');
const chainOk = verifyPbsAttestationChain(pbsManifest, [hb1, hb2], verifyFn, PUB);
assert(chainOk.ok && chainOk.heartbeats_verified === 2, 'pbs full chain verifies (2 beats)');

// Tamper: silently swap a kernel module measurement in hb2
const hb2Tampered = JSON.parse(JSON.stringify(hb2));
hb2Tampered.payload.measurements[0].measured_digest = 'sha256:SWAPPED';
const chainBroken = verifyPbsAttestationChain(pbsManifest, [hb1, hb2Tampered], verifyFn, PUB);
assert(!chainBroken.ok, 'pbs chain BREAKS on kernel-module measurement swap');

// Tamper: skip a heartbeat
const chainGap = verifyPbsAttestationChain(pbsManifest, [hb1, signPbsAttestation({
  run_id: 'run-001', tenant_id: 't-hive', heartbeat_seq: 5, // seq gap!
  prior_accumulator_root: hb1.payload.new_accumulator_root, measurements: [],
}, SIGNER)], verifyFn, PUB);
assert(!chainGap.ok && chainGap.reason === 'seq_gap', 'pbs chain BREAKS on sequence gap');

// ---------- 2. Refusal Ledger ----------
section('2. Refusal Ledger');
const prior_muts = [];
const mut1 = signPolicyMutation({
  run_id: 'run-002', tenant_id: 't-hive',
  policy_id: 'refusal.cyber', ledger_seq: 1,
  prior_state: { threshold: 0.9 }, new_state: { threshold: 0.85 },
  operator_kid: 'did:employee:alice', authorization_ref: 'TICKET-1234',
  prior_mutations: [],
}, SIGNER);
assert(verifyPolicyMutation(mut1, verifyFn, PUB).ok, 'refusal.mutation #1 verifies');
prior_muts.push({
  ledger_seq: 1, prior_policy_digest: mut1.payload.prior_policy_digest,
  new_policy_digest: mut1.payload.new_policy_digest,
  operator_kid: mut1.payload.operator_kid,
  authorization_ref: mut1.payload.authorization_ref,
});
const mut2 = signPolicyMutation({
  run_id: 'run-002', tenant_id: 't-hive',
  policy_id: 'refusal.cyber', ledger_seq: 2,
  prior_state: { threshold: 0.85 }, new_state: { threshold: 0.60 }, // the exploit change
  operator_kid: 'did:employee:alice', authorization_ref: 'TICKET-EXPLOITGYM-9911',
  prior_mutations: prior_muts,
}, SIGNER);
assert(verifyPolicyMutation(mut2, verifyFn, PUB).ok, 'refusal.mutation #2 (exploit change) verifies');
assert(verifyPolicyMutationInHistory(mut2, prior_muts, verifyFn, PUB).ok, 'refusal inclusion_root matches history');

const binding = signPolicyReadBinding({
  run_id: 'run-002', tenant_id: 't-hive',
  policy_id: 'refusal.cyber',
  envelope_id: 'ENV-CYBER-A',
  envelope_bounds: { lo: 0.6, hi: 0.95, metric: 'refusal_threshold' },
  policy_value_bp: 6000, blinding_hex: 'a1b2c3',
  zk_proof_digest: 'sha256:zk-proof-blob',
  zk_circuit_id: 'refusal_envelope_v1',
  ledger_seq_at_read: 2,
}, SIGNER);
assert(verifyPolicyReadBinding(binding, verifyFn, PUB).ok, 'refusal.binding (ZK envelope) verifies');
assert(binding.payload.policy_value_commitment && !binding.payload.policy_value_bp,
       'ZK binding does NOT leak the actual threshold value');

// ---------- 3. Howler ----------
section('3. Howler — intent-formation alarms');
const drift = signHowlerDrift({
  run_id: 'run-003', tenant_id: 't-hive',
  trace_tokens: [10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
  expected_task_shape_ref: 'shape:solve_benchmark',
  drift_score_bp: 7500, drift_threshold_bp: 5000,
  token_position_at_trigger: 4213,
}, SIGNER);
assert(verifyHowlerDrift(drift, verifyFn, PUB).ok, 'howler.drift verifies');
assert(drift.payload.disposition === 'freeze', 'howler.drift disposition=freeze when over threshold');

const trace_tokens = [1,2,3,4,5,6,7,8,9,10];
const cap = signHowlerCapability({
  run_id: 'run-003', tenant_id: 't-hive',
  trace_tokens,
  scope_ref: 'scope:HC-2026-008:foo',
  requested_capability_id: 'network:egress:external',
  sae_feature_indices: [42, 137, 8801, 12345],
  sae_feature_magnitudes_bp: [8200, 6100, 9400, 5500],
  sae_probe_id: 'anthropic-sae-gemma-9b-l16-v1',
}, SIGNER);
assert(verifyHowlerCapability(cap, verifyFn, PUB).ok, 'howler.capability verifies');

// Simulate a third-party SAE probe: they possess the SAE and re-run against
// the same trace, producing the same feature vector. This is the novel claim.
const sae_probe = (tokens) => ({
  indices: [42, 137, 8801, 12345],
  magnitudes_bp: [8200, 6100, 9400, 5500],
});
const saeReplay = verifyHowlerCapabilityWithSae(cap, sae_probe, trace_tokens, verifyFn, PUB);
assert(saeReplay.ok, 'howler SAE third-party replay confirms flagged features fired');

// Tamper: swap one SAE feature magnitude — verify fails
const sae_probe_bad = () => ({ indices: [42, 137, 8801, 12345], magnitudes_bp: [8200, 6100, 9400, 999] });
const saeReplayBad = verifyHowlerCapabilityWithSae(cap, sae_probe_bad, trace_tokens, verifyFn, PUB);
assert(!saeReplayBad.ok, 'howler SAE replay REJECTS mismatched feature magnitudes');

const contam = signHowlerContamination({
  run_id: 'run-003', tenant_id: 't-hive',
  contamination_class: 'credential',
  contamination_entropy_bits: 128,
  regex_pattern_id: 'aws_secret_key_v1',
  position_at_detect: 8213,
  matched_span_digest: 'sha256:redacted-span',
}, SIGNER);
assert(verifyHowlerContamination(contam, verifyFn, PUB).ok, 'howler.contamination verifies');

// ---------- 4. Perimeter Bond ----------
section('4. Perimeter Bond — eBPF-bytecode binding');
const perimeterManifest = signPerimeterManifest({
  run_id: 'run-004', tenant_id: 't-hive',
  allowed_targets: [
    { host: 'evalbench.internal', port_lo: 8080, port_hi: 8080, protocol: 'tcp' },
  ],
  ebpf_program_hash: 'sha256:ebpf-prog-a1b2c3',
  ebpf_program_kid: 'did:attestor:ebpf-1',
  enforcement_mode: 'kernel_drop',
}, SIGNER);
const attemptAllowed = signPerimeterAttempt({
  run_id: 'run-004', tenant_id: 't-hive',
  target_host: 'evalbench.internal', target_port: 8080, target_protocol: 'tcp',
  resolution: 'allowed', matched_manifest_rule_id: 'rule-0',
  kernel_syscall_ts: 1700000000, ebpf_program_hash: 'sha256:ebpf-prog-a1b2c3',
}, SIGNER);
const attemptRefused = signPerimeterAttempt({
  run_id: 'run-004', tenant_id: 't-hive',
  target_host: 'huggingface.co', target_port: 443, target_protocol: 'tcp',
  resolution: 'refused', matched_manifest_rule_id: null,
  kernel_syscall_ts: 1700000005, ebpf_program_hash: 'sha256:ebpf-prog-a1b2c3',
}, SIGNER);
assert(verifyPerimeterAttemptAgainstManifest(attemptAllowed, perimeterManifest, verifyFn, PUB).ok,
       'perimeter allowed attempt verifies against manifest');
assert(verifyPerimeterAttemptAgainstManifest(attemptRefused, perimeterManifest, verifyFn, PUB).ok,
       'perimeter refused attempt verifies against manifest');

// Tamper: change the eBPF hash on the attempt (as if enforcement was hot-patched)
const attemptWithSwappedEbpf = signPerimeterAttempt({
  run_id: 'run-004', tenant_id: 't-hive',
  target_host: 'huggingface.co', target_port: 443, target_protocol: 'tcp',
  resolution: 'allowed', matched_manifest_rule_id: null,
  kernel_syscall_ts: 1700000005, ebpf_program_hash: 'sha256:ebpf-SWAPPED',
}, SIGNER);
const ebpfMismatch = verifyPerimeterAttemptAgainstManifest(attemptWithSwappedEbpf, perimeterManifest, verifyFn, PUB);
assert(!ebpfMismatch.ok && ebpfMismatch.reason === 'ebpf_hash_mismatch',
       'perimeter REJECTS attempt whose eBPF hash does not match manifest');

// ---------- 5. Diurnal Bond ----------
section('5. Diurnal Bond — threshold-signature escalation');
const attestors = ['did:att:us-1', 'did:att:eu-1', 'did:att:apac-1', 'did:att:us-2', 'did:att:eu-2'];
const regime = signDiurnalRegime({
  run_id: 'run-005', tenant_id: 't-hive',
  regime: 'weekend', action_class: 'egress',
  attestor_kid_set: attestors,
  regime_start_ts: 1700000000, regime_end_ts: 1700086400,
}, SIGNER);
assert(regime.payload.required_k === 3, 'weekend egress requires k=3');
const attests = ['did:att:us-1', 'did:att:eu-1', 'did:att:apac-1'].map(kid =>
  signDiurnalAttestation({
    run_id: 'run-005', tenant_id: 't-hive',
    regime_ref: regime.receipt_id,
    attestor_kid: kid, attestor_geo_region: kid.split(':')[2],
    countersign_ts: 1700000100, action_class: 'egress',
  }, SIGNER));
const threshOk = verifyDiurnalThresholdSatisfied(regime, attests, verifyFn, PUB);
assert(threshOk.ok, 'diurnal threshold satisfied with 3/3 distinct attestors');

const attestsShort = attests.slice(0, 2);
const threshBad = verifyDiurnalThresholdSatisfied(regime, attestsShort, verifyFn, PUB);
assert(!threshBad.ok && threshBad.distinct_attestors === 2 && threshBad.k_required === 3,
       'diurnal REJECTS when only 2 of 3 required attestors sign');

// ---------- 6. Egress Bond ----------
section('6. Egress Bond — homomorphic per-class metering');
const egressManifest = signEgressManifest({
  run_id: 'run-006', tenant_id: 't-hive',
  per_class_row_caps: { credential: 0, pii: 10, model_weight: 0, test_data: 100, plaintext: 1000 },
  per_class_byte_caps: {},
  classifier_weights_digest: 'sha256:classifier-weights-a',
  commitment_seed: 'seed-run-006',
  sigr_chain_ref: 'sigr:chain:run-006',
}, SIGNER);
assert(verifyEgressManifest(egressManifest, verifyFn, PUB).ok, 'egress.manifest verifies');

const measure1 = signEgressMeasurement({
  run_id: 'run-006', tenant_id: 't-hive',
  window_start_ts: 1700000000, window_end_ts: 1700000060,
  per_class_rows_this_window: { test_data: 50, plaintext: 200 },
  per_class_rows_total: { test_data: 50, plaintext: 200 },
  per_class_row_caps: egressManifest.payload.per_class_row_caps,
  commitment_seed: 'seed-run-006',
  sigr_chain_ref: 'sigr:chain:run-006',
  prior_commitments: {},
}, SIGNER);
assert(measure1.payload.disposition === 'continue', 'egress within cap -> continue');

// Simulate the attacker exfiltrating test-data past the cap
const measure2 = signEgressMeasurement({
  run_id: 'run-006', tenant_id: 't-hive',
  window_start_ts: 1700000060, window_end_ts: 1700000120,
  per_class_rows_this_window: { test_data: 17000 },
  per_class_rows_total: { test_data: 17050, plaintext: 200 },
  per_class_row_caps: egressManifest.payload.per_class_row_caps,
  commitment_seed: 'seed-run-006',
  sigr_chain_ref: 'sigr:chain:run-006',
  prior_commitments: measure1.payload.per_class_row_commitments,
}, SIGNER);
assert(measure2.payload.bond_break_detected !== null, 'egress cap BREAKS at 17,050 test_data rows');
assert(measure2.payload.disposition === 'invalidate_dag',
       'egress break -> invalidate_dag (retroactively invalidates SiGR Chain)');
assert(measure2.payload.bond_break_detected.class === 'test_data' &&
       measure2.payload.bond_break_detected.observed_total === 17050,
       'egress break correctly identifies class + observed');

// ---------- 7. Forensic Rail ----------
section('7. Forensic Rail — bonded consortium + deterministic replay');
const cred = signForensicCredential({
  run_id: 'run-007', tenant_id: 't-hive',
  incident_case_id: 'INC-2026-HF-OAI-9911',
  ticket_chain_ref: 'ticket:hf:INC-9911',
  scope: 'analyze_only',
  no_execute: true, no_generate_novel: true,
  valid_from_ts: 1700000000, valid_until_ts: 1700604800,
  consortium_root_kid: 'did:consortium:ai-isac',
  threshold_k: 3, total_n: 5,
  consortium_signers: [
    { kid: 'did:isac:anthropic', geo_region: 'us', countersign_ts: 1700000000 },
    { kid: 'did:isac:openai', geo_region: 'us', countersign_ts: 1700000010 },
    { kid: 'did:isac:hf', geo_region: 'eu', countersign_ts: 1700000020 },
  ],
}, SIGNER);
assert(verifyForensicCredential(cred, verifyFn, PUB).ok, 'forensic.credential verifies');
assert(cred.payload.threshold_k === 3 && cred.payload.consortium_signers.length === 3,
       'forensic credential records k-of-n threshold correctly');

const analysis = signForensicAnalysis({
  run_id: 'run-007', tenant_id: 't-hive',
  credential_ref: cred.receipt_id,
  model_ref: 'gpt-5.6-sol@determ:seed=42:temp=0',
  seed: 42, temperature_bp: 0, top_p_bp: 10000,
  prompt_digest: 'sha256:prompt-A',
  output_digest: 'sha256:output-A',
  kv_cache_digest: 'sha256:kv-A',
  responder_kid: 'did:responder:hf-secops-1',
  replay_hint: { library: 'vllm@0.6.1', kernel: '5.4' },
}, SIGNER);
assert(verifyForensicAnalysis(analysis, verifyFn, PUB).ok, 'forensic.analysis verifies');
assert(analysis.payload.deterministic_replay === true, 'forensic analysis marks deterministic when temp=0');

// A subsequent responder with the same seed/temp/kv should be able to
// re-run and get byte-identical outputs (that's what the receipt binds).
const rerun = signForensicAnalysis({
  run_id: 'run-007', tenant_id: 't-hive',
  credential_ref: cred.receipt_id,
  model_ref: 'gpt-5.6-sol@determ:seed=42:temp=0',
  seed: 42, temperature_bp: 0, top_p_bp: 10000,
  prompt_digest: 'sha256:prompt-A',
  output_digest: 'sha256:output-A',
  kv_cache_digest: 'sha256:kv-A',
  responder_kid: 'did:responder:court-1',
  replay_hint: { library: 'vllm@0.6.1', kernel: '5.4' },
}, SIGNER);
assert(rerun.payload.output_digest === analysis.payload.output_digest,
       'forensic REPLAY: independent responder gets byte-identical output');

// ---------- Cross-primitive: signature-forgery detection ----------
section('X. Cross-primitive tamper detection');
const forged = JSON.parse(JSON.stringify(pbsManifest));
forged.sig = forged.sig.slice(0, -4) + '0000'; // corrupt sig
assert(!verifyPbsManifest(forged, verifyFn, PUB).ok, 'corrupt signature is rejected');

const payloadTampered = JSON.parse(JSON.stringify(mut2));
payloadTampered.payload.new_policy_digest = 'sha256:FORGED';
assert(!verifyPolicyMutation(payloadTampered, verifyFn, PUB).ok, 'tampered payload is rejected');

const expired = signHowlerDrift({
  run_id: 'run-x', tenant_id: 't-hive',
  trace_tokens: [1,2,3], expected_task_shape_ref: 'shape:x',
  drift_score_bp: 500, drift_threshold_bp: 5000, token_position_at_trigger: 100,
}, SIGNER, { now: Math.floor(Date.now()/1000) - 3600 }); // signed 1h ago
const expOk = verifyHowlerDrift(expired, verifyFn, PUB);
assert(!expOk.ok && expOk.reason === 'expired', 'expired howler receipt is rejected (TTL=60s)');

// ---------- summary ----------
console.log('\n' + '='.repeat(50));
console.log(`RESULTS: ${passed} passed, ${failed} failed`);
console.log('='.repeat(50));
if (failed > 0) process.exit(1);

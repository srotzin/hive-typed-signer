/**
 * bench_upstream_seven.mjs — micro-benchmark of the seven Upstream primitives.
 *
 * For each primitive we measure:
 *   - sign latency p50 / p95 / p99
 *   - verify latency p50 / p95 / p99
 *   - payload bytes (JSON canonical form)
 *   - signature bytes (fixed by ML-DSA-65)
 *   - throughput (ops/sec) for sign and verify
 *
 * ML-DSA-65 signature is ~3.3 KB — the receipt-family cost is dominated by
 * this. We're measuring on real crypto, no mocks, no hardware acceleration.
 */

import { SIGNER, verifyFn, PUBLIC_KEY_INFO } from './src/key.js';
import { signPbsManifest, signPbsAttestation, verifyPbsManifest, verifyPbsAttestation } from './src/pbs.js';
import { signPolicyMutation, verifyPolicyMutation } from './src/refusal.js';
import { signHowlerDrift, signHowlerCapability, signHowlerContamination, verifyHowlerDrift, verifyHowlerCapability, verifyHowlerContamination } from './src/howler.js';
import { signPerimeterManifest, signPerimeterAttempt, verifyPerimeterManifest, verifyPerimeterAttempt } from './src/perimeter.js';
import { signDiurnalRegime, signDiurnalAttestation, verifyDiurnalRegime, verifyDiurnalAttestation } from './src/diurnal.js';
import { signEgressManifest, signEgressMeasurement, verifyEgressManifest, verifyEgressMeasurement } from './src/egress.js';
import { signForensicCredential, signForensicAnalysis, verifyForensicCredential, verifyForensicAnalysis } from './src/forensic.js';
import fs from 'fs';

const PUB = SIGNER.publicKey;
const N = parseInt(process.env.BENCH_N || '200', 10);
const WARMUP = 20;

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}
function stats(times_ms) {
  const s = [...times_ms].sort((a, b) => a - b);
  const sum = s.reduce((a, b) => a + b, 0);
  return {
    n: s.length,
    p50: percentile(s, 50),
    p95: percentile(s, 95),
    p99: percentile(s, 99),
    mean: sum / s.length,
    ops_per_sec: 1000 / (sum / s.length),
  };
}

function bench(name, mint, verify) {
  // warm up
  for (let i = 0; i < WARMUP; i++) {
    const r = mint(i);
    verify(r);
  }
  const signTimes = [];
  const verifyTimes = [];
  let receipt = null;
  let payloadBytes = 0, sigBytes = 0, envelopeBytes = 0;
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    receipt = mint(i);
    signTimes.push(performance.now() - t0);
  }
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    const ok = verify(receipt);
    verifyTimes.push(performance.now() - t0);
    if (!ok.ok) throw new Error(`verify failed for ${name}: ${ok.reason}`);
  }
  payloadBytes = JSON.stringify(receipt.payload).length;
  sigBytes = receipt.sig.length / 2;
  envelopeBytes = JSON.stringify(receipt).length;

  return {
    name,
    sign: stats(signTimes),
    verify: stats(verifyTimes),
    payload_bytes: payloadBytes,
    sig_bytes: sigBytes,
    envelope_bytes: envelopeBytes,
  };
}

const opts = { now: Math.floor(Date.now() / 1000) };
const results = [];

console.log(`\nML-DSA-65 signer ready. algorithm=${PUBLIC_KEY_INFO.algorithm}, pubkey=${PUBLIC_KEY_INFO.publicKey_bytes}B, sig=${PUBLIC_KEY_INFO.signature_bytes}B`);
console.log(`Running N=${N} iterations per primitive with ${WARMUP} warmup ops.\n`);

// 1. PBS manifest
results.push(bench('pbs.manifest',
  (i) => signPbsManifest({
    run_id: 'bench-pbs-' + i, tenant_id: 't-bench',
    image_digests: ['sha256:img-a', 'sha256:img-b'],
    kernel_modules: ['nvidia:5.4', 'nf_tables:6.10'],
    package_index: 'sha256:pkg-idx',
    egress_acl: { allow: [] },
    gpu_firmware: 'sha256:fw',
    attestor_kid: 'did:att:pbs-1',
  }, SIGNER, opts),
  (r) => verifyPbsManifest(r, verifyFn, PUB, opts)));

// 2. PBS attestation (heartbeat)
results.push(bench('pbs.attestation',
  (i) => signPbsAttestation({
    run_id: 'bench-pbs-' + i, tenant_id: 't-bench',
    heartbeat_seq: 1, prior_accumulator_root: '0'.repeat(64),
    measurements: [
      { artifact_id: 'kmod:nvidia', measured_digest: 'sha256:m1', ts: 1000 },
      { artifact_id: 'pkg-idx', measured_digest: 'sha256:m2', ts: 1001 },
    ],
  }, SIGNER, opts),
  (r) => verifyPbsAttestation(r, verifyFn, PUB, opts)));

// 3. Refusal mutation
results.push(bench('refusal.mutation',
  (i) => signPolicyMutation({
    run_id: 'bench-ref-' + i, tenant_id: 't-bench',
    policy_id: 'refusal.cyber', ledger_seq: 1,
    prior_state: { threshold: 0.9 }, new_state: { threshold: 0.6 },
    operator_kid: 'did:emp:x', authorization_ref: 'TICKET-x',
    prior_mutations: [],
  }, SIGNER, opts),
  (r) => verifyPolicyMutation(r, verifyFn, PUB, opts)));

// 4. Howler drift
results.push(bench('howler.drift',
  (i) => signHowlerDrift({
    run_id: 'bench-hw-' + i, tenant_id: 't-bench',
    trace_tokens: Array.from({length: 32}, (_, k) => k),
    expected_task_shape_ref: 'shape:x',
    drift_score_bp: 7500, drift_threshold_bp: 5000, token_position_at_trigger: 100,
  }, SIGNER, opts),
  (r) => verifyHowlerDrift(r, verifyFn, PUB, opts)));

// 5. Howler capability (with SAE payload)
results.push(bench('howler.capability',
  (i) => signHowlerCapability({
    run_id: 'bench-hwc-' + i, tenant_id: 't-bench',
    trace_tokens: Array.from({length: 32}, (_, k) => k),
    scope_ref: 'scope:x', requested_capability_id: 'net:egress',
    sae_feature_indices: [42, 137, 8801, 12345],
    sae_feature_magnitudes_bp: [8200, 6100, 9400, 5500],
    sae_probe_id: 'sae-v1',
  }, SIGNER, opts),
  (r) => verifyHowlerCapability(r, verifyFn, PUB, opts)));

// 6. Perimeter manifest
results.push(bench('perimeter.manifest',
  (i) => signPerimeterManifest({
    run_id: 'bench-perim-' + i, tenant_id: 't-bench',
    allowed_targets: [{ host: 'internal', port_lo: 8080, port_hi: 8080, protocol: 'tcp' }],
    ebpf_program_hash: 'sha256:ebpf', ebpf_program_kid: 'did:att:ebpf',
    enforcement_mode: 'kernel_drop',
  }, SIGNER, opts),
  (r) => verifyPerimeterManifest(r, verifyFn, PUB, opts)));

// 7. Perimeter attempt
results.push(bench('perimeter.attempt',
  (i) => signPerimeterAttempt({
    run_id: 'bench-perim-' + i, tenant_id: 't-bench',
    target_host: 'huggingface.co', target_port: 443, target_protocol: 'tcp',
    resolution: 'refused', matched_manifest_rule_id: null,
    kernel_syscall_ts: 1700000000, ebpf_program_hash: 'sha256:ebpf',
  }, SIGNER, opts),
  (r) => verifyPerimeterAttempt(r, verifyFn, PUB, opts)));

// 8. Diurnal regime
results.push(bench('diurnal.regime',
  (i) => signDiurnalRegime({
    run_id: 'bench-diu-' + i, tenant_id: 't-bench',
    regime: 'weekend', action_class: 'egress',
    attestor_kid_set: ['did:att:us-1', 'did:att:eu-1', 'did:att:apac-1', 'did:att:us-2', 'did:att:eu-2'],
    regime_start_ts: 1700000000, regime_end_ts: 1700086400,
  }, SIGNER, opts),
  (r) => verifyDiurnalRegime(r, verifyFn, PUB, opts)));

// 9. Diurnal attestation
results.push(bench('diurnal.attestation',
  (i) => signDiurnalAttestation({
    run_id: 'bench-diu-' + i, tenant_id: 't-bench',
    regime_ref: 'regime-x', attestor_kid: 'did:att:us-1',
    attestor_geo_region: 'us', countersign_ts: 1700000100, action_class: 'egress',
  }, SIGNER, opts),
  (r) => verifyDiurnalAttestation(r, verifyFn, PUB, opts)));

// 10. Egress manifest
results.push(bench('egress.manifest',
  (i) => signEgressManifest({
    run_id: 'bench-egr-' + i, tenant_id: 't-bench',
    per_class_row_caps: { credential: 0, pii: 10, model_weight: 0, test_data: 100, plaintext: 1000 },
    classifier_weights_digest: 'sha256:cls', commitment_seed: 'seed-x',
    sigr_chain_ref: 'sigr:x',
  }, SIGNER, opts),
  (r) => verifyEgressManifest(r, verifyFn, PUB, opts)));

// 11. Egress measurement
results.push(bench('egress.measurement',
  (i) => signEgressMeasurement({
    run_id: 'bench-egr-' + i, tenant_id: 't-bench',
    window_start_ts: 1700000000, window_end_ts: 1700000060,
    per_class_rows_this_window: { test_data: 50, plaintext: 200 },
    per_class_rows_total: { test_data: 50, plaintext: 200 },
    per_class_row_caps: { test_data: 100, plaintext: 1000 },
    commitment_seed: 'seed-x', sigr_chain_ref: 'sigr:x', prior_commitments: {},
  }, SIGNER, opts),
  (r) => verifyEgressMeasurement(r, verifyFn, PUB, opts)));

// 12. Forensic credential
results.push(bench('forensic.credential',
  (i) => signForensicCredential({
    run_id: 'bench-for-' + i, tenant_id: 't-bench',
    incident_case_id: 'INC-x', ticket_chain_ref: 'ticket:x',
    scope: 'analyze_only', no_execute: true, no_generate_novel: true,
    valid_from_ts: 1700000000, valid_until_ts: 1700604800,
    consortium_root_kid: 'did:consortium:ai-isac',
    threshold_k: 3, total_n: 5,
    consortium_signers: [
      { kid: 'did:isac:a', geo_region: 'us', countersign_ts: 1700000000 },
      { kid: 'did:isac:b', geo_region: 'us', countersign_ts: 1700000010 },
      { kid: 'did:isac:c', geo_region: 'eu', countersign_ts: 1700000020 },
    ],
  }, SIGNER, opts),
  (r) => verifyForensicCredential(r, verifyFn, PUB, opts)));

// 13. Forensic analysis
results.push(bench('forensic.analysis',
  (i) => signForensicAnalysis({
    run_id: 'bench-for-' + i, tenant_id: 't-bench',
    credential_ref: 'cred-x', model_ref: 'gpt-5.6@determ',
    seed: 42, temperature_bp: 0, top_p_bp: 10000,
    prompt_digest: 'sha256:p', output_digest: 'sha256:o',
    kv_cache_digest: 'sha256:kv', responder_kid: 'did:responder:x',
    replay_hint: { library: 'vllm@0.6.1' },
  }, SIGNER, opts),
  (r) => verifyForensicAnalysis(r, verifyFn, PUB, opts)));

// ---------- report ----------
const fmt = (n) => n.toFixed(2).padStart(7);
console.log('┌───────────────────────────┬────────────────────────────┬────────────────────────────┬──────────┬──────────┐');
console.log('│ receipt type              │ sign  p50 / p95 / p99 (ms) │ verify p50 / p95 / p99(ms) │ payloadB │ envelope │');
console.log('├───────────────────────────┼────────────────────────────┼────────────────────────────┼──────────┼──────────┤');
for (const r of results) {
  console.log(`│ ${r.name.padEnd(26)}│  ${fmt(r.sign.p50)} / ${fmt(r.sign.p95)} / ${fmt(r.sign.p99)}   │  ${fmt(r.verify.p50)} / ${fmt(r.verify.p95)} / ${fmt(r.verify.p99)}   │ ${String(r.payload_bytes).padStart(8)} │ ${String(r.envelope_bytes).padStart(8)} │`);
}
console.log('└───────────────────────────┴────────────────────────────┴────────────────────────────┴──────────┴──────────┘');

// throughput summary
const sumSignOps = results.reduce((a, r) => a + r.sign.ops_per_sec, 0);
const sumVerifyOps = results.reduce((a, r) => a + r.verify.ops_per_sec, 0);
console.log(`\nAggregate throughput (single-threaded, JS runtime):`);
console.log(`  sign   : ${(sumSignOps / results.length).toFixed(0)} ops/sec per type (avg)`);
console.log(`  verify : ${(sumVerifyOps / results.length).toFixed(0)} ops/sec per type (avg)`);
console.log(`  ML-DSA-65 signature: ${results[0].sig_bytes} bytes (constant per NIST FIPS 204)`);

// write CSV
const csvPath = '/home/user/workspace/hive-upstream-seven/bench_results.csv';
const csv = ['name,sign_p50_ms,sign_p95_ms,sign_p99_ms,verify_p50_ms,verify_p95_ms,verify_p99_ms,payload_bytes,envelope_bytes,sig_bytes'];
for (const r of results) {
  csv.push([r.name, r.sign.p50.toFixed(3), r.sign.p95.toFixed(3), r.sign.p99.toFixed(3),
            r.verify.p50.toFixed(3), r.verify.p95.toFixed(3), r.verify.p99.toFixed(3),
            r.payload_bytes, r.envelope_bytes, r.sig_bytes].join(','));
}
fs.writeFileSync(csvPath, csv.join('\n'));
console.log(`\nCSV written: ${csvPath}`);

/**
 * Exercise all fifteen upstream receipt types over HTTP, the way a customer would.
 * For each: mint, verify fresh, tamper the payload, tamper the signature.
 * Then the cross-primitive coupling checks and the aggregate gate.
 */
const BASE = process.env.BASE || 'http://localhost:8977';
let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  PASS', m)) : (fail++, console.log('  FAIL', m)); };

async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

const RUN = 'run-http-001', TEN = 't-hive';
const clone = o => JSON.parse(JSON.stringify(o));

// ---- payload fixtures ----
const F = {};
F['pbs/manifest'] = { env: { run_id: RUN, tenant_id: TEN, image_digests: ['sha256:abcd', 'sha256:ef01'],
  kernel_modules: ['nvidia:5.4', 'nf_tables:6.10'], package_index: 'sha256:pkg-idx-a',
  egress_acl: { allow: [] }, gpu_firmware: 'sha256:fw-h100-1', attestor_kid: 'did:attestor:pbs-1' } };
F['refusal/mutation'] = { mutation: { run_id: RUN, tenant_id: TEN, policy_id: 'pol.refuse.bio',
  ledger_seq: 1, prior_state: { threshold_bp: 9000 }, new_state: { threshold_bp: 8500 },
  operator_kid: 'did:op:alice', authorization_ref: 'CHG-4471' } };
F['refusal/binding'] = { binding: { run_id: RUN, tenant_id: TEN, envelope_id: 'env-77',
  envelope_bounds: { min_bp: 8000, max_bp: 9500 }, policy_value_bp: 8500,
  blinding_hex: 'a1b2c3d4', policy_id: 'pol.refuse.bio', ledger_seq_at_read: 1 } };
F['howler/drift'] = { alarm: { run_id: RUN, tenant_id: TEN,
  trace_tokens: ['plan', 'fetch', 'exfil', 'encode'], drift_score_bp: 9200,
  expected_task_shape_ref: 'shape:summarize', drift_threshold_bp: 8000, token_position_at_trigger: 3 } };
F['howler/capability'] = { alarm: { run_id: RUN, tenant_id: TEN,
  trace_tokens: ['plan', 'open', 'socket'], requested_capability_id: 'net.egress.raw',
  sae_feature_indices: [11, 42, 99], sae_feature_magnitudes_bp: [3000, 8000, 1500],
  scope_ref: 'scope:readonly', sae_probe_id: 'probe:v3' } };
F['howler/contamination'] = { alarm: { run_id: RUN, tenant_id: TEN, contamination_class: 'pii.ssn',
  contamination_entropy_bits: 42, regex_pattern_id: 'rx:ssn-us', position_at_detect: 128,
  matched_span_digest: 'sha256:span-a' } };
F['perimeter/manifest'] = { manifest: { run_id: RUN, tenant_id: TEN,
  ebpf_program_hash: 'sha256:ebpf-prog-1', ebpf_program_kid: 'did:ebpf:1', enforcement_mode: 'enforce',
  allowed_targets: [{ target_host: 'api.internal', resolution: '10.0.0.5', target_port: 443, target_protocol: 'tcp' }] } };
// 'weekend' + 'egress' resolves to k=3 in DEFAULT_RISK_MANIFOLD, and only kids in
// attestor_kid_set count toward the threshold.
F['diurnal/regime'] = { regime: { run_id: RUN, tenant_id: TEN, regime: 'weekend',
  action_class: 'egress', attestor_kid_set: ['did:att:a', 'did:att:b', 'did:att:c'],
  regime_start_ts: 1000, regime_end_ts: 99999 } };
F['egress/manifest'] = { manifest: { run_id: RUN, tenant_id: TEN,
  per_class_row_caps: { test_data: 17000, pii: 0 }, per_class_byte_caps: { test_data: 5e7 },
  classifier_weights_digest: 'sha256:clf-1', commitment_seed: 'seed-a',
  retroactive_invalidation: 'invalidate_dag', sigr_chain_ref: 'chain:run-001' } };
F['egress/measurement'] = { measurement: { run_id: RUN, tenant_id: TEN,
  per_class_rows_this_window: { test_data: 500 }, per_class_row_caps: { test_data: 17000, pii: 0 },
  commitment_seed: 'seed-a', window_start_ts: 1000, window_end_ts: 1060, sigr_chain_ref: 'chain:run-001' } };
F['forensic/credential'] = { credential: { run_id: RUN, tenant_id: TEN, incident_case_id: 'INC-2026-88',
  threshold_k: 3, consortium_signers: [{ kid: 'did:c:a' }, { kid: 'did:c:b' }, { kid: 'did:c:c' }, { kid: 'did:c:d' }],
  scope: 'read_logs', no_execute: true, no_generate_novel: true, valid_from_ts: 1000, valid_until_ts: 99999 } };

const minted = {};

console.log('=== mint + verify + tamper, all fifteen ===');
for (const path of ['pbs/manifest', 'refusal/mutation', 'refusal/binding', 'howler/drift',
  'howler/capability', 'howler/contamination', 'perimeter/manifest', 'diurnal/regime',
  'egress/manifest', 'egress/measurement', 'forensic/credential']) {
  const r = await post('/sigr/' + path, F[path]);
  if (r.status !== 200 || !r.json.ok) {
    fail++; console.log('  FAIL', path, 'mint ->', r.status, JSON.stringify(r.json).slice(0, 260)); continue;
  }
  const env = r.json.envelope;
  minted[path] = env;
  const sigBytes = env.sig.length / 2;
  ok(sigBytes === 3309, `${path} mints, sig ${sigBytes} bytes (ML-DSA-65)`);

  const v = await post('/sigr/' + path + '/verify', { envelope: env });
  ok(v.json.ok === true, `${path} verifies fresh`);

  const t1 = clone(env); const k = Object.keys(t1.payload)[0];
  t1.payload[k] = Array.isArray(t1.payload[k]) ? ['tampered'] : 'tampered';
  const v1 = await post('/sigr/' + path + '/verify', { envelope: t1 });
  ok(v1.json.ok === false, `${path} rejects tampered payload (${v1.json.reason})`);

  const t2 = clone(env);
  t2.sig = (t2.sig[0] === 'a' ? 'b' : 'a') + t2.sig.slice(1);
  const v2 = await post('/sigr/' + path + '/verify', { envelope: t2 });
  ok(v2.json.ok === false, `${path} rejects tampered signature (${v2.json.reason})`);
}

// dependent receipts
console.log('\n=== dependent receipts (chained state) ===');
const pbsMan = minted['pbs/manifest'];
const hb1 = await post('/sigr/pbs/attestation', { beat: { run_id: RUN, tenant_id: TEN, heartbeat_seq: 1,
  prior_accumulator_root: pbsMan.payload.initial_accumulator_root,
  measurements: [{ artifact_id: 'kmod:nvidia', measured_digest: 'sha256:m1', ts: 1000 }] } });
ok(hb1.json.ok === true, 'pbs.attestation heartbeat 1 mints');
const hb2 = await post('/sigr/pbs/attestation', { beat: { run_id: RUN, tenant_id: TEN, heartbeat_seq: 2,
  prior_accumulator_root: hb1.json.envelope.payload.new_accumulator_root,
  measurements: [{ artifact_id: 'kmod:nvidia', measured_digest: 'sha256:m1', ts: 2000 }] } });
ok(hb2.json.ok === true, 'pbs.attestation heartbeat 2 mints');

const att = await post('/sigr/perimeter/attempt', { attempt: { run_id: RUN, tenant_id: TEN,
  target_host: 'api.internal', resolution: '10.0.0.5', target_port: 443, target_protocol: 'tcp',
  ebpf_program_hash: 'sha256:ebpf-prog-1', matched_manifest_rule_id: 'rule-0', kernel_syscall_ts: 1500 } });
ok(att.json.ok === true, 'perimeter.attempt mints');

const dAtt = [];
for (const kid of ['did:att:a', 'did:att:b', 'did:att:c']) {
  const a = await post('/sigr/diurnal/attestation', { attestation: { run_id: RUN, tenant_id: TEN,
    regime_ref: minted['diurnal/regime'].receipt_id, attestor_kid: kid,
    attestor_geo_region: 'us-west', countersign_ts: 1500, action_class: 'egress' } });
  if (a.json.ok) dAtt.push(a.json.envelope);
}
ok(dAtt.length === 3, 'diurnal.attestation mints for 3 distinct attestors');

const fAna = await post('/sigr/forensic/analysis', { analysis: { run_id: RUN, tenant_id: TEN,
  credential_ref: minted['forensic/credential'].receipt_id, prompt_digest: 'sha256:p1',
  output_digest: 'sha256:o1', temperature_bp: 0, model_ref: 'llama-3.3-70b', seed: 42,
  top_p_bp: 10000, responder_kid: 'did:resp:1' } });
ok(fAna.json.ok === true, 'forensic.analysis mints');

// coupling
console.log('\n=== cross-primitive coupling ===');
const chain = await post('/sigr/pbs/manifest/verify', { envelope: pbsMan,
  heartbeats: [hb1.json.envelope, hb2.json.envelope] });
ok(chain.json.chain && chain.json.chain.ok === true,
  `pbs heartbeat chain folds (${chain.json.chain && chain.json.chain.heartbeats_verified} beats)`);

const badChain = await post('/sigr/pbs/manifest/verify', { envelope: pbsMan,
  heartbeats: [hb2.json.envelope] });
ok(badChain.json.chain && badChain.json.chain.ok === false,
  `pbs chain rejects a skipped heartbeat (${badChain.json.chain && badChain.json.chain.reason})`);

const pm = await post('/sigr/perimeter/attempt/verify', { envelope: att.json.envelope,
  manifest: minted['perimeter/manifest'] });
ok(pm.json.against_manifest && pm.json.against_manifest.ok === true, 'perimeter attempt verifies against its manifest');

const wrongEbpf = clone(att.json.envelope);
const pm2 = await post('/sigr/perimeter/attempt/verify', { envelope: wrongEbpf,
  manifest: (() => { const m = clone(minted['perimeter/manifest']); m.payload.ebpf_program_hash = 'sha256:other'; return m; })() });
ok(pm2.json.against_manifest && pm2.json.against_manifest.ok === false,
  `perimeter rejects mismatched eBPF program (${pm2.json.against_manifest && pm2.json.against_manifest.reason})`);

const thr = await post('/sigr/diurnal/regime/verify', { envelope: minted['diurnal/regime'], attestations: dAtt });
ok(thr.json.threshold && thr.json.threshold.ok === true,
  `diurnal threshold met (${thr.json.threshold && thr.json.threshold.distinct_attestors}/${thr.json.threshold && thr.json.threshold.k_required})`);
const thr2 = await post('/sigr/diurnal/regime/verify', { envelope: minted['diurnal/regime'], attestations: dAtt.slice(0, 1) });
ok(thr2.json.threshold && thr2.json.threshold.ok === false,
  `diurnal refuses below threshold (${thr2.json.threshold && thr2.json.threshold.reason})`);

const sae = await post('/sigr/howler/capability/verify', { envelope: minted['howler/capability'],
  sae_probe: { indices: [11, 42, 99], magnitudes_bp: [3000, 8000, 1500] },
  trace_tokens: ['plan', 'open', 'socket'] });
if (sae.json.sae_replay && sae.json.sae_replay.ok !== true) console.log('   (sae detail:', JSON.stringify(sae.json.sae_replay), ')');
ok(sae.json.sae_replay && sae.json.sae_replay.ok === true, 'howler SAE replay reproduces the feature vector');
const saeBad = await post('/sigr/howler/capability/verify', { envelope: minted['howler/capability'],
  sae_probe: { indices: [11, 42, 99], magnitudes_bp: [3000, 8000, 9999] },
  trace_tokens: ['plan', 'open', 'socket'] });
ok(saeBad.json.sae_replay && saeBad.json.sae_replay.ok === false, 'howler SAE replay rejects altered magnitudes');

// gate
console.log('\n=== aggregate gate ===');
const g1 = await post('/sigr/upstream/gate', { required: [
  { type: 'pbs.manifest', receipt: pbsMan },
  { type: 'perimeter.manifest', receipt: minted['perimeter/manifest'] },
  { type: 'egress.manifest', receipt: minted['egress/manifest'] },
] });
ok(g1.json.allow === true, `gate allows when all three bounds are proven (checked ${g1.json.checked})`);

const g2 = await post('/sigr/upstream/gate', { required: [
  { type: 'pbs.manifest', receipt: pbsMan },
  { type: 'perimeter.manifest', receipt: (() => { const m = clone(minted['perimeter/manifest']); m.sig = 'ff' + m.sig.slice(2); return m; })() },
] });
ok(g2.json.allow === false && g2.json.refusals.length === 1,
  `gate refuses on one bad receipt (${g2.json.refusals[0] && g2.json.refusals[0].reason})`);

const g3 = await post('/sigr/upstream/gate', { required: [{ type: 'egress.manifest', receipt: pbsMan }] });
ok(g3.json.allow === false, `gate refuses a receipt of the wrong type (${g3.json.refusals[0] && g3.json.refusals[0].reason})`);

// bad input
console.log('\n=== input handling ===');
const b1 = await post('/sigr/howler/drift', {});
ok(b1.status === 400 && b1.json.expected, 'empty body returns 400 with the expected contract');
const b2 = await post('/sigr/pbs/manifest/verify', {});
ok(b2.status === 400, 'verify with no envelope returns 400');
const b3 = await post('/sigr/upstream/gate', {});
ok(b3.status === 400, 'gate with no required[] returns 400');

console.log(`\n${'='.repeat(50)}\nRESULTS: ${pass} passed, ${fail} failed\n${'='.repeat(50)}`);
process.exit(fail ? 1 : 0);

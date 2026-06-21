// AFiR-S3 HTTP smoke test — exercises every new live route end-to-end.
// Run against an already-booted server (PORT env or 3939). Writes JSON summary to stdout.
const BASE = `http://127.0.0.1:${process.env.SMOKE_PORT || 3939}`;
const results = [];
function rec(name, pass, detail) { results.push({ name, pass, detail }); }
async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  let j; try { j = await r.json(); } catch { j = null; }
  return { status: r.status, body: j };
}
const SHA64 = (c) => c.repeat(64);

(async () => {
  // 1) TOOL-SCOPE sign + verify
  const scope = {
    scope_id: 'scope-1', agent_ref: 'agent-x',
    tools: [
      { tool_id: 'read_project', tool_hash: SHA64('a') },
      { tool_id: 'delete_project', tool_hash: SHA64('b') },
      { tool_id: 'transfer_funds', tool_hash: SHA64('c') },
    ],
    destructive_tools: ['delete_project', 'transfer_funds'],
    granted_by: 'policy:root',
  };
  const ts = await post('/sigr/toolscope', { scope });
  rec('toolscope sign 200+ok+sig', ts.status === 200 && ts.body?.ok && (ts.body.envelope?.envelope_signature?.length || 0) > 3000,
      `status=${ts.status} ok=${ts.body?.ok} siglen=${ts.body?.envelope?.envelope_signature?.length}`);
  const scopeEnv = ts.body?.envelope;

  const tsv = await post('/sigr/toolscope/verify', { envelope: scopeEnv });
  rec('toolscope verify valid', tsv.status === 200 && tsv.body?.valid === true, `valid=${tsv.body?.valid} reasons=${(tsv.body?.reasons||[]).join('|')}`);

  // toolscope sign-gate: destructive tool not in tools list -> 500 (sign error)
  const tsBad = await post('/sigr/toolscope', { scope: { ...scope, destructive_tools: ['ghost_tool'] } });
  rec('toolscope rejects ghost destructive', tsBad.status >= 400 && tsBad.body?.ok !== true, `status=${tsBad.status}`);

  // 2) AGENTIC sign + verify (in-scope)
  const run = {
    run_id: 'arun-1', agent_ref: 'agent-x',
    steps: [
      { step_id: 's1', kind: 'plan', seq: 0, parents: [], input: { goal: 'cleanup' }, output: { plan: ['read', 'delete'] } },
      { step_id: 's2', kind: 'tool_call', seq: 1, parents: ['s1'], input: { id: 'P1' }, action: 'read_project', tool_target: 'P1', tool_hash: SHA64('a'), scope_ref: 'sigr:scope-1' },
      { step_id: 's3', kind: 'tool_call', seq: 2, parents: ['s2'], input: { id: 'P1' }, action: 'delete_project', tool_target: 'P1', tool_hash: SHA64('b'), scope_ref: 'sigr:scope-1' },
      { step_id: 's4', kind: 'final', seq: 3, parents: ['s3'], input: {}, output: { done: true } },
    ],
  };
  const ag = await post('/sigr/agentic', { run, scopes: [scopeEnv] });
  rec('agentic sign 200+ok', ag.status === 200 && ag.body?.ok && (ag.body.envelope?.envelope_signature?.length||0) > 3000, `status=${ag.status} ok=${ag.body?.ok}`);
  const agEnv = ag.body?.envelope;
  const agv = await post('/sigr/agentic/verify', { envelope: agEnv, scopes: [scopeEnv] });
  rec('agentic verify valid', agv.status === 200 && agv.body?.valid === true, `valid=${agv.body?.valid} reasons=${(agv.body?.reasons||[]).join('|')}`);
  rec('agentic ARSC tiers (s3 rise, s2 sink)', agEnv?.agentic_actions?.s3?.meta?.arsc_tier === 'rise' && agEnv?.agentic_actions?.s2?.meta?.arsc_tier === 'sink',
      `s3=${agEnv?.agentic_actions?.s3?.meta?.arsc_tier} s2=${agEnv?.agentic_actions?.s2?.meta?.arsc_tier}`);

  // agentic sign-gate: out-of-scope action -> 400
  const runBad = JSON.parse(JSON.stringify(run));
  runBad.steps[2].action = 'wipe_everything'; runBad.steps[2].tool_hash = SHA64('9');
  const agBad = await post('/sigr/agentic', { run: runBad, scopes: [scopeEnv] });
  rec('agentic rejects out-of-scope (400)', agBad.status === 400 && agBad.body?.ok !== true, `status=${agBad.status} msg=${agBad.body?.message}`);

  // 3) CERN sign + verify (append lossless)
  const CTX0 = [{ id: 1, t: 'user asked for refund of $500' }, { id: 2, t: 'policy: refunds <= $100 auto' }, { id: 3, t: 'order total $500' }];
  const after = [...CTX0, { id: 4, t: 'agent note: escalate' }];
  const cern = await post('/sigr/cern', { mutation: { run_id: 'r1', step: 1, mutation_type: 'append', context_before: CTX0, context_after: after, integrity_claim: 'lossless' } });
  rec('cern sign 200+ok', cern.status === 200 && cern.body?.ok && (cern.body.envelope?.envelope_signature?.length||0) > 3000, `status=${cern.status} ok=${cern.body?.ok}`);
  const cernEnv = cern.body?.envelope;
  const cernv = await post('/sigr/cern/verify', { envelope: cernEnv });
  rec('cern verify valid', cernv.status === 200 && cernv.body?.valid === true, `valid=${cernv.body?.valid} reasons=${(cernv.body?.reasons||[]).join('|')}`);

  // cern sign-gate: silent alteration (claim lossless but content altered, undisclosed) -> 400
  const alteredAfter = [{ id: 1, t: 'user asked for refund of $50' }, CTX0[1], CTX0[2]];
  const cernBad = await post('/sigr/cern', { mutation: { run_id: 'r1', step: 9, mutation_type: 'append', context_before: CTX0, context_after: alteredAfter, integrity_claim: 'lossless' } });
  rec('cern rejects silent alteration (400)', cernBad.status === 400 && cernBad.body?.ok !== true, `status=${cernBad.status} msg=${cernBad.body?.message}`);

  // 4) REWARD sign + verify
  const rw = await post('/sigr/reward', { reward_attestation: { episode_id: 'ep-1', step_receipt_digests: [SHA64('1'), SHA64('2')], reward: 1.0, reward_model_hash: SHA64('d'), algo: 'GRPO' } });
  rec('reward sign 200+ok', rw.status === 200 && rw.body?.ok && (rw.body.envelope?.envelope_signature?.length||0) > 3000, `status=${rw.status} ok=${rw.body?.ok}`);
  const rwEnv = rw.body?.envelope;
  const rwv = await post('/sigr/reward/verify', { envelope: rwEnv });
  rec('reward verify valid', rwv.status === 200 && rwv.body?.valid === true, `valid=${rwv.body?.valid} reasons=${(rwv.body?.reasons||[]).join('|')}`);
  // reward sign-gate: missing reward_model_hash -> 400
  const rwBad = await post('/sigr/reward', { reward_attestation: { episode_id: 'ep-x', step_receipt_digests: [SHA64('1')], reward: 0.5, algo: 'PPO' } });
  rec('reward rejects missing model_hash (400)', rwBad.status === 400, `status=${rwBad.status}`);

  // 5) TOOL ANCHOR mint + verify
  const ta = await post('/sigr/toolanchor', { call: { tool_id: 'get_project', tool_hash: SHA64('a'), input: { id: 'P1' }, output: { name: 'Proj 1' }, deterministic: true, holder: 'acct-1' } });
  rec('toolanchor mint 200+ok', ta.status === 200 && ta.body?.ok && !!ta.body?.anchor?.identity_key, `status=${ta.status} ok=${ta.body?.ok}`);
  const taEnv = ta.body?.anchor;
  const tav = await post('/sigr/toolanchor/verify', { anchor: taEnv });
  rec('toolanchor verify valid', tav.status === 200 && tav.body?.valid === true, `valid=${tav.body?.valid} reasons=${(tav.body?.reasons||[]).join('|')}`);
  // toolanchor mint-gate: non-deterministic -> 400
  const taBad = await post('/sigr/toolanchor', { call: { tool_id: 'web_now', input: {}, output: {}, deterministic: false, holder: 'a' } });
  rec('toolanchor rejects non-deterministic (400)', taBad.status === 400, `status=${taBad.status}`);

  // 6) GCA sign + verify (per-claim grounding, one unsupported claim visible)
  const gca = await post('/sigr/gca', { grounding_claims: {
    answer_id: 'ans-1', method_hash: SHA64('e'),
    claims: [
      { claim_id: 1, claim: 'c1', support: SHA64('1'), support_strength: 0.96 },
      { claim_id: 2, claim: 'c2', support: SHA64('2'), support_strength: 0.88 },
      { claim_id: 3, claim: 'c3', support: null },
    ],
  } });
  rec('gca sign 200+ok', gca.status === 200 && gca.body?.ok && (gca.body.envelope?.envelope_signature?.length||0) > 3000, `status=${gca.status} ok=${gca.body?.ok}`);
  const gcaEnv = gca.body?.envelope;
  rec('gca unsupported visible + asserts support_not_truth', gcaEnv?.unsupported_count === 1 && gcaEnv?.asserts === 'support_not_truth', `unsup=${gcaEnv?.unsupported_count} asserts=${gcaEnv?.asserts}`);
  const gcav = await post('/sigr/gca/verify', { envelope: gcaEnv });
  rec('gca verify valid', gcav.status === 200 && gcav.body?.valid === true, `valid=${gcav.body?.valid} reasons=${(gcav.body?.reasons||[]).join('|')}`);
  // gca sign-gate: missing method_hash -> 400
  const gcaBad = await post('/sigr/gca', { grounding_claims: { claims: [{ claim: 'x', support: null }] } });
  rec('gca rejects missing method_hash (400)', gcaBad.status === 400, `status=${gcaBad.status}`);

  // 7) GiTM sign + verify (cross-signal anomaly, asserts provenance_anomaly_only)
  const gitm = await post('/sigr/gitm', { gitm: {
    subject_id: 'ans-1', claims_root_ref: gcaEnv?.claims_root,
    signals: { grounding_anomaly: 0.74, cross_run_divergence: 0.63 },
  } });
  rec('gitm sign 200+ok', gitm.status === 200 && gitm.body?.ok && (gitm.body.envelope?.envelope_signature?.length||0) > 3000, `status=${gitm.status} ok=${gitm.body?.ok}`);
  const gitmEnv = gitm.body?.envelope;
  rec('gitm triggered + asserts provenance_anomaly_only + triangulate', gitmEnv?.triggered === true && gitmEnv?.asserts === 'provenance_anomaly_only' && gitmEnv?.decision?.recommendation?.action === 'triangulate', `trig=${gitmEnv?.triggered} asserts=${gitmEnv?.asserts} action=${gitmEnv?.decision?.recommendation?.action}`);
  const gitmv = await post('/sigr/gitm/verify', { envelope: gitmEnv });
  rec('gitm verify valid', gitmv.status === 200 && gitmv.body?.valid === true, `valid=${gitmv.body?.valid} reasons=${(gitmv.body?.reasons||[]).join('|')}`);
  // gitm asserts-tamper: flip the non-truth declaration -> verify fails
  const gitmTamper = JSON.parse(JSON.stringify(gitmEnv)); gitmTamper.asserts = 'output_is_false';
  const gitmtv = await post('/sigr/gitm/verify', { envelope: gitmTamper });
  rec('gitm rejects tampered asserts', gitmtv.body?.valid === false, `valid=${gitmtv.body?.valid}`);

  const passed = results.filter(r => r.pass).length;
  const failed = results.length - passed;
  console.log(JSON.stringify({ passed, failed, total: results.length, results }, null, 2));
  process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.log(JSON.stringify({ fatal: e.message })); process.exit(2); });

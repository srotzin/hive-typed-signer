// AFiR-S3 Agentic Provenance — adversarial suite. Real ML-DSA-65 signatures
// (SIGNER from key.js); every tamper vector for all four primitives + tool reuse.
import { SIGNER, verifyFn } from '../src/key.js';
import { signToolScope, verifyToolScope, scopeAllows } from '../src/toolscope.js';
import { signAgenticRun, verifyAgenticRun } from '../src/agentic.js';
import { signCern, verifyCern, contextRoot } from '../src/cern.js';
import { signReward, verifyReward } from '../src/reward.js';
import {
  mintToolAnchor, verifyToolAnchor, resolveToolCall,
  verifyToolSavingsProof, toolCallIdentity,
} from '../src/toolreuse.js';
import { canonicalize, hashHex, resolveSuite } from '../src/typed.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;
const pubResolver = () => PUB;
const SUITE = resolveSuite('sha-256');
const clone = o => JSON.parse(JSON.stringify(o));

// ---------------------------------------------------------------------------
// 1. TOOL-SCOPE (HC-2026-008)
// ---------------------------------------------------------------------------
function mkScope() {
  return {
    scope_id: 'scope-1', agent_ref: 'agent-x',
    tools: [
      { tool_id: 'read_project', tool_hash: 'a'.repeat(64) },
      { tool_id: 'delete_project', tool_hash: 'b'.repeat(64) },
      { tool_id: 'transfer_funds', tool_hash: 'c'.repeat(64) },
    ],
    destructive_tools: ['delete_project', 'transfer_funds'],
    granted_by: 'policy:root',
  };
}

section('toolscope: seal + verify happy path');
let SCOPE_ENV;
{
  const { envelope } = signToolScope(mkScope(), SIGNER);
  SCOPE_ENV = envelope;
  const r = verifyToolScope(envelope, verifyFn, PUB);
  ok(r.valid, 'scope verifies; reasons=' + r.reasons.join(','));
  ok(/^[0-9a-f]{64}$/.test(envelope.scope_root), 'scope_root is a real hex root');
  ok(Buffer.from(envelope.envelope_signature, 'base64').length > 3000, 'real ML-DSA-65 sig (>3KB)');
}

section('toolscope: add a tool (privilege escalation) is rejected');
{
  const t = clone(SCOPE_ENV);
  t.tools.push({ tool_id: 'wipe_db', tool_hash: 'd'.repeat(64) });
  t.tool_count = t.tools.length;
  const r = verifyToolScope(t, verifyFn, PUB);
  ok(!r.valid, 'injected tool rejected');
}

section('toolscope: edit a tool_hash is rejected');
{
  const t = clone(SCOPE_ENV);
  t.tools[0].tool_hash = 'f'.repeat(64);
  const r = verifyToolScope(t, verifyFn, PUB);
  ok(!r.valid, 'edited tool_hash rejected (leaves/root mismatch)');
}

section('toolscope: flag a non-granted tool destructive is rejected at sign');
{
  let threw = false;
  try { signToolScope({ ...mkScope(), destructive_tools: ['ghost_tool'] }, SIGNER); }
  catch (e) { threw = /destructive_not_in_scope/.test(e.message); }
  ok(threw, 'destructive tool must be in scope');
}

section('toolscope: scopeAllows predicate');
{
  eq(scopeAllows(SCOPE_ENV, 'read_project').allowed, true, 'in-scope tool allowed');
  eq(scopeAllows(SCOPE_ENV, 'delete_project').destructive, true, 'delete flagged destructive');
  eq(scopeAllows(SCOPE_ENV, 'unknown_tool').allowed, false, 'out-of-scope tool denied');
}

// ---------------------------------------------------------------------------
// 2. AGENTIC ACTION (HC-2026-009) — thin wrapper over chain.js, SCOPE-GATED
// ---------------------------------------------------------------------------
function mkAgenticRun() {
  return {
    run_id: 'arun-1', agent_ref: 'agent-x',
    steps: [
      { step_id: 's1', kind: 'plan', seq: 0, parents: [], input: { goal: 'cleanup' }, output: { plan: ['read', 'delete'] } },
      { step_id: 's2', kind: 'tool_call', seq: 1, parents: ['s1'], input: { id: 'P1' },
        action: 'read_project', tool_target: 'P1', tool_hash: 'a'.repeat(64), scope_ref: 'sigr:scope-1' },
      { step_id: 's3', kind: 'tool_call', seq: 2, parents: ['s2'], input: { id: 'P1' },
        action: 'delete_project', tool_target: 'P1', tool_hash: 'b'.repeat(64), scope_ref: 'sigr:scope-1' },
      { step_id: 's4', kind: 'final', seq: 3, parents: ['s3'], input: {}, output: { done: true } },
    ],
  };
}

section('agentic: in-scope run seals + verifies');
let AG_ENV;
{
  const { envelope } = signAgenticRun(mkAgenticRun(), [SCOPE_ENV], SIGNER, verifyFn, pubResolver);
  AG_ENV = envelope;
  const r = verifyAgenticRun(envelope, [SCOPE_ENV], verifyFn, pubResolver);
  ok(r.valid, 'in-scope agentic run verifies; reasons=' + r.reasons.join(','));
  eq(envelope.agentic_actions['s3'].meta.arsc_tier, 'rise', 'destructive action -> ARSC rise tier');
  eq(envelope.agentic_actions['s2'].meta.arsc_tier, 'sink', 'read action -> ARSC sink tier');
}

section('agentic: OUT-OF-SCOPE action is REJECTED at sign (the gate)');
{
  const run = mkAgenticRun();
  run.steps[2].action = 'wipe_everything';   // not in scope
  run.steps[2].tool_hash = '9'.repeat(64);
  let threw = false, msg = '';
  try { signAgenticRun(run, [SCOPE_ENV], SIGNER, verifyFn, pubResolver); }
  catch (e) { threw = /out_of_scope_action/.test(e.message); msg = e.message; }
  ok(threw, 'out-of-scope action rejected, never sealed: ' + msg);
}

section('agentic: missing scope_ref on an action is rejected');
{
  const run = mkAgenticRun();
  delete run.steps[1].scope_ref;
  let threw = false;
  try { signAgenticRun(run, [SCOPE_ENV], SIGNER, verifyFn, pubResolver); }
  catch (e) { threw = /missing_scope_ref/.test(e.message); }
  ok(threw, 'action without scope_ref rejected');
}

section('agentic: tampered/invalid scope is rejected at sign (fail closed)');
{
  const badScope = clone(SCOPE_ENV);
  badScope.scope_root = '0'.repeat(64);     // break the scope
  let threw = false;
  try { signAgenticRun(mkAgenticRun(), [badScope], SIGNER, verifyFn, pubResolver); }
  catch (e) { threw = /scope_invalid/.test(e.message); }
  ok(threw, 'invalid referenced scope rejected');
}

section('agentic: tool_hash mismatch vs scoped tool is rejected');
{
  const run = mkAgenticRun();
  run.steps[1].tool_hash = 'e'.repeat(64);  // read_project scoped as a..a
  let threw = false;
  try { signAgenticRun(run, [SCOPE_ENV], SIGNER, verifyFn, pubResolver); }
  catch (e) { threw = /tool_hash_mismatch/.test(e.message); }
  ok(threw, 'action tool_hash must match scoped tool_hash');
}

section('agentic: editing a sealed step I/O breaks the chain');
{
  const t = clone(AG_ENV);
  t.steps.find(s => s.step_id === 's3').io_digest = 'f'.repeat(64);
  const r = verifyAgenticRun(t, [SCOPE_ENV], verifyFn, pubResolver);
  ok(!r.valid, 'edited action step rejected (chain integrity)');
}

section('agentic: post-hoc sidecar tamper (out-of-scope rewrite) caught at verify');
{
  const t = clone(AG_ENV);
  // attacker rewrites the sidecar action to an out-of-scope tool after sealing.
  // io_digest re-derivation from the tampered output will no longer match the
  // signed io_digest -> agentic_action_unbound; and re-gate flags out_of_scope.
  t.agentic_actions['s3'].meta.action = 'ghost';
  t.agentic_actions['s3'].output.__agentic_action.action = 'ghost';
  const r = verifyAgenticRun(t, [SCOPE_ENV], verifyFn, pubResolver);
  ok(!r.valid, 'post-hoc sidecar tamper caught at verify; reasons=' + r.reasons.join(','));
}

section('agentic: sidecar meta tamper WITHOUT touching output is caught (unbinding)');
{
  const t = clone(AG_ENV);
  // change only the inspectable meta, leave the bound output alone -> the
  // recomputed io_digest still matches, but meta!=output.__agentic_action catches it.
  t.agentic_actions['s2'].meta.action = 'transfer_funds';
  const r = verifyAgenticRun(t, [SCOPE_ENV], verifyFn, pubResolver);
  ok(!r.valid, 'sidecar meta/output divergence caught; reasons=' + r.reasons.join(','));
}

// ---------------------------------------------------------------------------
// 3. AFiR-CERN (HC-2026-010) — the crown jewel
// ---------------------------------------------------------------------------
const CTX0 = [{ id: 1, t: 'user asked for refund of $500' }, { id: 2, t: 'policy: refunds <= $100 auto' }, { id: 3, t: 'order total $500' }];

section('cern: append (lossless) verifies');
{
  const after = [...CTX0, { id: 4, t: 'agent note: escalate' }];
  const { envelope } = signCern({ run_id: 'r1', step: 1, mutation_type: 'append', context_before: CTX0, context_after: after, integrity_claim: 'lossless' }, SIGNER);
  const r = verifyCern(envelope, verifyFn, PUB);
  ok(r.valid, 'append verifies; reasons=' + r.reasons.join(','));
  eq(envelope.arsc_tier, 'sink', 'append -> ARSC sink');
}

section('cern: disclosed alteration (altered_attested) verifies');
let CERN_ALTER;
{
  // alter span id:1 ("$500" -> "$50") and disclose it
  const origDigest = hashHex(canonicalize(CTX0[0]), SUITE);
  const altered = { id: 1, t: 'user asked for refund of $50' };
  const after = [altered, CTX0[1], CTX0[2]];
  const resultDigest = hashHex(canonicalize(altered), SUITE);
  const { envelope } = signCern({
    run_id: 'r1', step: 2, mutation_type: 'alter',
    context_before: CTX0, context_after: after,
    altered_spans: [{ original_hash: origDigest, result_hash: resultDigest, reason: 'redact amount' }],
    integrity_claim: 'altered_attested',
  }, SIGNER);
  CERN_ALTER = envelope;
  const r = verifyCern(envelope, verifyFn, PUB);
  ok(r.valid, 'disclosed alteration verifies; reasons=' + r.reasons.join(','));
  eq(envelope.arsc_tier, 'rise', 'alteration -> ARSC rise (highest liability)');
}

section('cern: SILENT alteration (claims lossless) is REJECTED at sign');
{
  const altered = { id: 1, t: 'user asked for refund of $50' };  // changed, NOT disclosed
  const after = [altered, CTX0[1], CTX0[2]];
  let threw = false, msg = '';
  try {
    signCern({ run_id: 'r1', step: 3, mutation_type: 'append', context_before: CTX0, context_after: after, integrity_claim: 'lossless' }, SIGNER);
  } catch (e) { threw = /inconsistent_mutation/.test(e.message); msg = e.message; }
  ok(threw, 'silent rewrite claiming lossless rejected: ' + msg);
}

section('cern: undisclosed DROP is REJECTED at sign');
{
  const after = [CTX0[0], CTX0[2]];  // dropped span id:2 (the policy line) silently
  let threw = false;
  try {
    signCern({ run_id: 'r1', step: 4, mutation_type: 'append', context_before: CTX0, context_after: after, integrity_claim: 'lossless' }, SIGNER);
  } catch (e) { threw = /inconsistent_mutation/.test(e.message); }
  ok(threw, 'undisclosed drop claiming append rejected');
}

section('cern: disclosed drop verifies');
{
  const dropped = hashHex(canonicalize(CTX0[1]), SUITE);
  const after = [CTX0[0], CTX0[2]];
  const { envelope } = signCern({
    run_id: 'r1', step: 5, mutation_type: 'drop', context_before: CTX0, context_after: after,
    altered_spans: [{ original_hash: dropped, result_hash: null, reason: 'stale policy' }],
    integrity_claim: 'lossy_attested',
  }, SIGNER);
  const r = verifyCern(envelope, verifyFn, PUB);
  ok(r.valid, 'disclosed drop verifies; reasons=' + r.reasons.join(','));
}

section('cern: post-hoc tamper of after_root caught at verify');
{
  const t = clone(CERN_ALTER);
  t.context_after_root = 'a'.repeat(64);
  const r = verifyCern(t, verifyFn, PUB);
  ok(!r.valid, 'tampered after_root caught');
}

section('cern: post-hoc removal of a disclosed altered_span caught at verify');
{
  const t = clone(CERN_ALTER);
  t.altered_spans = [];  // hide the disclosure after the fact
  const r = verifyCern(t, verifyFn, PUB);
  ok(!r.valid, 'hidden disclosure caught (delta inconsistent)');
}

section('cern: editing a context_after_digest caught at verify');
{
  const t = clone(CERN_ALTER);
  t.context_after_digests[0] = 'b'.repeat(64);
  const r = verifyCern(t, verifyFn, PUB);
  ok(!r.valid, 'edited after digest caught (root mismatch)');
}

// ---------------------------------------------------------------------------
// 4. REWARD-ATTESTATION (HC-2026-011)
// ---------------------------------------------------------------------------
section('reward: seal + verify (trajectory_root supplied)');
let RW_ENV;
{
  const { envelope } = signReward({
    episode_id: 'ep-1', trajectory_root: 'a'.repeat(64),
    reward: 1.0, reward_model_hash: 'd'.repeat(64), algo: 'GRPO',
  }, SIGNER);
  RW_ENV = envelope;
  const r = verifyReward(envelope, verifyFn, PUB);
  ok(r.valid, 'reward verifies; reasons=' + r.reasons.join(','));
  eq(envelope.arsc_tier, 'float', 'reward -> ARSC float (training-time)');
}

section('reward: trajectory_root rolled up from step digests');
{
  const digs = ['1'.repeat(64), '2'.repeat(64), '3'.repeat(64)];
  const { envelope } = signReward({ episode_id: 'ep-2', step_receipt_digests: digs, reward: 0.5, reward_model_hash: 'e'.repeat(64), algo: 'PPO' }, SIGNER);
  const r = verifyReward(envelope, verifyFn, PUB);
  ok(r.valid, 'rolled-up trajectory reward verifies');
  // tamper a step digest -> root mismatch
  const t = clone(envelope);
  t.step_receipt_digests[0] = '9'.repeat(64);
  ok(!verifyReward(t, verifyFn, PUB).valid, 'tampered step digest breaks trajectory root');
}

section('reward: tampered reward value is rejected');
{
  const t = clone(RW_ENV);
  t.reward = 999.0;  // change the signed reward
  const r = verifyReward(t, verifyFn, PUB);
  ok(!r.valid, 'tampered reward rejected');
}

section('reward: swapped reward_model_hash is rejected');
{
  const t = clone(RW_ENV);
  t.reward_model_hash = 'f'.repeat(64);
  const r = verifyReward(t, verifyFn, PUB);
  ok(!r.valid, 'swapped reward model rejected');
}

section('reward: missing reward_model_hash rejected at sign');
{
  let threw = false;
  try { signReward({ trajectory_root: 'a'.repeat(64), reward: 1.0, algo: 'GRPO' }, SIGNER); }
  catch (e) { threw = /missing_reward_model_hash/.test(e.message); }
  ok(threw, 'reward model hash required');
}

// ---------------------------------------------------------------------------
// 5. TOOL-CALL TRUST-ANCHOR REUSE (AFiR-S3 §3, R2 identical-never-similar)
// ---------------------------------------------------------------------------
function detCall(input, output) {
  return { tool_id: 'get_project', tool_hash: 'a'.repeat(64), input, output, deterministic: true, holder: 'acct-1' };
}

section('toolreuse: mint + verify a deterministic anchor');
let ANCHOR;
{
  const { anchor } = mintToolAnchor(detCall({ id: 'P1' }, { name: 'Proj 1', status: 'active' }), SIGNER);
  ANCHOR = anchor;
  const r = verifyToolAnchor(anchor, verifyFn, PUB);
  ok(r.valid, 'tool anchor verifies; reasons=' + r.reasons.join(','));
  ok(Buffer.from(anchor.envelope_signature, 'base64').length > 3000, 'real ML-DSA-65 sig on anchor');
}

section('toolreuse: non-deterministic tool CANNOT anchor');
{
  let threw = false;
  try { mintToolAnchor({ tool_id: 'web_now', input: {}, output: {}, deterministic: false, holder: 'a' }, SIGNER); }
  catch (e) { threw = /non_deterministic_tool_cannot_anchor/.test(e.message); }
  ok(threw, 'non-deterministic tool refused');
}

section('toolreuse: byte-identical call CHAINS (R2 hit) + signed savings proof');
{
  const index = new Map([[ANCHOR.identity_key, ANCHOR]]);
  const res = resolveToolCall(detCall({ id: 'P1' }, { name: 'Proj 1', status: 'active' }), index, new Set(), SIGNER, verifyFn, pubResolver);
  eq(res.outcome, 'chain', 'identical call chains');
  ok(res.savings_proof, 'chain emits a savings proof');
  ok(verifyToolSavingsProof(res.savings_proof, verifyFn, PUB).valid, 'savings proof verifies');
  ok(res.savings_proof.saved_us > 0, 'savings proof records positive saving');
}

section('toolreuse: ONE-BYTE different input COLD-MINTS (R2: never similar)');
{
  const index = new Map([[ANCHOR.identity_key, ANCHOR]]);
  const res = resolveToolCall(detCall({ id: 'P2' }, { name: 'Proj 2' }), index, new Set(), SIGNER, verifyFn, pubResolver);
  eq(res.outcome, 'cold_mint', 'different input never reuses (identical, not similar)');
  ok(res.identity_key !== ANCHOR.identity_key, 'different identity_key');
}

section('toolreuse: different tool_hash COLD-MINTS (model/tool axis)');
{
  const index = new Map([[ANCHOR.identity_key, ANCHOR]]);
  const call = { ...detCall({ id: 'P1' }, { name: 'Proj 1', status: 'active' }), tool_hash: 'z'.repeat(64) };
  const res = resolveToolCall(call, index, new Set(), SIGNER, verifyFn, pubResolver);
  eq(res.outcome, 'cold_mint', 'different tool_hash never reuses');
}

section('toolreuse: REVOKED anchor fails closed -> cold-mint');
{
  const index = new Map([[ANCHOR.identity_key, ANCHOR]]);
  const revoked = new Set([ANCHOR.identity_key]);
  const res = resolveToolCall(detCall({ id: 'P1' }, { name: 'Proj 1', status: 'active' }), index, revoked, SIGNER, verifyFn, pubResolver);
  eq(res.outcome, 'cold_mint', 'revoked anchor fails closed');
}

section('toolreuse: TAMPERED anchor fails closed -> cold-mint');
{
  const bad = clone(ANCHOR);
  bad.result_digest = 'f'.repeat(64);  // tamper the attested result
  const index = new Map([[bad.identity_key, bad]]);
  const res = resolveToolCall(detCall({ id: 'P1' }, { name: 'Proj 1', status: 'active' }), index, new Set(), SIGNER, verifyFn, pubResolver);
  eq(res.outcome, 'cold_mint', 'tampered anchor fails closed (re-mints real sig)');
}

section('toolreuse: result mismatch on identical inputs fails closed');
{
  const index = new Map([[ANCHOR.identity_key, ANCHOR]]);
  // identical identity, but the caller presents a different result than anchored
  const res = resolveToolCall(detCall({ id: 'P1' }, { name: 'Proj 1', status: 'CHANGED' }), index, new Set(), SIGNER, verifyFn, pubResolver);
  eq(res.outcome, 'cold_mint', 'result mismatch -> cold-mint, never chains a wrong result');
}

summary('afir_s3');

// SiGR Chain tests: causal-graph seal/verify + reorder/insert/drop/edit/cycle detection.
import { SIGNER, verifyFn } from '../src/key.js';
import { signChain, verifyChain, buildStepCommit } from '../src/chain.js';
import { resolveSuite } from '../src/typed.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;

// A small agent run: plan -> (two parallel tool_calls) -> merge -> final (a DAG)
function mkRun() {
  return {
    run_id: 'run-1', agent_ref: 'research-agent-v2',
    steps: [
      { step_id: 's1', kind: 'plan', seq: 0, parents: [], input: { goal: 'compare' }, output: { plan: ['a', 'b'] } },
      { step_id: 's2', kind: 'tool_call', seq: 1, parents: ['s1'], input: { q: 'a' }, output: { r: 'A' } },
      { step_id: 's3', kind: 'tool_call', seq: 1, parents: ['s1'], input: { q: 'b' }, output: { r: 'B' } },
      { step_id: 's4', kind: 'merge', seq: 2, parents: ['s2', 's3'], input: { merge: ['A', 'B'] }, output: { m: 'AB' } },
      { step_id: 's5', kind: 'final', seq: 3, parents: ['s4'], input: { m: 'AB' }, output: { answer: 'done' } },
    ],
  };
}

section('chain: seal + verify happy path (DAG)');
{
  const { envelope } = signChain(mkRun(), SIGNER);
  const r = verifyChain(envelope, verifyFn, PUB);
  ok(r.valid, 'DAG chain verifies; reasons=' + r.reasons.join(','));
  eq(r.step_count, 5, 'all 5 steps sealed');
}

section('chain: edit a step I/O');
{
  const { envelope } = signChain(mkRun(), SIGNER);
  const t = JSON.parse(JSON.stringify(envelope));
  t.steps.find(s => s.step_id === 's2').io_digest = 'f'.repeat(64); // forge an output
  const r = verifyChain(t, verifyFn, PUB);
  ok(!r.valid, 'edited step I/O rejected');
  ok(r.reasons.some(x => x.startsWith('commit_digest_mismatch')) ||
     r.reasons.includes('causal_root_mismatch'), 'edit flagged: ' + r.reasons.join(','));
}

section('chain: drop a step');
{
  const { envelope } = signChain(mkRun(), SIGNER);
  const t = JSON.parse(JSON.stringify(envelope));
  t.steps = t.steps.filter(s => s.step_id !== 's3'); // remove a parallel branch
  const r = verifyChain(t, verifyFn, PUB);
  ok(!r.valid, 'dropped step rejected');
}

section('chain: insert a fabricated step');
{
  const { envelope } = signChain(mkRun(), SIGNER);
  const suite = resolveSuite('sha-256');
  const fake = buildStepCommit(
    { step_id: 's6', kind: 'tool_call', seq: 4, parents: ['s5'], input: { x: 1 }, output: { y: 2 } },
    [envelope.steps.find(s => s.step_id === 's5').commit_digest], suite);
  const t = JSON.parse(JSON.stringify(envelope));
  t.steps.push({ ...fake.record, commit_digest: fake.commit_digest });
  t.step_count = t.steps.length;
  const r = verifyChain(t, verifyFn, PUB);
  ok(!r.valid, 'inserted step rejected (causal root + count change)');
}

section('chain: reorder via parent rewrite');
{
  const { envelope } = signChain(mkRun(), SIGNER);
  const t = JSON.parse(JSON.stringify(envelope));
  // try to make s5 (final) appear to descend directly from s1, skipping the merge
  t.steps.find(s => s.step_id === 's5').parents = ['s1'];
  const r = verifyChain(t, verifyFn, PUB);
  ok(!r.valid, 'parent rewrite rejected');
}

section('chain: cycle is rejected at verify');
{
  const { envelope } = signChain(mkRun(), SIGNER);
  const t = JSON.parse(JSON.stringify(envelope));
  t.steps.find(s => s.step_id === 's1').parents = ['s5']; // s1<-s5 makes a cycle
  const r = verifyChain(t, verifyFn, PUB);
  ok(!r.valid, 'cycle rejected');
  ok(r.reasons.some(x => x.startsWith('graph_invalid')), 'cycle flagged: ' + r.reasons.join(','));
}

section('chain: linear run (degenerate single-parent)');
{
  const lin = {
    run_id: 'run-2', agent_ref: 'linear',
    steps: [
      { step_id: 'a', kind: 'plan', seq: 0, parents: [], output: { x: 1 } },
      { step_id: 'b', kind: 'reason', seq: 1, parents: ['a'], output: { x: 2 } },
      { step_id: 'c', kind: 'final', seq: 2, parents: ['b'], output: { x: 3 } },
    ],
  };
  const { envelope } = signChain(lin, SIGNER);
  ok(verifyChain(envelope, verifyFn, PUB).valid, 'linear chain verifies');
}

summary('chain');

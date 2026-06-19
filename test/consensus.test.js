// Concept E Consensus tests: sub-receipt verify, decision math, panel reconcile,
// drop-a-dissenter detection, all four decision methods.
import { SIGNER, verifyFn } from '../src/key.js';
import {
  signSubReceipt, verifySubReceipt, computeConsensus,
  signConsensus, verifyConsensus,
} from '../src/consensus.js';
import { hashHex, resolveSuite } from '../src/typed.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;
const S = resolveSuite('sha-256');

// Two distinct answers, A and B. output_digest groups votes.
const DIG_A = hashHex('answer-A', S);
const DIG_B = hashHex('answer-B', S);

function member(panel_id, model_id, digest, score, seq) {
  return { panel_id, model_id, output_digest: digest, score, seq };
}

section('consensus: sub-receipt happy path + tamper');
{
  const env = signSubReceipt(member('p1', 'gpt-4o', DIG_A, 80, 0), SIGNER);
  ok(verifySubReceipt(env, verifyFn, PUB).valid, 'sub-receipt verifies');
  const t = JSON.parse(JSON.stringify(env));
  t.member.output_digest = DIG_B;             // swap what the model "said"
  ok(!verifySubReceipt(t, verifyFn, PUB).valid, 'swapped output rejected');
}

section('consensus: decision math (pure)');
{
  // panel of 5: A,A,A,B,B -> majority A
  const members = [
    member('p1', 'm1', DIG_A, 50, 0), member('p1', 'm2', DIG_A, 50, 1),
    member('p1', 'm3', DIG_A, 50, 2), member('p1', 'm4', DIG_B, 90, 3),
    member('p1', 'm5', DIG_B, 90, 4),
  ];
  const maj = computeConsensus(members, 'majority');
  ok(maj.decided && maj.winner.output_digest === DIG_A, 'majority picks A (3 vs 2)');

  // weighted: B has higher summed score (180 vs 150) -> weighted picks B
  const w = computeConsensus(members, 'weighted');
  ok(w.decided && w.winner.output_digest === DIG_B, 'weighted picks B (180 > 150)');

  // quorum of 4 not met by either group -> no decision
  const q = computeConsensus(members, 'quorum', { quorum_n: 4 });
  ok(!q.decided, 'quorum 4 not reached');
  const q3 = computeConsensus(members, 'quorum', { quorum_n: 3 });
  ok(q3.decided && q3.winner.output_digest === DIG_A, 'quorum 3 reached by A');

  // judge picks a specific model's answer regardless of vote
  const j = computeConsensus(members, 'judge', { judge_pick: 'm4' });
  ok(j.decided && j.winner.output_digest === DIG_B && j.winner.model_id === 'm4', 'judge picks m4 (B)');
}

section('consensus: panel aggregation + reconcile');
{
  const subs = [
    signSubReceipt(member('p1', 'm1', DIG_A, 50, 0), SIGNER),
    signSubReceipt(member('p1', 'm2', DIG_A, 50, 1), SIGNER),
    signSubReceipt(member('p1', 'm3', DIG_B, 50, 2), SIGNER),
  ];
  const { envelope } = signConsensus({ panel_id: 'p1' }, subs, 'majority', SIGNER);

  const good = verifyConsensus(envelope, subs, verifyFn, PUB);
  ok(good.valid, 'honest consensus reconciles; reasons=' + good.reasons.join(','));
  ok(good.decided && good.winner.output_digest === DIG_A, 'winner A surfaced');

  // drop the dissenting sub-receipt (m3/B) -> panel root + decision tally change
  const dropped = verifyConsensus(envelope, subs.slice(0, 2), verifyFn, PUB);
  ok(!dropped.valid, 'dropped dissenter detected');
  ok(dropped.reasons.includes('panel_root_mismatch_vs_sub_receipts') ||
     dropped.reasons.includes('member_count_mismatch') ||
     dropped.reasons.includes('decision_digest_mismatch'), 'drop flagged: ' + dropped.reasons.join(','));

  // tamper the carried decision winner -> digest mismatch
  const t = JSON.parse(JSON.stringify(envelope));
  t.decision.winner = { output_digest: DIG_B, models: ['m3'] };
  const bad = verifyConsensus(t, subs, verifyFn, PUB);
  ok(!bad.valid, 'misreported winner detected');
}

summary('consensus');

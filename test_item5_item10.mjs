/**
 * Proof suite for dossier items 5 (temporal proof) + 10 (SHA-384 long-life).
 * Builds on the QPuF signer. Pure assertions; exits non-zero on any failure.
 */
import { buildFragments, signTyped, verifyTyped, resolveSuite } from './src/typed.js';
import { getQpufSigner, verifyFn } from './src/qpuf/index.js';
import { buildTemporalProof } from './src/temporal.js';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name); } };

const QPUF = getQpufSigner();
const pub = QPUF.publicKey;
const items = [
  { text: 'The pit limiter engaged at 80 km/h on entry.', id: 'f1', type: 'reasoning' },
  { text: 'Call strategy_model(undercut=true).', id: 'f2', type: 'tool_call' },
  { text: 'Therefore the answer is to pit on lap 18.', id: 'f3', type: 'final' },
];
const policy = { sign_types: ['reasoning', 'tool_call', 'final'], absence_bound: 0, policy_id: 'test' };
const canonOf = frags => frags.map(f => ({ fragment_id: f.fragment_id, fragment_type: f.fragment_type, text_hash: f.text_hash, index: f.index }));

// ---- BASELINE: default SHA-256, no temporal (must be unchanged / back-compat) ----
{
  const frags = buildFragments(items);
  const { envelope } = signTyped(frags, policy, QPUF);
  const r = verifyTyped(envelope, canonOf(frags), verifyFn, pub);
  ok('B1 baseline sha-256 receipt verifies', r.valid);
  ok('B1 baseline omits hash_suite field (wire-compat)', envelope.hash_suite === undefined);
  ok('B1 baseline omits temporal field', envelope.temporal === undefined);
}

// ---- ITEM 10: SHA-384 ultra-long-life ----
{
  const suite = resolveSuite('sha-384');
  const frags = buildFragments(items, suite);
  const { envelope } = signTyped(frags, policy, QPUF, { hashSuite: 'sha-384' });
  ok('T10.1 hash_suite recorded as sha-384', envelope.hash_suite === 'sha-384');
  ok('T10.2 agg_root is 96 hex chars (48-byte SHA-384)', (envelope.agg_root || '').length === 96);
  ok('T10.3 payload_digest is 96 hex chars (SHA-384)', envelope.payload_digest.length === 96);
  const r = verifyTyped(envelope, canonOf(frags), verifyFn, pub);
  ok('T10.4 SHA-384 receipt verifies under matching suite', r.valid);
  // tamper: flip the recorded suite to sha-256 -> must fail (verifier recomputes wrong)
  const tampered = JSON.parse(JSON.stringify(envelope));
  tampered.hash_suite = 'sha-256';
  const rt = verifyTyped(tampered, canonOf(frags), verifyFn, pub);
  ok('T10.5 downgrading hash_suite to sha-256 fails verification', !rt.valid);
}

// ---- ITEM 5: three-tier temporal proof bound into the signature ----
{
  const frags = buildFragments(items);
  const temporal = buildTemporalProof();
  const { envelope } = signTyped(frags, policy, QPUF, { temporal });
  ok('T5.1 envelope carries temporal proof', !!envelope.temporal && envelope.temporal.object === 'hive.temporal.proof');
  ok('T5.2 tier1 capture present (wall + monotonic)', !!envelope.temporal.tier1_capture.wall_iso && !!envelope.temporal.tier1_capture.monotonic_ns);
  ok('T5.3 tier2 soft = base flashblocks ~200ms', envelope.temporal.tier2_soft.mechanism === 'flashblocks' && envelope.temporal.tier2_soft.preconf_ms === 200);
  ok('T5.4 tier3 finality present', envelope.temporal.tier3_final.tier === 'finality');
  ok('T5.5 sim time source honestly flagged not-attested', envelope.temporal.tier1_capture.source.attested === false);
  const r = verifyTyped(envelope, canonOf(frags), verifyFn, pub);
  ok('T5.6 temporal receipt verifies (temporal digest bound)', r.valid);
  // tamper: back-date the wall clock -> temporal digest changes -> payload mismatch -> fail
  const tampered = JSON.parse(JSON.stringify(envelope));
  tampered.temporal.tier1_capture.wall_iso = '2020-01-01T00:00:00.000Z';
  tampered.temporal.tier1_capture.wall_unix_ms = 1577836800000;
  const rt = verifyTyped(tampered, canonOf(frags), verifyFn, pub);
  ok('T5.7 back-dating the timestamp fails verification', !rt.valid && rt.reasons.includes('payload_digest_mismatch'));
}

// ---- COMBINED: SHA-384 + temporal + QPuF trust block all at once ----
{
  const suite = resolveSuite('sha-384');
  const frags = buildFragments(items, suite);
  const temporal = buildTemporalProof();
  const { envelope } = signTyped(frags, policy, QPUF, { hashSuite: 'sha-384', temporal });
  ok('C1 combined carries QPuF trust block', !!envelope.trust && envelope.trust.object === 'hive.qpuf.attestation');
  ok('C1 combined carries temporal + sha-384', !!envelope.temporal && envelope.hash_suite === 'sha-384');
  ok('C1 temporal digest computed with sha-384 (payload 96 hex)', envelope.payload_digest.length === 96);
  const r = verifyTyped(envelope, canonOf(frags), verifyFn, pub);
  ok('C1 combined receipt verifies end-to-end', r.valid);
  // tamper a fragment -> agg root + payload break
  const tampered = JSON.parse(JSON.stringify(envelope));
  const canon = canonOf(frags);
  canon[0].text_hash = 'deadbeef'.repeat(8);
  const rt = verifyTyped(tampered, canon, verifyFn, pub);
  ok('C1 edited fragment fails verification', !rt.valid);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);

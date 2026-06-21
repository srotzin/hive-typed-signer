// GCA tests: per-claim sign+verify, support: null preserved/visible, claims_root
// re-derivation, dropped-unsupported-claim detection, support_strength tamper,
// honest exposed signals (unsupported_count, support_variance), float->bp normalize.
import { SIGNER, verifyFn } from '../src/key.js';
import {
  signGca, verifyGca, normalizeStrength, normalizeClaim, claimLeaf,
} from '../src/gca.js';
import { hashHex, resolveSuite } from '../src/typed.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;
const S = resolveSuite('sha-256');

function span(label) { return hashHex('span-' + label, S); }

section('gca: strength normalization (float -> bp, unsupported pinned to 0)');
{
  eq(normalizeStrength({ support: span('a'), support_strength: 0.96 }), 9600, 'float 0.96 -> 9600bp');
  eq(normalizeStrength({ support: span('a'), support_strength_bp: 8800 }), 8800, 'explicit bp passthrough');
  eq(normalizeStrength({ support: null, support_strength: 0.5 }), 0, 'unsupported pinned to 0bp');
  eq(normalizeStrength({ support: span('a'), support_strength: 5 }), 10000, 'clamps above 1.0');
}

section('gca: happy path sign + verify');
{
  const gca = {
    answer_id: 'ans-1',
    method_hash: hashHex('grounding-method-v1', S),
    claims: [
      { claim_id: 1, claim: 'Paris is the capital of France', support: span('1'), support_strength: 0.96 },
      { claim_id: 2, claim: 'It has ~2.1M residents', support: span('2'), support_strength: 0.88 },
      { claim_id: 3, claim: 'The mayor was born in 1950', support: null },   // UNSUPPORTED
    ],
  };
  const { envelope } = signGca(gca, SIGNER);
  const v = verifyGca(envelope, verifyFn, PUB);
  ok(v.valid, 'honest GCA verifies; reasons=' + v.reasons.join(','));
  eq(envelope.claim_count, 3, 'claim_count');
  eq(envelope.unsupported_count, 1, 'one unsupported claim counted');
  eq(envelope.asserts, 'support_not_truth', 'binding asserts support_not_truth');
  eq(envelope.arsc_tier, 'critical', 'rides ARSC critical tier');
  // support: null is preserved + visible in the signed record
  ok(envelope.claims[2].support === null, 'unsupported claim support is null and visible');
}

section('gca: support: null is signed (made part of the record), not hidden');
{
  const gca = {
    method_hash: hashHex('m', S),
    claims: [{ claim_id: 1, claim: 'unsupported assertion', support: null }],
  };
  const { envelope } = signGca(gca, SIGNER);
  ok(verifyGca(envelope, verifyFn, PUB).valid, 'all-unsupported map still verifies (visible, signed)');
  eq(envelope.unsupported_count, 1, 'lone unsupported claim is counted in the signed record');
}

section('gca: tamper detection');
{
  const gca = {
    method_hash: hashHex('m', S),
    claims: [
      { claim_id: 1, claim: 'c1', support: span('1'), support_strength: 0.9 },
      { claim_id: 2, claim: 'c2', support: null },
    ],
  };
  const { envelope } = signGca(gca, SIGNER);

  // 1. flip an unsupported claim to "supported" by injecting a span -> claims_root breaks
  const t1 = JSON.parse(JSON.stringify(envelope));
  t1.claims[1].support = span('fake');
  ok(!verifyGca(t1, verifyFn, PUB).valid, 'injecting fake support detected');

  // 2. inflate support_strength on a real claim -> claims_root breaks
  const t2 = JSON.parse(JSON.stringify(envelope));
  t2.claims[0].support_strength_bp = 10000;
  ok(!verifyGca(t2, verifyFn, PUB).valid, 'inflated support_strength detected');

  // 3. drop the unsupported claim entirely (hide it) -> count + root mismatch
  const t3 = JSON.parse(JSON.stringify(envelope));
  t3.claims = [t3.claims[0]];
  const v3 = verifyGca(t3, verifyFn, PUB);
  ok(!v3.valid, 'dropped unsupported claim detected');
  ok(v3.reasons.includes('claim_count_mismatch') || v3.reasons.includes('claims_root_mismatch') ||
     v3.reasons.includes('unsupported_count_mismatch'), 'drop flagged: ' + v3.reasons.join(','));

  // 4. misreport the unsupported_count header -> mismatch
  const t4 = JSON.parse(JSON.stringify(envelope));
  t4.unsupported_count = 0;
  ok(!verifyGca(t4, verifyFn, PUB).valid, 'misreported unsupported_count detected');
}

section('gca: fail-closed on bad input');
{
  let threw = false;
  try { signGca({ claims: [{ claim: 'x', support: null }] }, SIGNER); } catch (e) { threw = true; }
  ok(threw, 'missing method_hash throws (fail-closed)');
  threw = false;
  try { signGca({ method_hash: hashHex('m', S), claims: [] }, SIGNER); } catch (e) { threw = true; }
  ok(threw, 'empty claims throws (fail-closed)');
}

summary('gca');

// SiGR-Bond tests: bond verify, measurement verify, breach math, settlement reconcile.
import { SIGNER, verifyFn } from '../src/key.js';
import {
  signBond, verifyBond, signMeasurement, verifyMeasurement,
  computeBreach, signSettlement, verifySettlement,
} from '../src/bond.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;

const TERMS = {
  bond_id: 'bond-1', customer_ref: 'acme', service_ref: 'llama-70b-prod',
  window_start: '2026-06-01', window_end: '2026-06-30',
  latency_ceiling_ms: 500,        // calls over 500ms are "slow"
  uptime_floor_ppm: 990_000,      // 99.0% uptime floor
  slow_tolerance_ppm: 100_000,    // up to 10% of served calls may be slow
  penalty_micro_usd: 1_000_000,   // $1.00 payout on breach
};

function meas(id, latency, served = true, seq = 0) {
  return { bond_id: 'bond-1', request_id: id, observed_latency_ms: latency, served, seq };
}

section('bond: terms receipt happy path + tamper');
{
  const env = signBond(TERMS, SIGNER);
  ok(verifyBond(env, verifyFn, PUB).valid, 'bond verifies');
  const t = JSON.parse(JSON.stringify(env));
  t.terms.latency_ceiling_ms = 99999;     // loosen the ceiling after signing
  ok(!verifyBond(t, verifyFn, PUB).valid, 'loosened ceiling rejected');
}

section('bond: measurement receipt happy path + tamper');
{
  const env = signMeasurement(meas('r1', 320), SIGNER);
  ok(verifyMeasurement(env, verifyFn, PUB).valid, 'measurement verifies');
  const t = JSON.parse(JSON.stringify(env));
  t.measurement.observed_latency_ms = 10;  // shave a slow call to look fast
  ok(!verifyMeasurement(t, verifyFn, PUB).valid, 'latency shave rejected');
}

section('bond: breach math (pure)');
{
  // 10 served calls, 1 slow (10%) -> at tolerance, NOT over -> no latency breach
  const within = Array.from({ length: 10 }, (_, i) => meas('r' + i, i === 0 ? 900 : 100));
  const b1 = computeBreach(TERMS, within.map(m => ({ ...m })));
  eq(b1.slow_requests, 1, 'one slow call counted');
  eq(b1.observed_slow_ppm, 100_000, 'slow ppm = 10%');
  ok(!b1.latency_breach, '10% slow == tolerance, not a breach');
  ok(!b1.breached, 'no breach within terms');

  // 10 served, 2 slow (20%) -> over 10% tolerance -> latency breach
  const over = Array.from({ length: 10 }, (_, i) => meas('r' + i, i < 2 ? 900 : 100));
  const b2 = computeBreach(TERMS, over.map(m => ({ ...m })));
  ok(b2.latency_breach, '20% slow > tolerance -> latency breach');
  ok(b2.breached, 'breached');
  eq(b2.payout_micro_usd, TERMS.penalty_micro_usd, 'payout owed on breach');

  // uptime breach: 100 calls, 5 unserved (95% uptime) < 99% floor
  const downs = Array.from({ length: 100 }, (_, i) => meas('r' + i, 100, i >= 95 ? false : true));
  const b3 = computeBreach(TERMS, downs.map(m => ({ ...m })));
  ok(b3.uptime_breach, '95% uptime < 99% floor -> uptime breach');
  eq(b3.observed_uptime_ppm, 950_000, 'uptime ppm correct');
}

section('bond: settlement reconciliation');
{
  const bondEnv = signBond(TERMS, SIGNER);
  // 10 calls, 2 slow -> breach
  const ms = Array.from({ length: 10 }, (_, i) => signMeasurement(meas('r' + i, i < 2 ? 900 : 100, true, i), SIGNER));
  const settle = signSettlement(bondEnv, ms, SIGNER);

  const good = verifySettlement(settle, bondEnv, ms, verifyFn, PUB);
  ok(good.valid, 'honest settlement reconciles; reasons=' + good.reasons.join(','));
  ok(good.signed_breached === true && good.recomputed_breached === true, 'breach agreed both sides');

  // provider hides a slow measurement from the window it settled on
  const hidden = ms.filter((_, i) => i !== 0); // drop one of the slow ones
  const bad = verifySettlement(settle, bondEnv, hidden, verifyFn, PUB);
  ok(!bad.valid, 'dropped slow call detected');
  ok(bad.reasons.includes('window_root_mismatch_vs_customer_measurements') ||
     bad.reasons.includes('measurement_count_mismatch'), 'hide flagged: ' + bad.reasons.join(','));

  // provider understates the breach (claims no payout) -> recomputation catches it
  const t = JSON.parse(JSON.stringify(settle));
  t.breached = false; t.payout_micro_usd = 0;
  const understated = verifySettlement(t, bondEnv, ms, verifyFn, PUB);
  ok(!understated.valid, 'understated breach detected');
}

summary('bond');

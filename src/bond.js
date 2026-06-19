/**
 * bond.js — SiGR-Bond: signed SLA terms + cryptographic breach detection.
 *
 * Survey convergence: 5 of 7 models independently proposed SLA-settlement-on-Base
 * (C3 — "pay if slow"). Clearest procurement pain in the survey: every enterprise
 * AI contract has latency/uptime language, NONE of it is machine-enforceable today.
 *
 * What it proves: an SLA (latency ceiling, uptime floor, measurement window) is
 * bound into a signed BOND receipt up front. Each served request emits a signed
 * MEASUREMENT receipt carrying the honest, attested latency for that call. At
 * window close, the bond + the window's measurements are reconciled by an
 * independent verifier that recomputes the breach math — pay-if-slow becomes a
 * cryptographic fact, not a vendor dashboard claim.
 *
 * Trust model: zero-secret verification. The customer needs only the published
 * ML-DSA-65 public key. The breach determination is recomputed from signed
 * measurements the customer collected themselves — the provider cannot drop a
 * slow call without breaking the window root.
 *
 * Honest-clock note (survey Signal B / build risk in synthesis §4): the latency
 * value in each measurement is the field a dishonest provider would shave. We bind
 * an OPTIONAL temporal proof slot (same primitive typed.js uses) so the timestamp
 * can be HW-attested where available; absent that, the measurement still binds the
 * provider's asserted latency under signature, making it non-repudiable after the
 * fact even if not independently sourced. Full HW-PTP attestation is the Tier-3
 * upgrade path, not a v1 blocker.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, the bind-one-payload
 * pattern, SIGNER/verifyFn — identical discipline to typed.js + bill.js.
 *
 * Patent Pending HC-2026-005 (HW-attested SLA enforcement coupling signed
 * per-request latency to deterministic on-chain breach settlement). Internal
 * docket only — never emit in public artifacts.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// ---- SLA terms (the bond) ----------------------------------------------------
// Integer units throughout to avoid float drift in breach math:
//   latency_ceiling_ms       — per-request ceiling; a call over this is a "slow" call
//   uptime_floor_ppm         — uptime floor in parts-per-million (e.g. 999_000 = 99.9%)
//   slow_tolerance_ppm       — fraction of calls allowed to exceed the ceiling
//   penalty_micro_usd        — payout owed to customer if the window breaches
export function buildBondTerms(terms, suite) {
  const s = suite || resolveSuite('sha-256');
  return {
    object: 'sigr.bond.terms',
    bond_id: terms.bond_id,
    customer_ref: terms.customer_ref || 'unspecified',
    service_ref: terms.service_ref || 'unspecified',
    window_start: terms.window_start,
    window_end: terms.window_end,
    latency_ceiling_ms: terms.latency_ceiling_ms | 0,
    uptime_floor_ppm: terms.uptime_floor_ppm | 0,
    slow_tolerance_ppm: terms.slow_tolerance_ppm | 0,
    penalty_micro_usd: terms.penalty_micro_usd | 0,
  };
}

/**
 * signBond — sign the SLA terms up front. Binds:
 *   base || terms_digest -> one payload -> one ML-DSA-65 sig.
 * This is the commitment the provider cannot later edit.
 */
export function signBond(terms, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const bondTerms = buildBondTerms(terms, suite);
  const termsDigest = hashHex(canonicalize(bondTerms), suite);

  const baseFields = {
    object: 'sigr.bond.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(termsDigest), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const sigBytes = signer.sign(hexToBytes(payloadHex));

  const envelope = {
    ...baseFields,
    terms: bondTerms,
    terms_digest: termsDigest,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  return envelope;
}

export function verifyBond(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  const termsDigest = hashHex(canonicalize(envelope.terms), suite);
  if (termsDigest !== envelope.terms_digest) reasons.push('terms_digest_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(termsDigest), dl);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== envelope.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(envelope.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return { valid: reasons.length === 0, reasons };
}

// ---- per-request measurements ------------------------------------------------
export function buildMeasurement(m, suite) {
  const s = suite || resolveSuite('sha-256');
  return {
    object: 'sigr.bond.measurement',
    bond_id: m.bond_id,
    request_id: m.request_id,
    observed_latency_ms: m.observed_latency_ms | 0,
    served: m.served === false ? false : true,   // false = request failed / not served (uptime miss)
    seq: m.seq | 0,
  };
}

/**
 * signMeasurement — one signed receipt per served request, carrying the attested
 * latency for that call. Binds:
 *   base || measurement_digest [|| temporal] -> one payload -> one ML-DSA-65 sig.
 * Optional temporal slot lets an HW-attested timestamp be bound (Signal B).
 */
export function signMeasurement(m, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);
  const temporal = opts.temporal || null;

  const meas = buildMeasurement(m, suite);
  const measDigest = hashHex(canonicalize(meas), suite);

  const baseFields = {
    object: 'sigr.bond.measure_receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const temporalDigest = temporal ? hashHex(canonicalize(temporal), suite) : zero;

  const slots = temporal ? 3 : 2;
  const bind = new Uint8Array(dl * slots);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(measDigest), dl);
  if (temporal) bind.set(hexToBytes(temporalDigest), dl * 2);
  const payloadHex = bytesToHex(suite.fn(bind));

  const sigBytes = signer.sign(hexToBytes(payloadHex));

  const envelope = {
    ...baseFields,
    measurement: meas,
    measurement_digest: measDigest,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  if (temporal) envelope.temporal = temporal;
  if (signer.trust) envelope.trust = signer.trust;
  return envelope;
}

export function verifyMeasurement(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);

  const measDigest = hashHex(canonicalize(envelope.measurement), suite);
  if (measDigest !== envelope.measurement_digest) reasons.push('measurement_digest_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const hasTemporal = !!envelope.temporal;
  const temporalDigest = hasTemporal ? hashHex(canonicalize(envelope.temporal), suite) : zero;

  const slots = hasTemporal ? 3 : 2;
  const bind = new Uint8Array(dl * slots);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(measDigest), dl);
  if (hasTemporal) bind.set(hexToBytes(temporalDigest), dl * 2);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== envelope.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(envelope.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return { valid: reasons.length === 0, reasons };
}

// ---- breach math (pure, deterministic — the on-chain settlement function) ----
/**
 * computeBreach — the deterministic settlement function. Given the bond terms and
 * the window's measurements, returns the breach determination + payout. Same code
 * runs provider-side, customer-side, and (conceptually) on-chain — everyone gets
 * the identical answer from the identical inputs.
 */
export function computeBreach(terms, measurements) {
  const total = measurements.length;
  const served = measurements.filter(m => m.served !== false).length;
  const slow = measurements.filter(m => m.served !== false && m.observed_latency_ms > terms.latency_ceiling_ms).length;

  // ppm arithmetic, integer-safe
  const observed_uptime_ppm = total === 0 ? 0 : Math.floor((served * 1_000_000) / total);
  const observed_slow_ppm = served === 0 ? 0 : Math.floor((slow * 1_000_000) / served);

  const uptime_breach = observed_uptime_ppm < terms.uptime_floor_ppm;
  const latency_breach = observed_slow_ppm > terms.slow_tolerance_ppm;
  const breached = uptime_breach || latency_breach;

  return {
    total_requests: total,
    served_requests: served,
    slow_requests: slow,
    observed_uptime_ppm,
    observed_slow_ppm,
    uptime_breach,
    latency_breach,
    breached,
    payout_micro_usd: breached ? (terms.penalty_micro_usd | 0) : 0,
  };
}

/**
 * signSettlement — at window close, the provider rolls up the window's signed
 * measurement digests into a Merkle window root, computes the breach, and signs
 * the settlement. The customer reconciles the window root against their OWN
 * collected measurement receipts (a dropped slow call changes the root).
 */
export function signSettlement(bondEnv, measurementEnvelopes, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());

  const leaves = measurementEnvelopes.map(e => e.payload_digest).sort();
  const windowRoot = merkleRoot(leaves, suite);
  const measurements = measurementEnvelopes.map(e => e.measurement);
  const breach = computeBreach(bondEnv.terms, measurements);

  const baseFields = {
    object: 'sigr.bond.settlement',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    bond_id: bondEnv.terms.bond_id,
    bond_digest: bondEnv.terms_digest,
    window_root: windowRoot,
    measurement_count: measurementEnvelopes.length,
    breached: breach.breached,
    payout_micro_usd: breach.payout_micro_usd,
  };
  const payloadHex = hashHex(canonicalize(baseFields), suite);
  const sigBytes = signer.sign(hexToBytes(payloadHex));

  const envelope = {
    ...baseFields,
    breach_detail: breach,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  return envelope;
}

/**
 * verifySettlement — customer-side reconciliation. Recomputes the window root
 * from the customer's OWN measurement receipts, RE-RUNS the breach math from
 * those measurements, and checks both match the signed settlement + signature.
 * A provider cannot understate a breach or hide a slow call.
 */
export function verifySettlement(settlementEnv, bondEnv, customerMeasurements, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (settlementEnv.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }

  const baseFields = {
    object: settlementEnv.object,
    version: settlementEnv.version,
    sig_scheme: settlementEnv.sig_scheme,
    public_key: settlementEnv.public_key,
    bond_id: settlementEnv.bond_id,
    bond_digest: settlementEnv.bond_digest,
    window_root: settlementEnv.window_root,
    measurement_count: settlementEnv.measurement_count,
    breached: settlementEnv.breached,
    payout_micro_usd: settlementEnv.payout_micro_usd,
  };
  const payloadHex = hashHex(canonicalize(baseFields), suite);
  if (payloadHex !== settlementEnv.payload_digest) reasons.push('payload_digest_mismatch');

  // settlement must reference the bond the customer holds
  if (bondEnv && settlementEnv.bond_digest !== bondEnv.terms_digest) reasons.push('bond_digest_mismatch');

  // reconcile window root from the customer's own measurement receipts
  const leaves = customerMeasurements.map(e => e.payload_digest).sort();
  const recomputedRoot = merkleRoot(leaves, suite);
  if (recomputedRoot !== settlementEnv.window_root) reasons.push('window_root_mismatch_vs_customer_measurements');
  if (customerMeasurements.length !== settlementEnv.measurement_count) reasons.push('measurement_count_mismatch');

  // RE-RUN the breach math from the customer's measurements
  const measurements = customerMeasurements.map(e => e.measurement);
  const recomputedBreach = computeBreach(bondEnv.terms, measurements);
  if (recomputedBreach.breached !== settlementEnv.breached) reasons.push('breach_determination_mismatch');
  if (recomputedBreach.payout_micro_usd !== settlementEnv.payout_micro_usd) reasons.push('payout_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(settlementEnv.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return {
    valid: reasons.length === 0,
    reasons,
    signed_breached: settlementEnv.breached,
    recomputed_breached: recomputedBreach.breached,
    payout_micro_usd: settlementEnv.payout_micro_usd,
  };
}

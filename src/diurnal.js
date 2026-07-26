/**
 * diurnal.js — Diurnal Bond.
 *
 * HC-2026-020. Temporal-risk bonding. Raises the required proof-state
 * for consequential actions during declared low-oversight windows.
 *
 * Novel core: THRESHOLD-SIGNATURE DYNAMIC ESCALATION.
 * Consequential actions in elevated regimes require a k-of-n threshold
 * signature across geographically distributed attestors — not just an
 * extra receipt. The k is dynamically computed from a signed risk
 * manifold that maps (time-of-day, day-of-week, holiday, declared
 * incident tempo) to a required-attestor-count. Weekend 3 AM might
 * require 4-of-7 attestors across three continents; weekday-noon
 * routine might require 1-of-3. The manifold is published in advance,
 * so gaming the clock is impossible.
 *
 * Two receipt types:
 *
 *   diurnal.regime — issued when a run enters a declared regime.
 *     Binds: regime ('on_call' | 'business_hours' | 'weekend' |
 *     'after_hours' | 'maintenance' | 'incident_active'),
 *     risk_manifold_digest, required_k, total_n, attestor_kid_set,
 *     regime_start_ts, regime_end_ts.
 *
 *   diurnal.attestation — issued per attestor countersign.
 *     Binds: regime_ref, attestor_kid, attestor_geo_region,
 *     countersign_ts, action_class ('inference' | 'tool_call' |
 *     'egress' | 'model_swap' | 'policy_change'). Verifier confirms
 *     that at least k distinct attestors have countersigned within the
 *     freshness window before Carnac Gateway allows the action.
 *
 * Patent Pending HC-2026-020 (a method for dynamically computing a
 * required-threshold-attestor-count from a signed temporal-risk
 * manifold and enforcing a k-of-n distributed threshold-signature
 * requirement on consequential autonomous-agent actions during
 * declared low-oversight windows, wherein the manifold is published
 * in advance and cryptographically bound to each regime receipt).
 */

import { canonicalize, hashHex, resolveSuite } from './typed.js';
import { signUpstreamReceipt, verifyUpstreamReceipt } from './upstream.js';

const TYPE_REGIME = 'diurnal.regime';
const TYPE_ATTESTATION = 'diurnal.attestation';

/**
 * Sample risk manifold — canonical, deterministic lookup:
 * (regime, action_class) -> required_k
 */
export const DEFAULT_RISK_MANIFOLD = {
  business_hours: { inference: 0, tool_call: 1, egress: 1, model_swap: 2, policy_change: 2 },
  on_call:        { inference: 0, tool_call: 1, egress: 2, model_swap: 2, policy_change: 3 },
  after_hours:    { inference: 1, tool_call: 2, egress: 3, model_swap: 3, policy_change: 4 },
  weekend:        { inference: 1, tool_call: 2, egress: 3, model_swap: 3, policy_change: 4 },
  maintenance:    { inference: 2, tool_call: 3, egress: 4, model_swap: 4, policy_change: 5 },
  incident_active:{ inference: 2, tool_call: 4, egress: 5, model_swap: 5, policy_change: 6 },
};

export function riskManifoldDigest(manifold, suite) {
  const s = suite || resolveSuite('sha-256');
  return hashHex(canonicalize(manifold), s);
}

export function computeRequiredK(regime, action_class, manifold) {
  const mf = manifold || DEFAULT_RISK_MANIFOLD;
  const row = mf[regime] || {};
  return Number.isInteger(row[action_class]) ? row[action_class] : 1;
}

/** signDiurnalRegime — issued when a run enters a regime. */
export function signDiurnalRegime(r, signer, opts = {}) {
  if (!r.regime) throw new Error('missing_regime');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const manifold = r.risk_manifold || DEFAULT_RISK_MANIFOLD;
  const required_k = computeRequiredK(r.regime, r.action_class || 'inference', manifold);
  const payload = {
    regime: r.regime,
    action_class: r.action_class || 'inference',
    risk_manifold_digest: riskManifoldDigest(manifold, suite),
    required_k,
    total_n: (r.attestor_kid_set || []).length,
    attestor_kid_set: r.attestor_kid_set || [],
    regime_start_ts: r.regime_start_ts,
    regime_end_ts: r.regime_end_ts,
  };
  return signUpstreamReceipt(TYPE_REGIME, payload, {
    run_id: r.run_id, tenant_id: r.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/** signDiurnalAttestation — issued per attestor countersign. */
export function signDiurnalAttestation(a, signer, opts = {}) {
  if (!a.regime_ref) throw new Error('missing_regime_ref');
  if (!a.attestor_kid) throw new Error('missing_attestor');
  const payload = {
    regime_ref: a.regime_ref,
    attestor_kid: a.attestor_kid,
    attestor_geo_region: a.attestor_geo_region,
    countersign_ts: a.countersign_ts,
    action_class: a.action_class,
  };
  return signUpstreamReceipt(TYPE_ATTESTATION, payload, {
    run_id: a.run_id, tenant_id: a.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/**
 * verifyDiurnalThresholdSatisfied — the coupling call: given a regime
 * receipt + a set of attestation receipts, confirm that k distinct
 * attestors from the regime's attestor_kid_set have countersigned
 * within the freshness window. Returns { ok, distinct_attestors, k_required }.
 */
export function verifyDiurnalThresholdSatisfied(regime, attestations, verifyFn, pubBytes, opts = {}) {
  const rOk = verifyUpstreamReceipt(regime, TYPE_REGIME, verifyFn, pubBytes, opts);
  if (!rOk.ok) return { ok: false, reason: 'regime_' + rOk.reason };
  const allowed = new Set(regime.payload.attestor_kid_set);
  const distinct = new Set();
  for (const a of attestations) {
    const aOk = verifyUpstreamReceipt(a, TYPE_ATTESTATION, verifyFn, pubBytes, opts);
    if (!aOk.ok) continue;
    if (a.payload.regime_ref !== regime.receipt_id) continue;
    if (!allowed.has(a.payload.attestor_kid)) continue;
    distinct.add(a.payload.attestor_kid);
  }
  const k = regime.payload.required_k;
  return {
    ok: distinct.size >= k,
    distinct_attestors: distinct.size,
    k_required: k,
    reason: distinct.size >= k ? undefined : 'insufficient_threshold',
  };
}

export const verifyDiurnalRegime = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_REGIME, v, pk, o);
export const verifyDiurnalAttestation = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_ATTESTATION, v, pk, o);

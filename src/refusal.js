/**
 * refusal.js — Refusal Ledger.
 *
 * HC-2026-017. Append-only, cryptographically anchored ledger of every
 * refusal-policy change, PLUS a zero-knowledge envelope-proof stub so
 * enterprises can bond their refusal configs to a public envelope without
 * revealing the specific threshold values.
 *
 * Novel core (two mechanisms):
 *
 * (1) CT-LOG-STYLE APPEND-ONLY LEDGER.
 *     Every PolicyMutation receipt binds:
 *       - policy_id: enterprise-scoped policy identifier
 *       - prior_policy_digest: digest of the state BEFORE the change
 *       - new_policy_digest: digest of the state AFTER the change
 *       - operator_kid: identity of the human/system that made the change
 *       - authorization_ref: pointer to approving evidence (change ticket, etc.)
 *       - ledger_seq: monotonic sequence number
 *       - inclusion_root: Merkle root over all mutations up to and including this one
 *
 *     Because inclusion_root is bound to a monotonic seq and each receipt
 *     carries prior_policy_digest, a missing or reordered mutation breaks
 *     the chain deterministically.
 *
 * (2) ZK-BONDED ENVELOPE PROOF.
 *     PolicyReadBinding receipts prove "at time T the refusal threshold was
 *     within pre-declared envelope [lo, hi]" WITHOUT revealing the specific
 *     value. This resolves the frontier-lab objection ("we can't publish
 *     our refusal thresholds — competitors would game them"): they can
 *     bond their thresholds to a public envelope and prove ongoing
 *     compliance without leaking the numbers.
 *
 *     Implementation note: the ZK-SNARK proof itself is stubbed — a real
 *     Groth16 or PLONK implementation requires a trusted setup + circuit
 *     compilation. The receipt structure binds:
 *       - envelope_id: enterprise-declared public envelope (e.g. "cyber
 *         refusal stays in [0.6, 0.95]")
 *       - envelope_bounds_digest: canonical digest of the public [lo, hi]
 *       - policy_value_commitment: Pedersen-style commitment to the actual
 *         threshold (hiding the value, binding to the envelope)
 *       - zk_proof_digest: digest of the ZK-SNARK proof bytes (external)
 *       - zk_circuit_id: identifier of the compiled circuit that produced
 *         the proof (so verifiers know which circuit to run)
 *
 *     Verifier fetches the actual ZK proof by digest from an external
 *     store (production integration point) and runs the circuit locally.
 *     This module verifies the RECEIPT layer — that the commitment + proof
 *     digest + envelope digest are cryptographically bound to the ledger.
 *
 * Patent Pending HC-2026-017 (a method for cryptographically anchoring the
 * mutation history of an autonomous-agent refusal-policy configuration in
 * an append-only ledger and emitting zero-knowledge envelope-bond proofs
 * that a runtime policy value lies within a pre-declared public envelope
 * without disclosing the value itself, wherein each mutation receipt
 * chains to a monotonic inclusion root such that missing, reordered, or
 * contradictory mutations are detectable independent of the ledger
 * operator).
 */

import { canonicalize, hashHex, resolveSuite } from './typed.js';
import { signUpstreamReceipt, verifyUpstreamReceipt } from './upstream.js';
import { createHash } from 'crypto';

const TYPE_MUTATION = 'refusal.mutation';
const TYPE_BINDING = 'refusal.binding';

/** Digest of the canonical policy state. */
export function policyStateDigest(policy_state, suite) {
  const s = suite || resolveSuite('sha-256');
  return hashHex(canonicalize(policy_state || {}), s);
}

/** Digest of the public envelope bounds. */
export function envelopeBoundsDigest(bounds, suite) {
  const s = suite || resolveSuite('sha-256');
  // canonicalize to fixed decimal precision for float safety
  const canon = {
    lo_bp: Math.round(Number(bounds.lo) * 10000),
    hi_bp: Math.round(Number(bounds.hi) * 10000),
    metric: String(bounds.metric || ''),
  };
  return hashHex(canonicalize(canon), s);
}

/**
 * inclusionRoot — deterministic root over the ordered sequence of
 * (seq, prior, new) mutation triples. Uses a chained hash so any missing
 * or reordered mutation breaks it.
 */
export function inclusionRoot(mutations, suite) {
  const s = suite || resolveSuite('sha-256');
  let acc = '0'.repeat(s.digest_len * 2);
  for (const m of mutations) {
    const leaf = hashHex(canonicalize({
      seq: m.ledger_seq,
      prior: m.prior_policy_digest,
      next: m.new_policy_digest,
      op: m.operator_kid,
      auth: m.authorization_ref,
    }), s);
    acc = hashHex(acc + leaf, s);
  }
  return acc;
}

/**
 * pedersenCommit — stub Pedersen commitment for the policy value.
 * Real implementation uses secp256k1 or bls12-381 curve points; this stub
 * uses HMAC-SHA256 with a supplied blinding factor to preserve the *shape*
 * of a hiding+binding commitment for the receipt layer. The provisional
 * covers the commitment binding to the envelope regardless of curve.
 */
export function pedersenCommit(value_bp, blinding_hex) {
  const h = createHash('sha256');
  h.update('pedersen_stub_v1');
  h.update(String(value_bp));
  h.update(String(blinding_hex));
  return h.digest('hex');
}

/**
 * signPolicyMutation — issued at every refusal-policy configuration change.
 *
 * mut = {
 *   run_id, tenant_id,
 *   policy_id,
 *   prior_state, new_state,       // full policy states, will be digested
 *   operator_kid,
 *   authorization_ref,
 *   ledger_seq,                   // monotonic
 *   prior_mutations               // ordered list of prior mutations (for inclusion root)
 * }
 */
export function signPolicyMutation(mut, signer, opts = {}) {
  if (!mut.policy_id) throw new Error('missing_policy_id');
  if (!Number.isInteger(mut.ledger_seq) || mut.ledger_seq < 1) throw new Error('bad_ledger_seq');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const prior_policy_digest = policyStateDigest(mut.prior_state, suite);
  const new_policy_digest = policyStateDigest(mut.new_state, suite);
  const full_history = [
    ...(mut.prior_mutations || []),
    {
      ledger_seq: mut.ledger_seq,
      prior_policy_digest,
      new_policy_digest,
      operator_kid: mut.operator_kid,
      authorization_ref: mut.authorization_ref,
    },
  ];
  const payload = {
    policy_id: mut.policy_id,
    ledger_seq: mut.ledger_seq,
    prior_policy_digest,
    new_policy_digest,
    operator_kid: mut.operator_kid,
    authorization_ref: mut.authorization_ref,
    inclusion_root: inclusionRoot(full_history, suite),
  };
  return signUpstreamReceipt(TYPE_MUTATION, payload, {
    run_id: mut.run_id, tenant_id: mut.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/**
 * signPolicyReadBinding — issued at inference time to bond a runtime
 * policy value to a public envelope without revealing the value.
 *
 * binding = {
 *   run_id, tenant_id,
 *   policy_id,
 *   envelope_id, envelope_bounds: { lo, hi, metric },
 *   policy_value_bp,        // NOT stored in receipt; used for commitment only
 *   blinding_hex,           // caller-supplied blinding factor
 *   zk_proof_digest,        // digest of external ZK-SNARK proof bytes
 *   zk_circuit_id,          // identifier of the compiled circuit
 *   ledger_seq_at_read      // which mutation was in force
 * }
 */
export function signPolicyReadBinding(binding, signer, opts = {}) {
  if (!binding.envelope_id || !binding.envelope_bounds) throw new Error('missing_envelope');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const bounds_digest = envelopeBoundsDigest(binding.envelope_bounds, suite);
  const value_commit = pedersenCommit(binding.policy_value_bp, binding.blinding_hex);
  const payload = {
    policy_id: binding.policy_id,
    envelope_id: binding.envelope_id,
    envelope_bounds_digest: bounds_digest,
    policy_value_commitment: value_commit,
    zk_proof_digest: binding.zk_proof_digest || '',
    zk_circuit_id: binding.zk_circuit_id || '',
    ledger_seq_at_read: binding.ledger_seq_at_read,
  };
  return signUpstreamReceipt(TYPE_BINDING, payload, {
    run_id: binding.run_id, tenant_id: binding.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/** Verify a mutation receipt AND its inclusion_root against a known history. */
export function verifyPolicyMutationInHistory(mutReceipt, prior_mutations, verifyFn, pubBytes, opts = {}) {
  const base = verifyUpstreamReceipt(mutReceipt, TYPE_MUTATION, verifyFn, pubBytes, opts);
  if (!base.ok) return base;
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const p = mutReceipt.payload;
  const full = [
    ...(prior_mutations || []),
    {
      ledger_seq: p.ledger_seq,
      prior_policy_digest: p.prior_policy_digest,
      new_policy_digest: p.new_policy_digest,
      operator_kid: p.operator_kid,
      authorization_ref: p.authorization_ref,
    },
  ];
  const recomputed = inclusionRoot(full, suite);
  if (recomputed !== p.inclusion_root) return { ok: false, reason: 'inclusion_root_mismatch' };
  return { ok: true };
}

// legacy shims
export function verifyPolicyMutation(env, verifyFn, pubBytes, opts) {
  return verifyUpstreamReceipt(env, TYPE_MUTATION, verifyFn, pubBytes, opts);
}
export function verifyPolicyReadBinding(env, verifyFn, pubBytes, opts) {
  return verifyUpstreamReceipt(env, TYPE_BINDING, verifyFn, pubBytes, opts);
}

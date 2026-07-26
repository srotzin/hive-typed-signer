/**
 * forensic.js — Forensic Rail.
 *
 * HC-2026-022. Bonded consortium credential + deterministic sandboxed
 * re-execution rail for post-incident analysis. Solves the problem the
 * OpenAI-Hugging-Face incident surfaced: commercial frontier-model APIs
 * refused to analyze the attacker payloads, so HF had to fall back to
 * open-weight GLM 5.2.
 *
 * Novel core (two mechanisms):
 *
 * (1) K-OF-N CONSORTIUM THRESHOLD CREDENTIAL.
 *     A credential minted by a consortium root (industry ISAC-style) via
 *     a k-of-n threshold signature. The credential is scoped to a
 *     specific incident_case_id, valid for a specific time window, and
 *     cryptographically bound to the incident's ticket chain.
 *
 * (2) DETERMINISTIC REPLAY BOND.
 *     Analysis under a Forensic Rail credential runs inside a
 *     deterministic sandbox that pins model seed, temperature (0), KV-
 *     cache init, and token sampler. Every model call is captured as
 *     a replayable receipt binding {model_ref, seed, temperature,
 *     top_p, prompt_digest, output_digest, kv_cache_digest}. A court,
 *     regulator, or independent responder can later RE-EXECUTE the
 *     entire analysis from the receipt chain and verify byte-identical
 *     outputs. Guardrail bypass becomes not just bonded but fully
 *     reproducible.
 *
 * Two receipt types:
 *
 *   forensic.credential — minted by consortium root.
 *     Binds: incident_case_id, ticket_chain_ref, scope
 *     ('analyze_only' | 'analyze_and_generate'), no_execute (bool),
 *     no_generate_novel (bool), valid_from_ts, valid_until_ts,
 *     consortium_root_kid, threshold_k, total_n,
 *     consortium_signers[] (the k attestors who signed the mint).
 *
 *   forensic.analysis — per model call under the credential.
 *     Binds: credential_ref, model_ref (deterministic-mode identifier),
 *     seed, temperature_bp (integer basis points, e.g. 0), top_p_bp,
 *     prompt_digest, output_digest, kv_cache_digest, responder_kid,
 *     replay_hint (data needed to reproduce byte-identically).
 *
 * Patent Pending HC-2026-022 (a method for bonded post-incident analysis
 * of an autonomous-agent execution incident via a k-of-n consortium-
 * threshold-signed credential that scopes guardrail-bypass privileges
 * to a specific incident case, and further wherein each model call
 * under the credential is captured as a deterministic-replay receipt
 * binding seed, sampler configuration, and inputs such that any third
 * party can byte-identically reproduce the analysis output).
 */

import { canonicalize, hashHex, resolveSuite } from './typed.js';
import { signUpstreamReceipt, verifyUpstreamReceipt } from './upstream.js';

const TYPE_CREDENTIAL = 'forensic.credential';
const TYPE_ANALYSIS = 'forensic.analysis';

/**
 * signForensicCredential — minted by the consortium root. In production
 * the underlying signature would be a threshold BLS/FROST aggregate; at
 * the receipt layer we bind the k threshold signers into the payload so
 * the receipt records "which k of n countersigned" even though the
 * outer ML-DSA-65 signature is a single aggregate.
 *
 * c = {
 *   run_id, tenant_id,
 *   incident_case_id, ticket_chain_ref,
 *   scope, no_execute, no_generate_novel,
 *   valid_from_ts, valid_until_ts,
 *   consortium_root_kid, threshold_k, total_n,
 *   consortium_signers: [{ kid, geo_region, countersign_ts }...]
 * }
 */
export function signForensicCredential(c, signer, opts = {}) {
  if (!c.incident_case_id) throw new Error('missing_incident');
  if (!Number.isInteger(c.threshold_k) || c.threshold_k < 1) throw new Error('bad_threshold_k');
  if (!Array.isArray(c.consortium_signers) || c.consortium_signers.length < c.threshold_k) {
    throw new Error('insufficient_signers');
  }
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const payload = {
    incident_case_id: c.incident_case_id,
    ticket_chain_ref: c.ticket_chain_ref,
    scope: c.scope || 'analyze_only',
    no_execute: c.no_execute !== false,
    no_generate_novel: c.no_generate_novel !== false,
    valid_from_ts: c.valid_from_ts,
    valid_until_ts: c.valid_until_ts,
    consortium_root_kid: c.consortium_root_kid,
    threshold_k: c.threshold_k,
    total_n: c.total_n,
    consortium_signers: [...c.consortium_signers].sort((a, b) => a.kid.localeCompare(b.kid)),
    signers_digest: hashHex(canonicalize({
      signers: [...c.consortium_signers].map(s => s.kid).sort()
    }), suite),
  };
  return signUpstreamReceipt(TYPE_CREDENTIAL, payload, {
    run_id: c.run_id, tenant_id: c.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/**
 * signForensicAnalysis — per model call under the credential.
 * a = { run_id, tenant_id, credential_ref, model_ref, seed,
 *       temperature_bp, top_p_bp, prompt_digest, output_digest,
 *       kv_cache_digest, responder_kid, replay_hint }
 */
export function signForensicAnalysis(a, signer, opts = {}) {
  if (!a.credential_ref) throw new Error('missing_credential_ref');
  if (!a.prompt_digest || !a.output_digest) throw new Error('missing_digests');
  if (a.temperature_bp !== 0) {
    // Deterministic replay requires temperature == 0. Non-zero is a
    // programming error at this layer; the receipt still emits with a
    // deterministic_replay: false flag to be honest about what was signed.
  }
  const payload = {
    credential_ref: a.credential_ref,
    model_ref: a.model_ref,
    seed: a.seed,
    temperature_bp: a.temperature_bp,
    top_p_bp: a.top_p_bp,
    prompt_digest: a.prompt_digest,
    output_digest: a.output_digest,
    kv_cache_digest: a.kv_cache_digest,
    responder_kid: a.responder_kid,
    replay_hint: a.replay_hint || {},
    deterministic_replay: (a.temperature_bp === 0),
  };
  return signUpstreamReceipt(TYPE_ANALYSIS, payload, {
    run_id: a.run_id, tenant_id: a.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

export const verifyForensicCredential = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_CREDENTIAL, v, pk, o);
export const verifyForensicAnalysis = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_ANALYSIS, v, pk, o);

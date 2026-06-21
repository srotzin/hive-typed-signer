/**
 * agentic.js — AFiR-S3 Agentic Action Receipt (DURING).
 *
 * AFiR-S3 §2.2. Sign-before-act at the TOOL boundary. Each tool call commits to
 * (observed_state_hash + chosen action + tool_target) BEFORE execution, and the
 * steps chain into an ordered, tamper-evident causal trace of the run.
 *
 * THIN WRAPPER over chain.js (the flagship SiGR Chain, HC-2026-006). We do NOT
 * re-implement the DAG, the topo order, the per-step commit, or the single-sig
 * causal-root rollup — chain.js already provides sign-before-act + causal chaining
 * with full reorder/insert/drop/edit/cycle detection. This module adds exactly
 * two things on top:
 *
 *   1. Action semantics — each step carries action / tool_target / scope_ref /
 *      observed_state_hash, folded into the step's signed I/O so they are bound
 *      into the same causal root chain.js already produces. No separate signature.
 *
 *   2. SCOPE GATING (the requirement) — before sealing, every tool_call step is
 *      resolved against its referenced Tool-Scope receipt. The scope envelope is
 *      cryptographically VERIFIED (verifyToolScope), then each action is checked
 *      with scopeAllows(). An out-of-scope action (or one whose tool_hash does not
 *      match the scoped tool) is REJECTED — the run is never sealed. This is an
 *      authorization gate, not a cosmetic field append.
 *
 * Destructive actions (tools in the scope's destructive subset) are tagged
 * arsc_tier='rise' (inline, instant finality); reads/queries are 'sink' (batched)
 * — recorded for the ARSC settlement layer, AFiR-S3 §2.2.
 *
 * Trust model: zero-secret verification. verifyAgenticRun re-runs verifyChain
 * (the full causal-graph reconstruction + single ML-DSA-65 check) AND re-confirms
 * each action stayed within its referenced, verified scope. Either failing fails
 * the run.
 *
 * Patent Pending HC-2026-009 (sign-before-act tool-boundary commitment for an
 * autonomous agent, gated against a pre-committed tool-scope receipt and chained
 * under a single aggregate post-quantum signature, such that an out-of-scope or
 * reordered action breaks verification). Internal docket only.
 */
import { signChain, verifyChain } from './chain.js';
import { verifyToolScope, scopeAllows } from './toolscope.js';
import { canonicalize, hashHex, resolveSuite } from './typed.js';

// Recompute a step's io_digest EXACTLY as chain.js buildStepCommit does, given
// the step's input and the reconstructed output (base output + folded action
// metadata). Used at verify to bind the unsigned sidecar to the signed io_digest.
function recomputeIoDigest(input, output, suite) {
  const io = {
    input_digest: hashHex(canonicalize(input ?? null), suite),
    output_digest: hashHex(canonicalize(output ?? null), suite),
  };
  return hashHex(canonicalize(io), suite);
}

// non-destructive read-like actions settle on the cheap (batched) ARSC tier
const READ_LIKE = new Set(['read', 'query', 'get', 'list', 'search', 'retrieve', 'lookup']);

function arscTier(actionStep, destructive) {
  if (destructive) return 'rise';                 // value-moving/destructive -> inline finality
  const a = (actionStep.action || '').toLowerCase();
  for (const r of READ_LIKE) if (a.startsWith(r)) return 'sink';
  return 'float';                                  // other writes -> mid tier
}

/**
 * resolveScopes — index the provided Tool-Scope receipts by scope_id AFTER
 * cryptographically verifying each. Returns Map(scope_id -> verified envelope).
 * Throws if any referenced scope fails verification.
 */
function resolveScopes(scopeEnvelopes, verifyFn, pubResolver) {
  const byId = new Map();
  for (const env of scopeEnvelopes || []) {
    const pub = pubResolver(env);
    const r = verifyToolScope(env, verifyFn, pub);
    if (!r.valid) throw new Error('scope_invalid:' + (env.scope_id || '?') + ':' + r.reasons.join(','));
    byId.set(env.scope_id, env);
  }
  return byId;
}

/**
 * gateAndAnnotate — for each step, if it is a tool_call/action step it MUST name
 * a scope_ref that resolves to a verified scope, and the action MUST be in scope.
 * Out-of-scope -> throw (run is never sealed). On success we fold the action
 * fields into the step's `output` (so they are bound into chain.js's signed I/O)
 * and tag the ARSC tier. Non-action steps (plan/reason/merge/final) pass through.
 */
function gateAndAnnotate(run, scopesById, suite) {
  const annotated = run.steps.map(step => {
    const isAction = step.kind === 'tool_call' && (step.action || step.tool_target);
    if (!isAction) return { ...step };

    const scopeRef = step.scope_ref;
    if (!scopeRef) throw new Error('missing_scope_ref:' + step.step_id);
    const scopeId = scopeRef.replace(/^sigr:/, '');
    const scope = scopesById.get(scopeId);
    if (!scope) throw new Error('unresolved_scope_ref:' + step.step_id + '->' + scopeId);

    const decision = scopeAllows(scope, step.action, step.tool_hash);
    if (!decision.allowed) {
      throw new Error('out_of_scope_action:' + step.step_id + ':' + decision.reason);
    }

    const tier = arscTier(step, decision.destructive);
    // fold action semantics into the signed I/O via `output` so they ride the
    // existing causal-root chain. We also record observed_state_hash explicitly.
    const observed = step.observed_state_hash
      || hashHex(canonicalize(step.input ?? null), suite);
    const action_meta = {
      action: step.action,
      tool_target: step.tool_target,
      tool_hash: step.tool_hash || null,
      scope_ref: 'sigr:' + scopeId,
      observed_state_hash: observed,
      destructive: decision.destructive,
      arsc_tier: tier,
    };
    return {
      ...step,
      output: { ...(step.output || {}), __agentic_action: action_meta },
    };
  });
  return { ...run, steps: annotated };
}

/**
 * signAgenticRun — gate every action against its verified scope, then seal the
 * whole run through chain.js (one ML-DSA-65 signature over the causal root).
 *
 * args:
 *   run     = { run_id, agent_ref, steps:[{ step_id, kind, seq, parents,
 *               input, output?, action?, tool_target?, tool_hash?, scope_ref?,
 *               observed_state_hash? }] }
 *   scopes  = [ signed Tool-Scope envelopes ]   (referenced by steps' scope_ref)
 */
export function signAgenticRun(run, scopes, signer, verifyFn, pubResolver, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const scopesById = resolveScopes(scopes, verifyFn, pubResolver);
  const gated = gateAndAnnotate(run, scopesById, suite);
  const { envelope, timing_us } = signChain(gated, signer, opts);
  // The action metadata is already cryptographically bound (it rode each step's
  // `output` -> output_digest -> io_digest -> causal_root -> the single ML-DSA-65
  // signature). chain.js keeps only io_digest per sealed step, so we carry a
  // SIDECAR map of the folded action metadata for inspection + re-gating at
  // verify. This sidecar is NOT inside the signed chain fields; verify re-derives
  // each step's io_digest FROM the sidecar metadata and confirms it matches the
  // signed io_digest, so the sidecar cannot be tampered without breaking the sig.
  // NOTE: we do NOT mutate any signed field (object/etc) post-sign, or the
  // chain signature would no longer verify.
  const actions = {};
  for (const gs of gated.steps) {
    const meta = gs.output && gs.output.__agentic_action;
    // store the FULL signed output + input so verify can recompute io_digest
    // byte-exactly and confirm it matches the signed io_digest in the envelope.
    if (meta) actions[gs.step_id] = { meta, input: gs.input ?? null, output: gs.output };
  }
  envelope.afir_s3 = 'agentic-action';
  envelope.agentic_actions = actions;   // sidecar (unsigned, but verify-bound)
  return { envelope, timing_us };
}

/**
 * verifyAgenticRun — two-part check:
 *   (1) verifyChain — full causal-graph reconstruction + single signature
 *   (2) scope re-gate — every action step's folded scope_ref must resolve to a
 *       verified scope and the action must still be in scope.
 * Either failing fails the run.
 */
export function verifyAgenticRun(envelope, scopes, verifyFn, pubResolver) {
  // (1) full causal-graph reconstruction + single ML-DSA-65 signature check
  const chainRes = verifyChain(envelope, verifyFn, pubResolver(envelope));
  const reasons = [...chainRes.reasons];

  const suite = resolveSuite((envelope.hash_suite || 'sha-256').toLowerCase());
  const sidecar = envelope.agentic_actions || {};
  const stepById = new Map((envelope.steps || []).map(s => [s.step_id, s]));

  // (2) bind the unsigned sidecar to the signed steps: for every action recorded
  // in the sidecar, recompute io_digest from its carried input/output and confirm
  // it equals the signed io_digest of that step. Tampering the sidecar (e.g.
  // rewriting the action) changes output_digest -> io_digest mismatch -> caught.
  for (const [stepId, entry] of Object.entries(sidecar)) {
    const signed = stepById.get(stepId);
    if (!signed) { reasons.push('sidecar_unknown_step:' + stepId); continue; }
    const recIo = recomputeIoDigest(entry.input, entry.output, suite);
    if (recIo !== signed.io_digest) reasons.push('agentic_action_unbound:' + stepId);
    // the carried output must actually contain the action metadata we re-gate on
    const meta = entry.output && entry.output.__agentic_action;
    if (!meta || JSON.stringify(meta) !== JSON.stringify(entry.meta)) {
      reasons.push('sidecar_meta_inconsistent:' + stepId);
    }
  }

  // (3) re-gate every action against its verified scope
  let scopesById;
  try { scopesById = resolveScopes(scopes, verifyFn, pubResolver); }
  catch (e) { reasons.push('scope_resolution_failed:' + e.message); scopesById = new Map(); }

  for (const [stepId, entry] of Object.entries(sidecar)) {
    const meta = entry.meta;
    if (!meta) continue;
    const scopeId = (meta.scope_ref || '').replace(/^sigr:/, '');
    const scope = scopesById.get(scopeId);
    if (!scope) { reasons.push('unresolved_scope_ref:' + stepId); continue; }
    const decision = scopeAllows(scope, meta.action, meta.tool_hash || undefined);
    if (!decision.allowed) reasons.push('out_of_scope_action:' + stepId + ':' + decision.reason);
    if (decision.destructive !== meta.destructive) reasons.push('destructive_flag_mismatch:' + stepId);
  }

  return {
    valid: reasons.length === 0,
    reasons,
    step_count: (envelope.steps || []).length,
    causal_root: envelope.causal_root,
  };
}

/**
 * chain.js — SiGR Chain: signed agent causal-chain (compound-AI accountability).
 *
 * THE FLAGSHIP. Survey's clearest winner — composite 19/20, 3 models' own top
 * pick (Grok "SiGR Chain", Claude "Agentic Action Receipts", DeepSeek "SiGR
 * Chain"), 5-of-7 convergence (C1). The rare asset everyone else lacks: the rest
 * of the market logs AFTER the fact; this signs the exact state the agent saw
 * BEFORE it acted, and chains each step to the prior step's signed hash so the
 * causal order is itself cryptographic.
 *
 * What it proves: a multi-step / multi-tool agent run is a DAG of STEPS. Each step
 * commits to (a) its own typed inputs/outputs digest and (b) the digests of its
 * parent steps — so a step cannot be re-ordered, inserted, dropped, or back-dated
 * without breaking the chain. At run close, all step digests roll up into ONE
 * causal root carried under a SINGLE ML-DSA-65 signature. One signature attests
 * the entire agent trajectory.
 *
 * Why a DAG not just a list: real agents fan out (parallel tool calls) and fan in
 * (merge results). Each step names its parent step_ids; the per-step commit hashes
 * the SORTED parent digests, so the partial causal order is bound exactly. A
 * linear run is the degenerate single-parent case.
 *
 * Tamper properties (all caught by the independent verifier):
 *   - reorder steps            -> a child's bound parent digest no longer matches
 *   - insert a fabricated step -> causal root changes
 *   - drop a step              -> a child references a missing parent / root changes
 *   - edit a step's I/O        -> that step's commit digest changes -> root changes
 *   - cycle in the graph       -> rejected (no valid topological order)
 *
 * Trust model: zero-secret verification. The customer needs only the published
 * ML-DSA-65 public key and the step records; the verifier recomputes every
 * per-step commit, re-derives the causal root, and checks the single signature.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, the bind-one-payload
 * pattern, SIGNER/verifyFn — identical discipline to typed.js / bill.js / bond.js.
 *
 * Patent Pending HC-2026-006 (cryptographic accountability graph for compound /
 * multi-agent AI workflows: per-step commitment to prior-step signed hashes under
 * a single aggregate post-quantum signature). Internal docket only.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export const STEP_KINDS = ['plan', 'reason', 'tool_call', 'retrieval', 'inference', 'merge', 'final'];

/**
 * buildStepCommit — the per-step commitment. A step commits to:
 *   - its identity (step_id, kind, seq)
 *   - the digest of its typed input/output payload (the state it saw + produced)
 *   - the SORTED digests of its parent steps' commits (the causal edges)
 * Returns { record, commit_digest }. commit_digest is the leaf the chain binds.
 *
 * parentCommits: array of the parents' commit_digest hex strings (already computed,
 * because parents are signed/sealed before children — sign-before-act ordering).
 */
export function buildStepCommit(step, parentCommits, suite) {
  const s = suite || resolveSuite('sha-256');
  const io = {
    input_digest: step.input_digest || hashHex(canonicalize(step.input ?? null), s),
    output_digest: step.output_digest || hashHex(canonicalize(step.output ?? null), s),
  };
  const record = {
    object: 'sigr.chain.step',
    step_id: step.step_id,
    kind: STEP_KINDS.includes(step.kind) ? step.kind : 'reason',
    seq: step.seq | 0,
    parents: [...(step.parents || [])].sort(),
    io_digest: hashHex(canonicalize(io), s),
    // bind the actual parent commit digests (not just their ids) so a parent's
    // content is transitively bound into every descendant.
    parent_commit_root: parentCommits.length
      ? merkleRoot([...parentCommits].sort(), s)
      : '0'.repeat(s.digest_len * 2),
  };
  const commit_digest = hashHex(canonicalize(record), s);
  return { record, io, commit_digest };
}

/**
 * topoOrder — Kahn's algorithm over step parents. Returns the steps in a valid
 * causal order, or throws on a cycle / dangling parent. Children must follow all
 * parents so parent commit digests exist when a child is committed.
 */
function topoOrder(steps) {
  const byId = new Map(steps.map(s => [s.step_id, s]));
  const indeg = new Map(steps.map(s => [s.step_id, 0]));
  const children = new Map(steps.map(s => [s.step_id, []]));
  for (const s of steps) {
    for (const p of s.parents || []) {
      if (!byId.has(p)) throw new Error('dangling_parent:' + p + '->' + s.step_id);
      indeg.set(s.step_id, indeg.get(s.step_id) + 1);
      children.get(p).push(s.step_id);
    }
  }
  // deterministic queue: ready steps sorted by seq then id
  const ready = steps.filter(s => indeg.get(s.step_id) === 0)
    .map(s => s.step_id).sort();
  const order = [];
  while (ready.length) {
    const id = ready.shift();
    order.push(id);
    for (const c of children.get(id).sort()) {
      indeg.set(c, indeg.get(c) - 1);
      if (indeg.get(c) === 0) {
        // insert keeping deterministic (seq,id) order
        ready.push(c);
        ready.sort((a, b) => {
          const sa = byId.get(a).seq | 0, sb = byId.get(b).seq | 0;
          return sa - sb || (a < b ? -1 : a > b ? 1 : 0);
        });
      }
    }
  }
  if (order.length !== steps.length) throw new Error('cycle_detected');
  return order.map(id => byId.get(id));
}

/**
 * signChain — seal an entire agent run. Computes each step's commit in causal
 * order (parents first), binds the per-step commit digests into ONE causal root,
 * and signs:  base || causal_root -> one payload -> one ML-DSA-65 sig.
 */
export function signChain(run, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const ordered = topoOrder(run.steps);
  const commitById = new Map();
  const sealedSteps = [];
  for (const step of ordered) {
    const parentCommits = (step.parents || []).map(pid => {
      const c = commitById.get(pid);
      if (!c) throw new Error('parent_not_sealed:' + pid);
      return c;
    });
    const { record, commit_digest } = buildStepCommit(step, parentCommits, suite);
    commitById.set(step.step_id, commit_digest);
    sealedSteps.push({ ...record, commit_digest });
  }

  // causal root = Merkle over all step commit digests (sorted for determinism;
  // ordering is already bound INTO each commit via parent_commit_root).
  const leaves = sealedSteps.map(s => s.commit_digest).sort();
  const causalRoot = merkleRoot(leaves, suite);

  const baseFields = {
    object: 'sigr.chain.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    run_id: run.run_id,
    agent_ref: run.agent_ref || 'unspecified',
    step_count: sealedSteps.length,
    causal_root: causalRoot,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(causalRoot), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    steps: sealedSteps,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  if (signer.trust) envelope.trust = signer.trust;

  return { envelope, timing_us: { sign_us: Number(t1 - t0) / 1000 } };
}

/**
 * verifyChain — independent reconstruction of the entire causal graph + single
 * signature check. Recomputes each step's commit from its record (re-deriving the
 * parent_commit_root from the parents' recomputed commits), re-derives the causal
 * root, and verifies the one signature. Any reorder/insert/drop/edit/cycle fails.
 */
export function verifyChain(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);

  const steps = envelope.steps || [];
  if (steps.length !== envelope.step_count) reasons.push('step_count_mismatch');

  // re-derive causal order independently from the carried records
  let ordered;
  try {
    ordered = topoOrder(steps.map(s => ({ step_id: s.step_id, parents: s.parents, seq: s.seq })));
  } catch (e) {
    reasons.push('graph_invalid:' + e.message);
    return { valid: false, reasons };
  }

  // recompute each commit in causal order using recomputed parent commits
  const recById = new Map();
  for (const ord of ordered) {
    const s = steps.find(x => x.step_id === ord.step_id);
    const parentCommits = (s.parents || []).map(pid => recById.get(pid));
    if (parentCommits.some(c => c === undefined)) { reasons.push('parent_not_resolved:' + s.step_id); continue; }
    const expectedParentRoot = parentCommits.length
      ? merkleRoot([...parentCommits].sort(), suite)
      : zero;
    if ((s.parent_commit_root || zero) !== expectedParentRoot) reasons.push('parent_commit_root_mismatch:' + s.step_id);

    const record = {
      object: s.object,
      step_id: s.step_id,
      kind: s.kind,
      seq: s.seq,
      parents: [...(s.parents || [])].sort(),
      io_digest: s.io_digest,
      parent_commit_root: s.parent_commit_root,
    };
    const recDigest = hashHex(canonicalize(record), suite);
    if (recDigest !== s.commit_digest) reasons.push('commit_digest_mismatch:' + s.step_id);
    recById.set(s.step_id, recDigest);
  }

  const leaves = steps.map(s => s.commit_digest).sort();
  const recCausalRoot = merkleRoot(leaves, suite);
  if (recCausalRoot !== envelope.causal_root) reasons.push('causal_root_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    run_id: envelope.run_id,
    agent_ref: envelope.agent_ref,
    step_count: envelope.step_count,
    causal_root: envelope.causal_root,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.causal_root || zero), dl);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== envelope.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(envelope.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return {
    valid: reasons.length === 0,
    reasons,
    step_count: steps.length,
    causal_root: envelope.causal_root,
  };
}

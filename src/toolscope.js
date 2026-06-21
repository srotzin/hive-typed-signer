/**
 * toolscope.js — AFiR-S3 Tool-Scope Receipt (BEFORE).
 *
 * AFiR-S3 §2.1. Signs the EXACT set of capabilities an autonomous agent was
 * authorized to use, committed BEFORE it acts. The security layer for agents:
 * when an agent does something harmful, this proves whether it was even allowed
 * to. Any action outside the committed scope is provably unauthorized.
 *
 * What it proves: a scope manifest — the Merkle root over the agent's authorized
 * tool identities, plus the explicit destructive/value-moving subset — is bound
 * into ONE ML-DSA-65 signature up front. A later action receipt names this
 * scope_ref; an independent verifier can prove a given tool was (or was not) in
 * scope and whether it was flagged destructive, all without any secret.
 *
 * Membership proof: each authorized tool contributes a leaf
 *   tool_leaf = H( canonical({ tool_id, tool_hash }) )
 * scope_root = merkleRoot(sorted tool_leaves). Because the leaves are sorted and
 * the set is carried in the receipt, a verifier recomputes scope_root exactly and
 * can test membership of any (tool_id, tool_hash) against the carried tool list.
 *
 * Trust model: zero-secret verification. The customer needs only the published
 * ML-DSA-65 public key and the scope record; the verifier recomputes every tool
 * leaf, re-derives scope_root, and checks the single signature.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, the bind-one-payload
 * pattern, SIGNER/verifyFn — identical discipline to typed.js / chain.js.
 *
 * Patent Pending HC-2026-008 (cryptographic pre-commitment of an autonomous
 * agent's authorized tool scope, with a destructive-capability subset, bound
 * under a single aggregate post-quantum signature and referenced by subsequent
 * action receipts to gate authorization). Internal docket only — never emit in
 * public artifacts.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * toolLeaf — the per-tool commitment leaf. Binds the tool's stable identity and
 * the hash of its tool document / signature so a swapped tool definition is
 * detectable. tool_hash is supplied by the caller (hash of the tool's signed
 * doc / schema); if absent we hash the canonical tool_id alone (weakest form).
 */
export function toolLeaf(tool, suite) {
  const s = suite || resolveSuite('sha-256');
  const rec = {
    tool_id: tool.tool_id,
    tool_hash: tool.tool_hash || hashHex(canonicalize({ tool_id: tool.tool_id }), s),
  };
  return { rec, leaf: hashHex(canonicalize(rec), s) };
}

/**
 * computeScopeRoot — deterministic Merkle root over the sorted tool leaves.
 * Returns { leaves, scope_root, leafByToolId } for reuse by sign + verify.
 */
export function computeScopeRoot(tools, suite) {
  const s = suite || resolveSuite('sha-256');
  const leafByToolId = new Map();
  const leaves = [];
  for (const t of tools) {
    const { leaf } = toolLeaf(t, s);
    leafByToolId.set(t.tool_id, leaf);
    leaves.push(leaf);
  }
  const sorted = [...leaves].sort();
  const scope_root = sorted.length ? merkleRoot(sorted, s) : '0'.repeat(s.digest_len * 2);
  return { leaves: sorted, scope_root, leafByToolId };
}

/**
 * signToolScope — seal a scope manifest. Binds:
 *   base || scope_root -> one payload -> one ML-DSA-65 sig.
 *
 * scope = {
 *   scope_id, agent_ref,
 *   tools: [{ tool_id, tool_hash? }, ...],   // the full authorized set
 *   destructive_tools: ['delete_project', 'transfer_funds', ...],
 *   granted_by, granted_at?
 * }
 */
export function signToolScope(scope, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const tools = Array.isArray(scope.tools) ? scope.tools : [];
  if (tools.length === 0) throw new Error('empty_tool_scope');
  const ids = tools.map(t => t.tool_id);
  if (new Set(ids).size !== ids.length) throw new Error('duplicate_tool_id');

  const { leaves, scope_root } = computeScopeRoot(tools, suite);

  // destructive set must be a subset of the authorized tools (you cannot flag a
  // tool destructive that the agent was never granted).
  const destructive = [...new Set(scope.destructive_tools || [])].sort();
  for (const d of destructive) {
    if (!ids.includes(d)) throw new Error('destructive_not_in_scope:' + d);
  }

  // carry the tool records (sorted by tool_id) so a verifier can recompute leaves
  const toolRecords = tools
    .map(t => toolLeaf(t, suite).rec)
    .sort((a, b) => (a.tool_id < b.tool_id ? -1 : a.tool_id > b.tool_id ? 1 : 0));

  const baseFields = {
    object: 'sigr.toolscope.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    scope_id: scope.scope_id,
    agent_ref: scope.agent_ref || 'unspecified',
    tool_count: toolRecords.length,
    destructive_tools: destructive,
    granted_by: scope.granted_by || 'unspecified',
    granted_at: scope.granted_at || new Date().toISOString(),
    scope_root,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(scope_root), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    tools: toolRecords,
    leaves,                       // sorted leaf digests (for membership recompute)
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
 * verifyToolScope — independent recompute of scope_root + single signature check.
 * Recomputes every tool leaf from the carried tool records, re-derives the Merkle
 * root, confirms it matches the carried leaves and the signed scope_root, and
 * verifies the one signature. Any added/removed/edited tool breaks verification.
 */
export function verifyToolScope(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);

  const toolRecords = envelope.tools || [];
  if (toolRecords.length !== envelope.tool_count) reasons.push('tool_count_mismatch');

  // recompute leaves from records
  const recLeaves = [];
  const ids = [];
  for (const rec of toolRecords) {
    ids.push(rec.tool_id);
    recLeaves.push(hashHex(canonicalize({ tool_id: rec.tool_id, tool_hash: rec.tool_hash }), suite));
  }
  if (new Set(ids).size !== ids.length) reasons.push('duplicate_tool_id');

  const recSorted = [...recLeaves].sort();
  // carried leaves must equal recomputed leaves
  const carried = [...(envelope.leaves || [])].sort();
  if (carried.length !== recSorted.length || carried.some((l, i) => l !== recSorted[i])) {
    reasons.push('leaves_mismatch');
  }

  const recScopeRoot = recSorted.length ? merkleRoot(recSorted, suite) : zero;
  if (recScopeRoot !== envelope.scope_root) reasons.push('scope_root_mismatch');

  // destructive set must be a subset of carried tool ids
  for (const d of (envelope.destructive_tools || [])) {
    if (!ids.includes(d)) reasons.push('destructive_not_in_scope:' + d);
  }

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    scope_id: envelope.scope_id,
    agent_ref: envelope.agent_ref,
    tool_count: envelope.tool_count,
    destructive_tools: envelope.destructive_tools || [],
    granted_by: envelope.granted_by,
    granted_at: envelope.granted_at,
    scope_root: envelope.scope_root,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.scope_root || zero), dl);
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
    scope_id: envelope.scope_id,
    tool_count: toolRecords.length,
    scope_root: envelope.scope_root,
  };
}

/**
 * scopeAllows — authorization predicate used by the Agentic Action wrapper to
 * GATE actions. Returns { allowed, destructive, reason }.
 *   - allowed:    the tool_id is present in the (verified) scope
 *   - destructive: the tool_id is in the scope's destructive subset
 * Callers MUST first verify the scope envelope (verifyToolScope) before trusting
 * this; this function assumes the envelope is already cryptographically valid.
 */
export function scopeAllows(scopeEnvelope, toolId, toolHash) {
  const tools = scopeEnvelope.tools || [];
  const match = tools.find(t => t.tool_id === toolId);
  if (!match) return { allowed: false, destructive: false, reason: 'out_of_scope:' + toolId };
  // if a tool_hash is asserted by the action, it must match the scoped tool_hash
  if (toolHash && match.tool_hash && toolHash !== match.tool_hash) {
    return { allowed: false, destructive: false, reason: 'tool_hash_mismatch:' + toolId };
  }
  const destructive = (scopeEnvelope.destructive_tools || []).includes(toolId);
  return { allowed: true, destructive, reason: null };
}

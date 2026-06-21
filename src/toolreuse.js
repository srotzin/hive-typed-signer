/**
 * toolreuse.js — AFiR-S3 §3: trust-anchor reuse over byte-identical deterministic
 * tool calls. Extends the AFiR-S2 anchor-reuse market (two-axis byte-identity,
 * "identical never similar", R2) from RAG dependencies to TOOL CALLS.
 *
 * The economic thesis (AFiR-S3 §3): the agent market generates orders of
 * magnitude more deterministic, repeatable tool calls than RAG generates
 * citations. A tool result proven once chains for EVERY future agent making the
 * byte-identical call — a far larger reuse surface than citations.
 *
 * TWO-AXIS IDENTITY for a tool call (mirrors AFiR-S2 R2):
 *   axis 1: tool_hash   — identity of the tool (its signed doc / schema), bound
 *                         at mint. A different tool version = different identity.
 *   axis 2: input_hash  — content hash of the canonical call inputs' raw bytes.
 *   identity_key = H( canonical({ tool_hash, input_hash }) )
 *
 * R2 RULE — IDENTICAL, NEVER SIMILAR. Reuse fires iff BOTH axes are byte-identical
 * to the minted anchor. Similar inputs, a one-field change, a re-ordered argument
 * object that canonicalizes differently, or the same tool name under a different
 * tool_hash all produce a DIFFERENT identity_key and therefore a guaranteed cold
 * verify. Source/label is excluded from identity. Similarity is never money.
 *
 * DETERMINISM GATE (AFiR-S3 §3): only DETERMINISTIC tools may anchor. A tool
 * declared non-deterministic (live web, current time, RNG, live price) NEVER
 * anchors and NEVER chains — it cold-verifies every time, by definition. We refuse
 * to mint an anchor for a non-deterministic tool.
 *
 * FAIL-CLOSED (inherited from AFiR-S2): on cache miss, on a revoked anchor, on a
 * tampered (signature-absent/invalid) anchor, or absent a live signer, the
 * resolver cold-verifies and mints a fresh REAL signature rather than reusing.
 * The reuse path writes nothing new on-chain.
 *
 * Each chain event emits a signed savings proof (avoided cold cost − chain cost),
 * carrying the minting holder so AFiR-S2 graph-routed yield can route the fee.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, bind-one-payload, SIGNER/verifyFn.
 *
 * Patent Pending HC-2026-008 (continuation surface; extends the byte-identity
 * anchor-reuse market to deterministic agent tool calls). Internal docket only.
 */
import { canonicalize, hashHex, resolveSuite } from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * toolCallIdentity — the two-axis identity for a deterministic tool call.
 * Returns { tool_hash, input_hash, identity_key }.
 */
export function toolCallIdentity(call, suite) {
  const s = suite || resolveSuite('sha-256');
  const tool_hash = call.tool_hash || hashHex(canonicalize({ tool_id: call.tool_id }), s);
  const input_hash = call.input_hash || hashHex(canonicalize(call.input ?? null), s);
  const identity_key = hashHex(canonicalize({ tool_hash, input_hash }), s);
  return { tool_hash, input_hash, identity_key };
}

/**
 * mintToolAnchor — cold-mint: a deterministic tool result proven for the first
 * time. Binds two-axis identity + the result digest + holder + mint time under
 * ONE ML-DSA-65 signature. Refuses non-deterministic tools.
 *
 * call = { tool_id, tool_hash?, input?, input_hash?, output, deterministic, holder }
 */
export function mintToolAnchor(call, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  if (call.deterministic !== true) {
    throw new Error('non_deterministic_tool_cannot_anchor:' + (call.tool_id || '?'));
  }
  const { tool_hash, input_hash, identity_key } = toolCallIdentity(call, suite);
  const result_digest = call.result_digest || hashHex(canonicalize(call.output ?? null), suite);

  const baseFields = {
    object: 'sigr.toolanchor.mint',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    tool_id: call.tool_id,
    tool_hash,
    input_hash,
    identity_key,
    result_digest,
    holder: call.holder || 'unspecified',
    minted_at: new Date().toISOString(),
    deterministic: true,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(identity_key), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const anchor = {
    ...baseFields,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) anchor.hash_suite = (opts.hashSuite || '').toLowerCase();
  return { anchor, timing_us: { sign_us: Number(t1 - t0) / 1000 } };
}

/**
 * verifyToolAnchor — independent recompute of identity + result digest + single
 * signature. Used by the resolver before any reuse (a tampered anchor fails
 * closed).
 */
export function verifyToolAnchor(anchor, verifyFn, pubBytes) {
  const reasons = [];
  const suite = resolveSuite((anchor.hash_suite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const recIdentity = hashHex(canonicalize({ tool_hash: anchor.tool_hash, input_hash: anchor.input_hash }), suite);
  if (recIdentity !== anchor.identity_key) reasons.push('identity_key_mismatch');

  const baseFields = {
    object: anchor.object, version: anchor.version, sig_scheme: anchor.sig_scheme,
    public_key: anchor.public_key, tool_id: anchor.tool_id, tool_hash: anchor.tool_hash,
    input_hash: anchor.input_hash, identity_key: anchor.identity_key,
    result_digest: anchor.result_digest, holder: anchor.holder,
    minted_at: anchor.minted_at, deterministic: anchor.deterministic,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(anchor.identity_key), dl);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== anchor.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(anchor.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return { valid: reasons.length === 0, reasons };
}

/**
 * resolveToolCall — the AFiR-S2-style resolve: HIT chains, MISS cold-mints.
 *
 * Performs a single O(1) hash-keyed lookup on the two-axis identity. On a valid,
 * unrevoked, byte-identical anchor whose result matches: CHAIN (reuse, emit a
 * signed savings proof, write nothing new). Otherwise FAIL CLOSED -> cold-mint.
 *
 * args:
 *   call       — { tool_id, tool_hash?, input?, input_hash?, output, deterministic, holder }
 *   anchorIndex— Map(identity_key -> anchor)   (the reuse cache)
 *   revoked    — Set(identity_key)             (revocations -> fail closed)
 *   signer, verifyFn, pubResolver
 *   costs      — { cold_us, chain_us }  (for the savings proof; defaults applied)
 */
export function resolveToolCall(call, anchorIndex, revoked, signer, verifyFn, pubResolver, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const { identity_key } = toolCallIdentity(call, suite);

  // Non-deterministic tools never chain — cold every time, by definition.
  if (call.deterministic !== true) {
    return { outcome: 'cold_nondeterministic', identity_key, anchor: null, savings_proof: null };
  }

  const candidate = anchorIndex && anchorIndex.get(identity_key);
  const isRevoked = revoked && revoked.has(identity_key);

  if (candidate && !isRevoked) {
    // verify the anchor (fail closed if tampered) AND confirm the RESULT is
    // byte-identical (identity guarantees inputs, but we re-check the result the
    // anchor attests matches the result we'd reuse).
    const v = verifyToolAnchor(candidate, verifyFn, pubResolver(candidate));
    const recResult = call.result_digest || hashHex(canonicalize(call.output ?? null), suite);
    if (v.valid && recResult === candidate.result_digest) {
      const savings = signToolSavingsProof(
        { identity_key, anchor_holder: candidate.holder, cold_us: opts.cold_us ?? 1200, chain_us: opts.chain_us ?? 40 },
        signer, opts,
      );
      return { outcome: 'chain', identity_key, anchor: candidate, savings_proof: savings.envelope };
    }
    // tampered or result mismatch -> fall through to cold-mint (fail closed)
  }

  // MISS / revoked / tampered -> cold-mint a fresh real signature.
  const { anchor } = mintToolAnchor(call, signer, opts);
  if (anchorIndex) anchorIndex.set(identity_key, anchor);
  return { outcome: 'cold_mint', identity_key, anchor, savings_proof: null };
}

/**
 * signToolSavingsProof — the signed savings proof for a chain event. Records the
 * avoided cold-verification cost minus the actual chaining cost and the minting
 * holder (so AFiR-S2 graph-routed yield can route the fee). One ML-DSA-65 sig.
 */
export function signToolSavingsProof(s, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;
  const saved_us = Math.max(0, (s.cold_us | 0) - (s.chain_us | 0));

  const baseFields = {
    object: 'sigr.toolreuse.savings',
    version: signer.version, sig_scheme: signer.scheme, public_key: signer.publicKeyB64,
    identity_key: s.identity_key,
    anchor_holder: s.anchor_holder || 'unspecified',
    cold_us: s.cold_us | 0, chain_us: s.chain_us | 0, saved_us,
    minted_at: new Date().toISOString(),
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(s.identity_key), dl);
  const payloadHex = bytesToHex(suite.fn(bind));
  const sigBytes = signer.sign(hexToBytes(payloadHex));

  const envelope = {
    ...baseFields,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  return { envelope };
}

/**
 * verifyToolSavingsProof — recompute saved_us + single signature check.
 */
export function verifyToolSavingsProof(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suite = resolveSuite((envelope.hash_suite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const recSaved = Math.max(0, (envelope.cold_us | 0) - (envelope.chain_us | 0));
  if (recSaved !== envelope.saved_us) reasons.push('saved_us_mismatch');

  const baseFields = {
    object: envelope.object, version: envelope.version, sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key, identity_key: envelope.identity_key,
    anchor_holder: envelope.anchor_holder, cold_us: envelope.cold_us,
    chain_us: envelope.chain_us, saved_us: envelope.saved_us, minted_at: envelope.minted_at,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.identity_key), dl);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== envelope.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(envelope.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return { valid: reasons.length === 0, reasons, saved_us: envelope.saved_us };
}

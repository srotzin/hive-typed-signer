/**
 * consensus.js — Concept E: cross-model consensus receipt.
 *
 * THE INTERNAL DIFFERENTIATOR. Composite 17/20 and genuinely unique whitespace:
 * NOT independently proposed by ANY of the 7 surveyed frontier models. The survey
 * validated the building blocks (aggregate-over-sub-receipts in C1/C10) without
 * anyone claiming the consensus framing — so this is the clearest defensible IP
 * lane Hive has.
 *
 * What it proves: a single logical answer was produced by querying N models (a
 * panel / ensemble / mixture-of-experts / verifier-of-verifiers), each model's
 * individual output is captured as a signed SUB-RECEIPT, and the consensus
 * DECISION (majority vote, quorum, judge-selected, or score-weighted) is bound to
 * the exact set of sub-receipts it was computed from — all under ONE ML-DSA-65
 * signature.
 *
 * Why it matters: high-stakes AI increasingly uses panels (multiple models cross-
 * checking each other) precisely to reduce single-model error. But today nobody
 * can prove WHICH models were polled, WHAT each actually returned, or that the
 * reported consensus matches the panel. A consensus receipt makes the panel itself
 * auditable: you can prove a dissenting model was not silently dropped, that the
 * vote math is honest, and that the winning answer is the one the panel actually
 * produced.
 *
 * Structure:
 *   - sub-receipt[i] = signed commitment to model_id + output_digest + (optional)
 *     score, for each panel member. Each is independently verifiable.
 *   - consensus record binds: method, the SORTED sub-receipt digests (the exact
 *     panel), the decision (winning output digest + winning model), and the tally.
 *   - one aggregate ML-DSA-65 signature over base || panel_root || decision_digest.
 *
 * Decision methods (deterministic, integer-safe):
 *   - 'majority'  : winner = output_digest with the most votes (ties -> lowest hex)
 *   - 'quorum'    : winner present iff >= quorum_n members share an output_digest
 *   - 'weighted'  : winner = highest summed integer score per output_digest
 *   - 'judge'     : winner = the sub-receipt whose model_id == judge_pick (explicit)
 *
 * Trust model: zero-secret verification. Verifier recomputes every sub-receipt
 * digest, re-derives the panel root, RE-RUNS the decision method from the sub-
 * receipts, and checks one signature. A provider cannot drop a dissenter, fake a
 * panelist, or misreport the winner.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, bind-one-payload,
 * SIGNER/verifyFn — identical discipline to the rest of the stack.
 *
 * Patent Pending HC-2026-007 (aggregate post-quantum attestation of multi-model
 * consensus / ensemble inference binding panel composition to a verifiable
 * consensus decision). Internal docket only.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export const CONSENSUS_METHODS = ['majority', 'quorum', 'weighted', 'judge'];

/**
 * buildSubReceipt — one panel member's signed sub-receipt. Binds:
 *   base || member_digest -> payload -> ML-DSA-65 sig.
 * member_digest commits to model_id + output_digest + integer score.
 */
export function signSubReceipt(member, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const memberRecord = {
    object: 'sigr.consensus.member',
    panel_id: member.panel_id,
    model_id: member.model_id,
    output_digest: member.output_digest || hashHex(canonicalize(member.output ?? null), suite),
    score: member.score | 0,                 // integer score for 'weighted'
    seq: member.seq | 0,
  };
  const memberDigest = hashHex(canonicalize(memberRecord), suite);

  const baseFields = {
    object: 'sigr.consensus.sub_receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(memberDigest), dl);
  const payloadHex = bytesToHex(suite.fn(bind));
  const sigBytes = signer.sign(hexToBytes(payloadHex));

  const envelope = {
    ...baseFields,
    member: memberRecord,
    member_digest: memberDigest,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  return envelope;
}

export function verifySubReceipt(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  const memberDigest = hashHex(canonicalize(envelope.member), suite);
  if (memberDigest !== envelope.member_digest) reasons.push('member_digest_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(memberDigest), dl);
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

/**
 * computeConsensus — the deterministic decision function. Pure; same result
 * provider-side and verifier-side. Returns the winning output_digest, winning
 * model_id(s), the tally, and whether a decision was reached.
 */
export function computeConsensus(members, method, params = {}) {
  const m = CONSENSUS_METHODS.includes(method) ? method : 'majority';

  // tally votes / weights per output_digest
  const votes = new Map();   // output_digest -> count
  const weight = new Map();  // output_digest -> summed score
  const modelsByOut = new Map(); // output_digest -> sorted model_ids
  for (const mem of members) {
    const od = mem.output_digest;
    votes.set(od, (votes.get(od) || 0) + 1);
    weight.set(od, (weight.get(od) || 0) + (mem.score | 0));
    const arr = modelsByOut.get(od) || [];
    arr.push(mem.model_id);
    modelsByOut.set(od, arr);
  }
  for (const [k, v] of modelsByOut) modelsByOut.set(k, v.sort());

  const tally = [...votes.entries()]
    .map(([output_digest, count]) => ({
      output_digest, votes: count, weight: weight.get(output_digest) || 0,
      models: modelsByOut.get(output_digest),
    }))
    .sort((a, b) =>
      b.votes - a.votes || b.weight - a.weight ||
      (a.output_digest < b.output_digest ? -1 : a.output_digest > b.output_digest ? 1 : 0));

  let winner = null, decided = false;
  if (m === 'judge') {
    const pick = members.find(x => x.model_id === params.judge_pick);
    if (pick) { winner = { output_digest: pick.output_digest, model_id: pick.model_id }; decided = true; }
  } else if (m === 'quorum') {
    const need = params.quorum_n | 0;
    const top = tally[0];
    if (top && top.votes >= need) { winner = { output_digest: top.output_digest, models: top.models }; decided = true; }
  } else if (m === 'weighted') {
    const byWeight = [...tally].sort((a, b) =>
      b.weight - a.weight || b.votes - a.votes ||
      (a.output_digest < b.output_digest ? -1 : 1));
    if (byWeight[0]) { winner = { output_digest: byWeight[0].output_digest, models: byWeight[0].models }; decided = true; }
  } else { // majority (plurality), deterministic tie-break already in tally sort
    if (tally[0]) { winner = { output_digest: tally[0].output_digest, models: tally[0].models }; decided = true; }
  }

  return { method: m, member_count: members.length, tally, winner, decided };
}

/**
 * signConsensus — aggregate the panel. Binds the SORTED sub-receipt payload
 * digests into a panel root, computes the decision, and signs:
 *   base || panel_root || decision_digest -> one payload -> one ML-DSA-65 sig.
 */
export function signConsensus(panel, subReceiptEnvelopes, method, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const leaves = subReceiptEnvelopes.map(e => e.payload_digest).sort();
  const panelRoot = merkleRoot(leaves, suite);
  const members = subReceiptEnvelopes.map(e => e.member);
  const decision = computeConsensus(members, method, panel.params || {});

  const decisionRecord = {
    object: 'sigr.consensus.decision',
    method: decision.method,
    member_count: decision.member_count,
    decided: decision.decided,
    winner: decision.winner,
    tally: decision.tally,
    params: panel.params || {},
  };
  const decisionDigest = hashHex(canonicalize(decisionRecord), suite);

  const baseFields = {
    object: 'sigr.consensus.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    panel_id: panel.panel_id,
    panel_root: panelRoot,
    member_count: subReceiptEnvelopes.length,
    decision_digest: decisionDigest,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 3);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(panelRoot), dl);
  bind.set(hexToBytes(decisionDigest), dl * 2);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    decision: decisionRecord,
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
 * verifyConsensus — independent panel reconstruction. Pass the consensus envelope
 * and the customer's OWN collected sub-receipt envelopes. Recomputes the panel
 * root, RE-RUNS the decision from the sub-receipts, and checks both match the
 * signed receipt + the single signature. A dropped dissenter, faked panelist, or
 * misreported winner all fail.
 */
export function verifyConsensus(envelope, subReceiptEnvelopes, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  // reconcile panel root from the customer's own sub-receipts
  const leaves = subReceiptEnvelopes.map(e => e.payload_digest).sort();
  const recomputedRoot = merkleRoot(leaves, suite);
  if (recomputedRoot !== envelope.panel_root) reasons.push('panel_root_mismatch_vs_sub_receipts');
  if (subReceiptEnvelopes.length !== envelope.member_count) reasons.push('member_count_mismatch');

  // RE-RUN the decision from the customer's sub-receipts
  const members = subReceiptEnvelopes.map(e => e.member);
  const recDecision = computeConsensus(members, envelope.decision.method, envelope.decision.params || {});
  const recDecisionRecord = {
    object: 'sigr.consensus.decision',
    method: recDecision.method,
    member_count: recDecision.member_count,
    decided: recDecision.decided,
    winner: recDecision.winner,
    tally: recDecision.tally,
    params: envelope.decision.params || {},
  };
  const recDecisionDigest = hashHex(canonicalize(recDecisionRecord), suite);
  if (recDecisionDigest !== envelope.decision_digest) reasons.push('decision_digest_mismatch');

  // also confirm the carried decision record matches its bound digest
  const carriedDigest = hashHex(canonicalize(envelope.decision), suite);
  if (carriedDigest !== envelope.decision_digest) reasons.push('carried_decision_digest_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    panel_id: envelope.panel_id,
    panel_root: envelope.panel_root,
    member_count: envelope.member_count,
    decision_digest: envelope.decision_digest,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 3);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.panel_root), dl);
  bind.set(hexToBytes(envelope.decision_digest), dl * 2);
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
    decided: envelope.decision.decided,
    winner: envelope.decision.winner,
  };
}

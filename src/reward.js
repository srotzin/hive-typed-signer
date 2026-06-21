/**
 * reward.js — AFiR-S3 Reward-Attestation Receipt (AFTER).
 *
 * AFiR-S3 §2.4. Signs the RL reward r(τ) assigned to a trajectory. Binds
 * "this trajectory received this reward under this reward model" into one signed
 * receipt — tamper-evident provenance of HOW a model was shaped, not just how it
 * answered. A SEPARATE MARKET from answer-verification: regulators, acquirers,
 * and safety reviewers auditing how a model was trained need this; the buyer is
 * distinct from the inference platforms.
 *
 * What it signs:
 *   - trajectory_root  : root over the full episode's step receipts (the run this
 *                        reward is FOR). Supplied (e.g. an agentic/chain causal
 *                        root) or computed from a list of step receipt digests.
 *   - reward           : the scalar reward assigned (integer micro-units to avoid
 *                        float drift in any downstream settlement; see below)
 *   - reward_model_hash: identity of the reward model that produced it (swap the
 *                        reward model -> receipt no longer matches)
 *   - algo             : GRPO | PPO | RLOO | REINFORCE++ (the RL algorithm)
 *
 * Float discipline: rewards are real-valued in RL, but to keep the signed value
 * exact and settlement-safe we bind BOTH the caller's declared numeric `reward`
 * and a canonical string form into the payload via canonicalize (which JSON-
 * stringifies the number deterministically). No on-chain math is done on it here;
 * AFiR-S2 yield settlement, if applied, reads the signed value as-is.
 *
 * ARSC tier: Float (training-time, not latency-critical) — AFiR-S3 §2.4.
 *
 * Trust model: zero-secret verification. Only the published ML-DSA-65 public key
 * and the receipt are needed; the verifier recomputes the trajectory root (if
 * step digests are carried), re-binds the reward + model hash + algo, and checks
 * the single signature. A tampered reward, a swapped reward model, or an altered
 * trajectory all break verification.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, bind-one-payload,
 * SIGNER/verifyFn — identical discipline to typed.js / chain.js.
 *
 * Patent Pending HC-2026-011 (cryptographic attestation binding a reinforcement-
 * learning trajectory to its assigned reward and reward-model identity under a
 * single aggregate post-quantum signature, providing tamper-evident provenance of
 * a training signal). Internal docket only.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export const RL_ALGOS = ['GRPO', 'PPO', 'RLOO', 'REINFORCE++', 'DPO', 'unspecified'];

/**
 * resolveTrajectoryRoot — accept either a precomputed trajectory_root (e.g. an
 * agentic/chain causal_root) or a list of step receipt digests to roll up.
 */
export function resolveTrajectoryRoot(reward, suite) {
  const s = suite || resolveSuite('sha-256');
  if (reward.trajectory_root) return reward.trajectory_root;
  const digests = reward.step_receipt_digests || [];
  if (!digests.length) throw new Error('missing_trajectory_root_or_step_digests');
  return merkleRoot([...digests].sort(), s);
}

/**
 * signReward — seal a reward attestation. Binds:
 *   base || trajectory_root -> one payload -> one ML-DSA-65 sig.
 *
 * reward = {
 *   trajectory_root?  OR  step_receipt_digests:[...],
 *   reward,                 // numeric scalar
 *   reward_model_hash,      // hex identity of the reward model
 *   algo,                   // RL algorithm
 *   episode_id?
 * }
 */
export function signReward(reward, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  if (reward.reward === undefined || reward.reward === null || Number.isNaN(Number(reward.reward))) {
    throw new Error('invalid_reward_value');
  }
  if (!reward.reward_model_hash) throw new Error('missing_reward_model_hash');
  const algo = RL_ALGOS.includes(reward.algo) ? reward.algo : 'unspecified';

  const trajectory_root = resolveTrajectoryRoot(reward, suite);

  const baseFields = {
    object: 'sigr.reward.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    episode_id: reward.episode_id || 'unspecified',
    trajectory_root,
    reward: reward.reward,                  // canonicalize stringifies deterministically
    reward_canonical: canonicalize(reward.reward),
    reward_model_hash: reward.reward_model_hash,
    algo,
    arsc_tier: 'float',                     // training-time, not latency-critical
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(trajectory_root), dl);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  // carry the step digests if the caller asked us to roll them up, so the
  // trajectory_root is independently re-derivable.
  if (!reward.trajectory_root && reward.step_receipt_digests) {
    envelope.step_receipt_digests = [...reward.step_receipt_digests].sort();
  }
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  if (signer.trust) envelope.trust = signer.trust;

  return { envelope, timing_us: { sign_us: Number(t1 - t0) / 1000 } };
}

/**
 * verifyReward — independent recompute + single signature check.
 *   - if step digests are carried, re-derive trajectory_root and confirm match
 *   - re-bind base + trajectory_root, recompute payload, verify the one signature
 * A tampered reward, swapped reward_model_hash, altered algo, or altered
 * trajectory all break verification.
 */
export function verifyReward(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  // re-derive trajectory root if step digests are carried
  if (envelope.step_receipt_digests) {
    const rec = merkleRoot([...envelope.step_receipt_digests].sort(), suite);
    if (rec !== envelope.trajectory_root) reasons.push('trajectory_root_mismatch');
  }

  // reward_canonical must match the canonical form of the carried numeric reward
  if (canonicalize(envelope.reward) !== envelope.reward_canonical) reasons.push('reward_canonical_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    episode_id: envelope.episode_id,
    trajectory_root: envelope.trajectory_root,
    reward: envelope.reward,
    reward_canonical: envelope.reward_canonical,
    reward_model_hash: envelope.reward_model_hash,
    algo: envelope.algo,
    arsc_tier: envelope.arsc_tier,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(envelope.trajectory_root), dl);
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
    episode_id: envelope.episode_id,
    reward: envelope.reward,
    algo: envelope.algo,
  };
}

/**
 * pbs.js — Provenance-Bonded Sandbox (PBS).
 *
 * HC-2026-016. First of the seven Upstream Signed Pre-Effect Attestation
 * (USPA) primitives. Signs a sandbox environment manifest at provisioning,
 * then continuously proves the environment has not drifted via a Merkle
 * accumulator of heartbeat measurements.
 *
 * PBS has two receipt types:
 *
 *   pbs.manifest — issued once at sandbox instantiation. Binds:
 *     - image_digests: array of container/OCI image digests
 *     - kernel_modules: sorted list of loaded kernel modules with hashes
 *     - package_index: digest of the package-registry index snapshot
 *     - egress_acl: canonicalized network egress policy
 *     - gpu_firmware: firmware digest (dovetails with S2S)
 *     - attestor_kid: the external attestor that co-signed the manifest
 *
 *   pbs.attestation — heartbeat receipt emitted every N seconds while a
 *     run is live. Novel core: each heartbeat re-hashes a rotating subset
 *     of environment artifacts and folds the measurement into a Merkle
 *     accumulator whose root is bound to the receipt. Silent kernel-module
 *     swap, in-memory package replacement, or ACL loosen mid-run all break
 *     the accumulator chain.
 *
 * The accumulator is a rolling Merkle tree over an ordered sequence of
 * measurement leaves:
 *   leaf_i = H( canonical({ heartbeat_seq, artifact_id, measured_digest, ts }) )
 * accumulator_root_i = merkleRoot(leaves_0..i in sequence order)
 * Each attestation carries: heartbeat_seq, measurement_leaves_this_beat,
 * prior_accumulator_root, new_accumulator_root, delta_root. A verifier can
 * recompute new_accumulator_root deterministically given the carried leaves
 * and prior_accumulator_root — and any silent drift breaks it.
 *
 * Patent Pending HC-2026-016 (a method for continuously proving the
 * integrity of an autonomous-agent execution sandbox via a signed Merkle
 * accumulator of periodic runtime measurements bound to a pre-committed
 * environment manifest, wherein each heartbeat receipt cryptographically
 * chains to the prior accumulator root such that any undisclosed mid-run
 * drift invalidates the chain independent of the sandbox operator).
 */

import { canonicalize, hashHex, resolveSuite, merkleRoot } from './typed.js';
import { signUpstreamReceipt, verifyUpstreamReceipt } from './upstream.js';

const TYPE_MANIFEST = 'pbs.manifest';
const TYPE_ATTESTATION = 'pbs.attestation';

/** Deterministic root over the six manifest fields. */
export function manifestEnvRoot(env, suite) {
  const s = suite || resolveSuite('sha-256');
  const leaves = [
    hashHex(canonicalize({ k: 'image_digests', v: [...(env.image_digests || [])].sort() }), s),
    hashHex(canonicalize({ k: 'kernel_modules', v: [...(env.kernel_modules || [])].sort() }), s),
    hashHex(canonicalize({ k: 'package_index', v: String(env.package_index || '') }), s),
    hashHex(canonicalize({ k: 'egress_acl', v: env.egress_acl || {} }), s),
    hashHex(canonicalize({ k: 'gpu_firmware', v: String(env.gpu_firmware || '') }), s),
    hashHex(canonicalize({ k: 'attestor_kid', v: String(env.attestor_kid || '') }), s),
  ];
  return merkleRoot(leaves, s);
}

/**
 * Compute a heartbeat leaf for one measurement.
 * measurement = { artifact_id, measured_digest, ts }
 */
export function heartbeatLeaf(heartbeat_seq, measurement, suite) {
  const s = suite || resolveSuite('sha-256');
  return hashHex(canonicalize({
    heartbeat_seq,
    artifact_id: String(measurement.artifact_id),
    measured_digest: String(measurement.measured_digest),
    ts: Number(measurement.ts),
  }), s);
}

/**
 * foldHeartbeat — fold new measurement leaves into a running accumulator.
 * Returns { delta_root, new_accumulator_root, leaves_in_order }.
 *
 * The accumulator is folded like a linear chained Merkle: for a heartbeat
 * with leaves L_1..L_k added on top of prior root R_prev:
 *   delta_root = merkleRoot(L_1..L_k, sorted-preserving-order)
 *   new_accumulator_root = H( R_prev || delta_root )
 *
 * This is deterministic, cheap, verifiable, and grows in O(1) per heartbeat.
 */
export function foldHeartbeat(prior_root, measurements, heartbeat_seq, suite) {
  const s = suite || resolveSuite('sha-256');
  const leaves = measurements.map(m => heartbeatLeaf(heartbeat_seq, m, s));
  // preserve chronological order in the delta root — do NOT sort
  const delta_root = leaves.length
    ? merkleRootOrdered(leaves, s)
    : '0'.repeat(s.digest_len * 2);
  const new_accumulator_root = hashHex(String(prior_root) + delta_root, s);
  return { delta_root, new_accumulator_root, leaves_in_order: leaves };
}

/** Order-preserving Merkle root (unlike merkleRoot which sorts). */
function merkleRootOrdered(leaves, suite) {
  const s = suite || resolveSuite('sha-256');
  if (leaves.length === 0) return '0'.repeat(s.digest_len * 2);
  let level = [...leaves];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = i + 1 < level.length ? level[i + 1] : a;
      next.push(hashHex(a + b, s));
    }
    level = next;
  }
  return level[0];
}

/**
 * signPbsManifest — issued at sandbox provisioning by the external attestor.
 *
 * env = { image_digests[], kernel_modules[], package_index, egress_acl,
 *         gpu_firmware, attestor_kid, run_id, tenant_id }
 */
export function signPbsManifest(env, signer, opts = {}) {
  if (!env.image_digests || !env.kernel_modules) throw new Error('missing_env_fields');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const env_root = manifestEnvRoot(env, suite);
  const payload = {
    env_root,
    image_digests: [...env.image_digests].sort(),
    kernel_modules: [...env.kernel_modules].sort(),
    package_index: env.package_index,
    egress_acl: env.egress_acl,
    gpu_firmware: env.gpu_firmware,
    attestor_kid: env.attestor_kid,
    initial_accumulator_root: env_root, // heartbeat chain starts from env_root
  };
  return signUpstreamReceipt(TYPE_MANIFEST, payload, {
    run_id: env.run_id, tenant_id: env.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/**
 * signPbsAttestation — issued every heartbeat while the run is live.
 *
 * beat = {
 *   run_id, tenant_id, heartbeat_seq,
 *   prior_accumulator_root, measurements: [{ artifact_id, measured_digest, ts }...]
 * }
 */
export function signPbsAttestation(beat, signer, opts = {}) {
  if (!Number.isInteger(beat.heartbeat_seq) || beat.heartbeat_seq < 1) {
    throw new Error('bad_heartbeat_seq');
  }
  if (!beat.prior_accumulator_root) throw new Error('missing_prior_root');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const { delta_root, new_accumulator_root, leaves_in_order } =
    foldHeartbeat(beat.prior_accumulator_root, beat.measurements || [], beat.heartbeat_seq, suite);

  const payload = {
    heartbeat_seq: beat.heartbeat_seq,
    prior_accumulator_root: beat.prior_accumulator_root,
    delta_root,
    new_accumulator_root,
    measurements: beat.measurements || [],
    measurement_leaves: leaves_in_order,
  };
  return signUpstreamReceipt(TYPE_ATTESTATION, payload, {
    run_id: beat.run_id, tenant_id: beat.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/**
 * verifyPbsAttestationChain — deterministic re-check of an entire heartbeat
 * chain against a starting manifest. Returns { ok, reason?, broken_at? }.
 *
 * @param manifestReceipt   the signed pbs.manifest receipt
 * @param heartbeats        ordered array of pbs.attestation receipts
 * @param verifyFn, pubBytes for signature verification
 */
export function verifyPbsAttestationChain(manifestReceipt, heartbeats, verifyFn, pubBytes, opts = {}) {
  const manOk = verifyUpstreamReceipt(manifestReceipt, TYPE_MANIFEST, verifyFn, pubBytes, opts);
  if (!manOk.ok) return { ok: false, reason: 'manifest_' + manOk.reason };

  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  let expected_prior = manifestReceipt.payload.initial_accumulator_root;
  let expected_seq = 1;

  for (let i = 0; i < heartbeats.length; i++) {
    const hb = heartbeats[i];
    const hbOk = verifyUpstreamReceipt(hb, TYPE_ATTESTATION, verifyFn, pubBytes, opts);
    if (!hbOk.ok) return { ok: false, reason: 'heartbeat_' + hbOk.reason, broken_at: i };

    if (hb.payload.heartbeat_seq !== expected_seq) {
      return { ok: false, reason: 'seq_gap', broken_at: i };
    }
    if (hb.payload.prior_accumulator_root !== expected_prior) {
      return { ok: false, reason: 'chain_break', broken_at: i };
    }
    // recompute delta_root and new_accumulator_root
    const { delta_root, new_accumulator_root } = foldHeartbeat(
      expected_prior, hb.payload.measurements, hb.payload.heartbeat_seq, suite);
    if (delta_root !== hb.payload.delta_root) return { ok: false, reason: 'delta_mismatch', broken_at: i };
    if (new_accumulator_root !== hb.payload.new_accumulator_root) {
      return { ok: false, reason: 'accumulator_mismatch', broken_at: i };
    }

    expected_prior = hb.payload.new_accumulator_root;
    expected_seq += 1;
  }

  return { ok: true, final_accumulator_root: expected_prior, heartbeats_verified: heartbeats.length };
}

// legacy per-receipt verify shims (used by server routes)
export function verifyPbsManifest(env, verifyFn, pubBytes, opts) {
  return verifyUpstreamReceipt(env, TYPE_MANIFEST, verifyFn, pubBytes, opts);
}
export function verifyPbsAttestation(env, verifyFn, pubBytes, opts) {
  return verifyUpstreamReceipt(env, TYPE_ATTESTATION, verifyFn, pubBytes, opts);
}

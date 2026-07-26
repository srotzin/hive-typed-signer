/**
 * perimeter.js — Perimeter Bond.
 *
 * HC-2026-019. Exploit-class Protected Flow. Bounds every outbound
 * side-effect against a signed manifest of allowed target systems.
 *
 * Novel core: EBPF-BYTECODE-BOUND ENFORCEMENT.
 * Perimeter Bond doesn't just DECLARE a target manifest — it installs an
 * eBPF program in the sandbox kernel that intercepts every outbound
 * syscall (connect, sendmsg, DNS) and consults the bond. The bond is
 * cryptographically bound to the eBPF program's compiled bytecode hash;
 * tampering with the eBPF program breaks the bond signature. This is
 * the difference between "we promise we blocked it" and "here's
 * cryptographic proof of the actual enforcement code that was running
 * when the call was refused."
 *
 * Two receipt types:
 *
 *   perimeter.manifest — issued at run start.
 *     Binds: allowed_targets (list of {host, port_range, protocol}),
 *     ebpf_program_hash (SHA-256 of the compiled BPF bytecode),
 *     ebpf_program_kid (attestor identity that signed the eBPF program),
 *     enforcement_mode ('kernel_drop' | 'log_only').
 *
 *   perimeter.attempt — issued per outbound connect() attempt.
 *     Binds: target_host, target_port, target_protocol, resolution
 *     ('allowed' | 'refused'), matched_manifest_rule_id, kernel_syscall_ts,
 *     ebpf_program_hash (must match the manifest — proof the enforcement
 *     code did not change between manifest issue and attempt).
 *
 * Patent Pending HC-2026-019 (a method for cryptographically binding an
 * outbound network enforcement program's compiled bytecode to a signed
 * pre-effect reach manifest for an autonomous-agent execution sandbox,
 * such that each interception receipt carries the enforcement bytecode
 * hash and verifies against the manifest, and wherein tampering with the
 * enforcement program invalidates all subsequent interception receipts
 * independent of the sandbox operator).
 */

import { canonicalize, hashHex, resolveSuite } from './typed.js';
import { signUpstreamReceipt, verifyUpstreamReceipt } from './upstream.js';

const TYPE_MANIFEST = 'perimeter.manifest';
const TYPE_ATTEMPT = 'perimeter.attempt';

/** Compute a canonical digest over the allowed-targets rule set. */
export function targetsDigest(targets, suite) {
  const s = suite || resolveSuite('sha-256');
  const sorted = [...targets].map(t => ({
    host: String(t.host),
    port_lo: Number(t.port_lo || t.port_range?.[0] || 0),
    port_hi: Number(t.port_hi || t.port_range?.[1] || 65535),
    protocol: String(t.protocol || 'tcp'),
  })).sort((a, b) => (a.host + a.protocol + a.port_lo).localeCompare(b.host + b.protocol + b.port_lo));
  return hashHex(canonicalize({ targets: sorted }), s);
}

/**
 * signPerimeterManifest — issued at run start.
 * m = { run_id, tenant_id, allowed_targets, ebpf_program_hash,
 *       ebpf_program_kid, enforcement_mode }
 */
export function signPerimeterManifest(m, signer, opts = {}) {
  if (!m.ebpf_program_hash) throw new Error('missing_ebpf_hash');
  if (!Array.isArray(m.allowed_targets)) throw new Error('missing_targets');
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const payload = {
    allowed_targets: m.allowed_targets,
    targets_digest: targetsDigest(m.allowed_targets, suite),
    ebpf_program_hash: m.ebpf_program_hash,
    ebpf_program_kid: m.ebpf_program_kid,
    enforcement_mode: m.enforcement_mode || 'kernel_drop',
  };
  return signUpstreamReceipt(TYPE_MANIFEST, payload, {
    run_id: m.run_id, tenant_id: m.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/**
 * signPerimeterAttempt — issued per outbound connect() attempt.
 * a = { run_id, tenant_id, target_host, target_port, target_protocol,
 *       resolution, matched_manifest_rule_id, kernel_syscall_ts,
 *       ebpf_program_hash }
 */
export function signPerimeterAttempt(a, signer, opts = {}) {
  if (!a.target_host) throw new Error('missing_target');
  if (!a.resolution) throw new Error('missing_resolution');
  const payload = {
    target_host: a.target_host,
    target_port: a.target_port,
    target_protocol: a.target_protocol || 'tcp',
    resolution: a.resolution,
    matched_manifest_rule_id: a.matched_manifest_rule_id || null,
    kernel_syscall_ts: a.kernel_syscall_ts,
    ebpf_program_hash: a.ebpf_program_hash,
  };
  return signUpstreamReceipt(TYPE_ATTEMPT, payload, {
    run_id: a.run_id, tenant_id: a.tenant_id, ttl_seconds: opts.ttl_seconds,
  }, signer, opts);
}

/** Verify an attempt receipt AGAINST a manifest — the eBPF hash must match. */
export function verifyPerimeterAttemptAgainstManifest(attempt, manifest, verifyFn, pubBytes, opts = {}) {
  const a = verifyUpstreamReceipt(attempt, TYPE_ATTEMPT, verifyFn, pubBytes, opts);
  if (!a.ok) return a;
  const m = verifyUpstreamReceipt(manifest, TYPE_MANIFEST, verifyFn, pubBytes, opts);
  if (!m.ok) return { ok: false, reason: 'manifest_' + m.reason };
  if (attempt.payload.ebpf_program_hash !== manifest.payload.ebpf_program_hash) {
    return { ok: false, reason: 'ebpf_hash_mismatch' };
  }
  if (attempt.run_id !== manifest.run_id) return { ok: false, reason: 'run_id_mismatch' };
  return { ok: true };
}

export const verifyPerimeterManifest = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_MANIFEST, v, pk, o);
export const verifyPerimeterAttempt = (env, v, pk, o) => verifyUpstreamReceipt(env, TYPE_ATTEMPT, v, pk, o);

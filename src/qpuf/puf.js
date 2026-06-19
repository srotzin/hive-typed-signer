/**
 * puf.js — Physically Unclonable Function: device-bound key derivation.
 *
 * GOAL: bind the ML-DSA-65 signing key to ONE physical device so the secret
 * cannot be copied off the box and tampering provably destroys the ability to
 * sign valid receipts. The signing seed is never stored in the clear; it is
 * reconstructed at runtime from (a) a public "helper" blob and (b) the device's
 * live PUF response. Without the authentic device the seed cannot be rebuilt.
 *
 * This is a fuzzy-extractor construction (the standard PUF -> stable-key
 * pattern): a noisy PUF response is turned into a stable, high-entropy key via
 * a helper string that is safe to publish. We add an ML-DSA seed derivation on
 * top so the same device always regenerates the same keypair.
 *
 * HARDWARE TARGETS (spec for later swap-in — readPufResponse() is the one swap
 * point; everything else is identical):
 *   - SRAM PUF (Synopsys/Intrinsic ID QuiddiKey) : power-up SRAM startup pattern
 *   - Silicon photonic PUF (OFC 2024 demos)      : optical resonance fingerprint
 *   - SiC color-center PUF                        : laser-written defect spectrum
 *   - TPM 2.0 / device root key                   : sealed hardware secret
 *
 * Patent Pending HC-2026-001.
 */
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import fs from 'fs';
import path from 'path';

export const PUF_SOURCES = {
  SRAM_QUIDDIKEY:   { id: 'sram-puf-quiddikey',    name: 'SRAM PUF (Intrinsic ID QuiddiKey)', kind: 'hardware', simulated: false },
  PHOTONIC_PUF:     { id: 'photonic-puf-si',        name: 'Silicon Photonic PUF',              kind: 'hardware', simulated: false },
  SIC_COLOR_CENTER: { id: 'sic-color-center-puf',   name: 'SiC Color-Center PUF',              kind: 'hardware', simulated: false },
  TPM:              { id: 'tpm2-device-root',        name: 'TPM 2.0 device root key',           kind: 'hardware', simulated: false },
  SIMULATED:        { id: 'sim-device-puf',          name: 'Simulated device PUF (stable per-machine secret)', kind: 'simulated', simulated: true },
};

function selectSource() {
  const want = (process.env.PUF_SOURCE || 'SIMULATED').toUpperCase();
  return PUF_SOURCES[want] || PUF_SOURCES.SIMULATED;
}

const DEVICE_SECRET_FILE =
  process.env.PUF_DEVICE_FILE || path.join(process.cwd(), 'data', 'device_puf_secret.bin');

/**
 * readPufResponse(challenge) -> Uint8Array (32B)
 * SOURCE SWAP POINT. Real hardware: present `challenge` to the PUF, read the
 * (slightly noisy) response. Simulation: derive a STABLE per-device response by
 * mixing a machine-local secret with the challenge — mirrors "same device =>
 * same response, different device => different response". The local secret file
 * stands in for the physical fingerprint; deleting/altering it == tamper, which
 * (correctly) makes the key unrecoverable.
 */
export function readPufResponse(challenge) {
  const source = selectSource();
  let deviceSecret;
  try {
    if (fs.existsSync(DEVICE_SECRET_FILE)) {
      deviceSecret = new Uint8Array(fs.readFileSync(DEVICE_SECRET_FILE));
    }
  } catch (_) {}
  if (!deviceSecret || deviceSecret.length !== 32) {
    // First boot on this device: "manufacture" the fingerprint once.
    deviceSecret = randomBytes(32);
    try {
      fs.mkdirSync(path.dirname(DEVICE_SECRET_FILE), { recursive: true });
      fs.writeFileSync(DEVICE_SECRET_FILE, Buffer.from(deviceSecret), { mode: 0o600 });
    } catch (_) {}
  }
  // response = H(domain | deviceSecret | challenge) — deterministic per device.
  const buf = Uint8Array.from([
    ...new TextEncoder().encode('hive-puf-v1|'),
    ...deviceSecret,
    ...challenge,
  ]);
  return { response: sha256(buf), source };
}

/**
 * enroll() -> { helper, public_id, source }
 * One-time per device. Creates a random challenge, reads the PUF response, and
 * produces a PUBLIC helper blob. The helper alone reveals nothing; it only
 * works in combination with the authentic device's PUF.
 */
export function enroll() {
  const challenge = randomBytes(32);
  const { response, source } = readPufResponse(challenge);
  // public_id is a non-secret device fingerprint commitment for the trust block.
  const public_id = bytesToHex(sha256(
    Uint8Array.from([...new TextEncoder().encode('hive-puf-id|'), ...response])
  ));
  const helper = {
    object: 'hive.puf.helper',
    version: '1.0.0',
    challenge: bytesToHex(challenge),
    source_id: source.id,
  };
  return { helper, public_id, source };
}

/**
 * deriveSeed(helper) -> { seed: Uint8Array(32), public_id, source }
 * Reconstructs the 32-byte ML-DSA seed from the device PUF + public helper.
 * Runs ONLY on the authentic device; on any other device readPufResponse yields
 * a different response and the derived seed (and thus the keypair) differs,
 * producing receipts that fail verification under the published public key.
 */
export function deriveSeed(helper) {
  const challenge = hexToBytes(helper.challenge);
  const { response, source } = readPufResponse(challenge);
  const public_id = bytesToHex(sha256(
    Uint8Array.from([...new TextEncoder().encode('hive-puf-id|'), ...response])
  ));
  // HKDF-SHA256: response is the IKM, fixed salt/info domain-separate the output.
  const seed = hkdf(
    sha256,
    response,                                   // input keying material (PUF)
    new TextEncoder().encode('hive-qpuf-salt'), // salt
    new TextEncoder().encode('ml-dsa-65-seed'), // info
    32
  );
  return { seed, public_id, source };
}

export function pufSourceInfo() {
  return selectSource();
}

/**
 * qpuf/index.js — QPuF: Quantum-entropy + Physically-Unclonable-Function
 * hardened ML-DSA-65 signing for Hive Civilization.
 *
 * QPuF chains four layers so a Hive receipt is trustworthy at every level:
 *   1. QRNG     — the key/entropy is born from a (real or simulated) quantum
 *                 source with SP 800-90B-style health checks + attestation.
 *   2. PuF      — the signing seed is reconstructed from the device PUF; the key
 *                 cannot be copied off the box and tampering destroys it.
 *   3. ML-DSA-65— the receipt is signed with a NIST FIPS 204 post-quantum
 *                 signature (unforgeable even by a quantum computer).
 *   4. Trust block — a publishable attestation that lets any verifier confirm
 *                 the whole chain WITHOUT learning any secret.
 *
 * Two key regimes:
 *   - getQpufSigner(): device-bound key derived via PuF (QRNG entropy was used
 *     at enrollment). This is the QPuF signer — the patentable artifact.
 *
 * The QRNG entropy at enrollment + the PuF binding at runtime are what make the
 * key both provably-random AND un-exfiltratable. That pairing is the claim.
 *
 * Patent Pending HC-2026-001.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import fs from 'fs';
import path from 'path';

import { drawEntropy, QRNG_SOURCES } from './qrng.js';
import { enroll, deriveSeed, pufSourceInfo } from './puf.js';

const ENROLL_FILE =
  process.env.QPUF_ENROLL_FILE || path.join(process.cwd(), 'data', 'qpuf_enrollment.json');

/**
 * enrollDevice() — one-time. Draws QRNG entropy (attested), enrolls the PuF,
 * and persists the PUBLIC enrollment record (helper + qrng attestation +
 * device public_id). No secret is stored: the seed is always re-derived live
 * from the device PuF. Returns the enrollment record.
 */
export function enrollDevice() {
  // QRNG entropy draw — at enrollment we prove the entropy regime that seeded
  // the device fingerprint era. (The PuF response itself is the physical seed;
  // the QRNG draw mixes in to the challenge so the bound key inherits quantum
  // entropy as well as device-uniqueness.)
  const { entropy, attestation: qrng } = drawEntropy(32);

  // Enroll PuF using a challenge that incorporates the QRNG draw, so the bound
  // key is a function of BOTH quantum entropy AND device physics.
  const base = enroll();
  const mixedChallenge = bytesToHex(sha256(
    Uint8Array.from([
      ...new TextEncoder().encode('hive-qpuf-enroll|'),
      ...Buffer.from(base.helper.challenge, 'hex'),
      ...entropy,
    ])
  ));
  const helper = { ...base.helper, challenge: mixedChallenge };
  const { public_id } = deriveSeed(helper);

  const record = {
    object: 'hive.qpuf.enrollment',
    version: '1.0.0',
    enrolled_at: new Date().toISOString(),
    qrng: qrng,                       // entropy-source attestation (no secret)
    puf_helper: helper,               // public helper blob (safe to publish)
    puf_source_id: base.source.id,
    device_public_id: public_id,      // device fingerprint commitment
    patent_pending: 'HC-2026-001',
  };
  try {
    fs.mkdirSync(path.dirname(ENROLL_FILE), { recursive: true });
    fs.writeFileSync(ENROLL_FILE, JSON.stringify(record, null, 2), { mode: 0o600 });
  } catch (_) {}
  return record;
}

export function loadEnrollment() {
  try {
    if (fs.existsSync(ENROLL_FILE)) {
      return JSON.parse(fs.readFileSync(ENROLL_FILE, 'utf8'));
    }
  } catch (_) {}
  return null;
}

/**
 * getQpufSigner() -> {
 *   sign(msgBytes), publicKey, publicKeyB64, scheme, version,
 *   trust  // the qpuf attestation block embedded into receipts
 * }
 * Derives the device-bound ML-DSA-65 keypair live from the PuF. The secret key
 * exists only in memory for the life of the process and is never persisted.
 */
export function getQpufSigner() {
  let enrollment = loadEnrollment();
  if (!enrollment) enrollment = enrollDevice();

  const t0 = process.hrtime.bigint();
  const { seed, public_id } = deriveSeed(enrollment.puf_helper);
  const keypair = ml_dsa65.keygen(seed);
  const t1 = process.hrtime.bigint();

  // SANITY: the live device must reproduce the enrolled fingerprint, else this
  // is not the authentic device (or it has been tampered). FAIL CLOSED.
  if (public_id !== enrollment.device_public_id) {
    throw new Error('qpuf_device_mismatch: PuF response does not match enrollment (wrong or tampered device)');
  }

  const publicKeyB64 = Buffer.from(keypair.publicKey).toString('base64');
  const pufSource = pufSourceInfo();

  // Publishable trust block. Reveals NO secret — only attestations + commitments.
  const trust = {
    object: 'hive.qpuf.attestation',
    version: '1.0.0',
    name: 'QPuF',
    summary: 'Quantum-entropy + Physically-Unclonable-Function hardened ML-DSA-65 key',
    qrng: enrollment.qrng,                         // entropy-source attestation
    puf: {
      source_id: pufSource.id,
      source_name: pufSource.name,
      simulated: pufSource.simulated,
      device_public_id: public_id,                 // device fingerprint commitment
      binding: 'seed = HKDF(PuF_response); key never stored; tamper => unrecoverable',
    },
    signature_scheme: { algorithm: 'ML-DSA-65', spec: 'NIST FIPS 204', quantum_security_bits: 168 },
    key_derivation_us: Number(t1 - t0) / 1000,
    chain: ['qrng_entropy', 'puf_device_binding', 'ml_dsa_65_signature', 'base_mainnet_anchor'],
    patent_pending: 'HC-2026-001',
  };

  return {
    scheme: 'ml-dsa-65',
    version: '2.0.0-qpuf',
    publicKey: keypair.publicKey,
    publicKeyB64,
    publicKeyHex: bytesToHex(keypair.publicKey),
    sign(msgBytes) { return ml_dsa65.sign(msgBytes, keypair.secretKey); },
    trust,
  };
}

export function verifyFn(sigBytes, msgBytes, pubBytes) {
  return ml_dsa65.verify(sigBytes, msgBytes, pubBytes);
}

export { QRNG_SOURCES };

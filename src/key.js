/**
 * key.js — fresh DEDICATED ML-DSA-65 demo keypair management.
 *
 * The demo signer key is generated ONCE and persisted to disk so the published
 * public key stays stable across restarts (anyone can re-verify old receipts).
 * This key is ISOLATED from any production key — it only signs public demo
 * receipts. Seed can be supplied via DEMO_SIGNER_SEED_HEX (64 hex chars = 32
 * bytes) for reproducible deploys; otherwise a random seed is generated and
 * saved next to the process.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import fs from 'fs';
import path from 'path';

const SEED_FILE = process.env.DEMO_SEED_FILE || path.join(process.cwd(), 'data', 'demo_signer_seed.hex');

function loadOrCreateSeed() {
  // 1. env-provided seed (preferred for reproducible Render deploys)
  const envSeed = process.env.DEMO_SIGNER_SEED_HEX;
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed)) {
    return hexToBytes(envSeed);
  }
  // 2. persisted seed on disk
  try {
    if (fs.existsSync(SEED_FILE)) {
      const hex = fs.readFileSync(SEED_FILE, 'utf8').trim();
      if (/^[0-9a-fA-F]{64}$/.test(hex)) return hexToBytes(hex);
    }
  } catch (_) {}
  // 3. generate fresh, persist
  const seed = randomBytes(32);
  try {
    fs.mkdirSync(path.dirname(SEED_FILE), { recursive: true });
    fs.writeFileSync(SEED_FILE, bytesToHex(seed), { mode: 0o600 });
  } catch (_) {}
  return seed;
}

const seed = loadOrCreateSeed();
const keypair = ml_dsa65.keygen(seed);

export const SIGNER = {
  scheme: 'ml-dsa-65',
  version: '1.0.0-typed-pq',
  publicKey: keypair.publicKey,
  publicKeyB64: Buffer.from(keypair.publicKey).toString('base64'),
  publicKeyHex: bytesToHex(keypair.publicKey),
  sign(msgBytes) {
    // @noble/post-quantum 0.6.x: sign(message, secretKey)
    return ml_dsa65.sign(msgBytes, keypair.secretKey);
  },
};

export function verifyFn(sigBytes, msgBytes, pubBytes) {
  // @noble/post-quantum 0.6.x: verify(signature, message, publicKey)
  return ml_dsa65.verify(sigBytes, msgBytes, pubBytes);
}

export const PUBLIC_KEY_INFO = {
  issuer: 'did:hive:typed-demo',
  algorithm: 'ML-DSA-65',
  spec: 'NIST FIPS 204',
  publicKey_b64: SIGNER.publicKeyB64,
  publicKey_hex: SIGNER.publicKeyHex,
  publicKey_bytes: keypair.publicKey.length,
  signature_bytes: ml_dsa65.lengths.signature,
  note: 'Dedicated public demo key. Real ML-DSA-65. Isolated from production keys.',
};

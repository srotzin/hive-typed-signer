/**
 * manifest.js — AFiR Model Manifest (P4).
 *
 * TEE-less streaming attestation of the model that served an inference. Signs
 * the model identity — model_id, weights digest (e.g. SHA3), config hash, and
 * serving endpoint — into ONE ML-DSA-65 signature under the published demo key,
 * resolvable publicly by nullifier. No trusted hardware required: the signature
 * itself is the attestation that this exact model/config/endpoint was declared.
 *
 * Rides the identical typed-signer discipline (canonicalize -> hash -> bind one
 * payload -> single PQ signature -> independent recompute + verify). No mock
 * signatures, no Ed25519.
 *
 * What it signs, per manifest:
 *   - model_id      : provider/model name + version
 *   - weights_sha3  : digest over the model weights (caller-supplied, hex)
 *   - config_hash   : digest over the serving config (caller-supplied, hex)
 *   - endpoint      : serving endpoint URL/identifier
 *   - nullifier     : public resolve handle (derived if not supplied)
 *
 * Trust model: zero-secret verification. Only the published ML-DSA-65 public
 * key + the receipt are needed; the verifier recomputes the manifest root and
 * checks the one signature. The nullifier is a deterministic public handle so a
 * third party can resolve "which model signed this" without any secret.
 *
 * Patent Pending.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * manifestRoot — bind the four identity fields into a single ordered root, so
 * any change to model/weights/config/endpoint is detectable.
 */
export function manifestRoot(model_id, weights_sha3, config_hash, endpoint, suite) {
  const s = suite || resolveSuite('sha-256');
  const leaves = [
    hashHex(canonicalize({ k: 'model_id', v: String(model_id) }), s),
    hashHex(canonicalize({ k: 'weights_sha3', v: String(weights_sha3) }), s),
    hashHex(canonicalize({ k: 'config_hash', v: String(config_hash) }), s),
    hashHex(canonicalize({ k: 'endpoint', v: String(endpoint) }), s),
  ];
  return merkleRoot(leaves, s);
}

/**
 * signManifest — seal one model manifest.
 *   base || (manifest_root padded) -> one payload -> one ML-DSA-65 sig.
 *
 * manifest = {
 *   model_id, weights_sha3, config_hash, endpoint, nullifier?
 * }
 */
export function signManifest(manifest, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  if (!manifest || !manifest.model_id) throw new Error('missing_model_id');
  if (!manifest.weights_sha3) throw new Error('missing_weights_sha3');
  if (!manifest.config_hash) throw new Error('missing_config_hash');
  if (!manifest.endpoint) throw new Error('missing_endpoint');

  const manifest_root = manifestRoot(
    manifest.model_id, manifest.weights_sha3, manifest.config_hash, manifest.endpoint, suite,
  );

  // public resolve handle: deterministic over the manifest root unless the
  // caller supplies one. No secret involved.
  const nullifier = manifest.nullifier || ('null_' + hashHex(manifest_root, suite).slice(0, 32));

  const baseFields = {
    object: 'sigr.manifest.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    model_id: String(manifest.model_id),
    weights_sha3: String(manifest.weights_sha3),
    config_hash: String(manifest.config_hash),
    endpoint: String(manifest.endpoint),
    manifest_root,
    nullifier,
    // ARSC: a model identity declaration is a Rise-tier event — it is the
    // anchor every downstream receipt resolves against.
    arsc_tier: 'rise',
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  // bind H(manifest_root || baseDigest)
  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(manifest_root), 0);
  bind.set(hexToBytes(baseDigest), dl);
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
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  if (signer.trust) envelope.trust = signer.trust;

  return { envelope, timing_us: { sign_us: Number(t1 - t0) / 1000 } };
}

/**
 * verifyManifest — independent reconstruction + single signature check.
 *   1. recompute manifest_root from the four carried identity fields
 *   2. re-derive the nullifier (when deterministic) and confirm
 *   3. recompute base + payload, verify the one signature
 */
export function verifyManifest(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;

  // 1. recompute manifest root
  const recRoot = manifestRoot(
    envelope.model_id, envelope.weights_sha3, envelope.config_hash, envelope.endpoint, suite,
  );
  if (recRoot !== envelope.manifest_root) reasons.push('manifest_root_mismatch');

  // 2. re-derive nullifier when it was deterministic (prefix 'null_')
  if (typeof envelope.nullifier === 'string' && envelope.nullifier.startsWith('null_')) {
    const recNull = 'null_' + hashHex(envelope.manifest_root, suite).slice(0, 32);
    if (recNull !== envelope.nullifier) reasons.push('nullifier_mismatch');
  }

  // 3. recompute base + payload
  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
    model_id: envelope.model_id,
    weights_sha3: envelope.weights_sha3,
    config_hash: envelope.config_hash,
    endpoint: envelope.endpoint,
    manifest_root: envelope.manifest_root,
    nullifier: envelope.nullifier,
    arsc_tier: envelope.arsc_tier,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);

  const bind = new Uint8Array(dl * 2);
  bind.set(hexToBytes(envelope.manifest_root || '0'.repeat(dl * 2)), 0);
  bind.set(hexToBytes(baseDigest), dl);
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
    model_id: envelope.model_id,
    nullifier: envelope.nullifier,
  };
}

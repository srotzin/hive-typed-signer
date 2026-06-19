/**
 * test_qpuf.mjs — End-to-end proof that QPuF works and is secure.
 *
 * Proves:
 *  T1  QRNG draws pass SP 800-90B-style health checks + emit attestation
 *  T2  QPuF signer derives a device-bound ML-DSA-65 key + trust block
 *  T3  A QPuF-signed typed receipt VERIFIES under the QPuF public key
 *  T4  STABILITY: re-deriving on the same device yields the SAME key (receipts
 *      stay verifiable across restarts)
 *  T5  TAMPER/CLONE: a different device fingerprint yields a DIFFERENT key whose
 *      receipts FAIL verification under the enrolled public key (un-clonable)
 *  T6  FAIL-CLOSED: a degenerate (all-zero) entropy draw is rejected by health
 *      checks (a bad entropy source can never sign)
 */
import fs from 'fs';
import path from 'path';
import { drawEntropy, healthChecks } from './src/qpuf/qrng.js';
import { getQpufSigner, enrollDevice, loadEnrollment } from './src/qpuf/index.js';
import { buildFragments, signTyped, verifyTyped } from './src/typed.js';
import { verifyFn } from './src/qpuf/index.js';

const DATA = path.join(process.cwd(), 'data');
let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`PASS  ${name} ${extra}`); }
  else { fail++; console.log(`FAIL  ${name} ${extra}`); }
};

function signReceipt(signer, text) {
  const items = text.split(/(?<=[.!?])\s+/).filter(Boolean).map((t, i) => ({ text: t, id: `f${i + 1}` }));
  const fragments = buildFragments(items.length ? items : [{ text, id: 'f1' }]);
  const policy = { sign_types: ['reasoning', 'tool_call', 'final', 'decomposition'], absence_bound: 0, policy_id: 'qpuf-test' };
  const { envelope } = signTyped(fragments, policy, signer, false);
  const fragments_canon = fragments.map(f => ({ fragment_id: f.fragment_id, fragment_type: f.fragment_type, text_hash: f.text_hash, index: f.index }));
  return { envelope, fragments_canon };
}

console.log('=== QPuF end-to-end proof ===\n');

// Clean slate so the test is deterministic.
for (const f of ['device_puf_secret.bin', 'qpuf_enrollment.json', 'demo_signer_seed.hex']) {
  try { fs.unlinkSync(path.join(DATA, f)); } catch (_) {}
}

// T1 — QRNG health + attestation
const { entropy, attestation } = drawEntropy(32);
ok('T1 QRNG health passed', attestation.health_checks.passed, `[source=${attestation.source_id} simulated=${attestation.simulated}]`);
ok('T1 QRNG attestation has commitment, no raw entropy', !!attestation.entropy_commitment && !('entropy' in attestation));

// T2 — QPuF signer derivation
const signer = getQpufSigner();
ok('T2 QPuF signer has device-bound key', signer.publicKey.length > 0 && signer.version === '2.0.0-qpuf');
ok('T2 trust block present', signer.trust && signer.trust.object === 'hive.qpuf.attestation',
   `[key_derivation_us=${signer.trust.key_derivation_us.toFixed(1)}]`);
ok('T2 trust chain complete', JSON.stringify(signer.trust.chain) === JSON.stringify(['qrng_entropy','puf_device_binding','ml_dsa_65_signature','base_mainnet_anchor']));

// T3 — sign + verify
const r1 = signReceipt(signer, 'The agent set pit limiter to 80kph. Final decision: hold position.');
const v1 = verifyTyped(r1.envelope, r1.fragments_canon, verifyFn, signer.publicKey);
ok('T3 QPuF receipt verifies', v1.valid, `[verify_us=${v1.verify_us.toFixed(2)}]`);
ok('T3 envelope carries trust block', r1.envelope.trust && r1.envelope.trust.name === 'QPuF');

// T4 — STABILITY across "restart" (re-derive from same device fingerprint)
const enrollPubId = loadEnrollment().device_public_id;
const signer2 = getQpufSigner();
const sameKey = Buffer.compare(Buffer.from(signer.publicKey), Buffer.from(signer2.publicKey)) === 0;
ok('T4 same device => same key (restart-stable)', sameKey, `[device_public_id stable=${signer2.trust.puf.device_public_id === enrollPubId}]`);
const v1b = verifyTyped(r1.envelope, r1.fragments_canon, verifyFn, signer2.publicKey);
ok('T4 old receipt still verifies after restart', v1b.valid);

// T5 — TAMPER/CLONE: corrupt the device fingerprint, key must change + fail.
const enrolledPub = Buffer.from(signer.publicKey); // capture authentic key
fs.writeFileSync(path.join(DATA, 'device_puf_secret.bin'), Buffer.from(Array(32).fill(0xAB)));
let tamperKeyDiffers = false, tamperVerifyFails = false, mismatchThrown = false;
try {
  const tampered = getQpufSigner(); // should throw on device mismatch (fail-closed)
  tamperKeyDiffers = Buffer.compare(Buffer.from(tampered.publicKey), enrolledPub) !== 0;
  const rT = signReceipt(tampered, 'Forged: pit limiter never set.');
  const vT = verifyTyped(rT.envelope, rT.fragments_canon, verifyFn, enrolledPub); // verify under AUTHENTIC key
  tamperVerifyFails = !vT.valid;
} catch (e) {
  mismatchThrown = /device_mismatch/.test(e.message);
}
ok('T5 tampered device rejected (fail-closed) OR produces non-verifying key',
   mismatchThrown || (tamperKeyDiffers && tamperVerifyFails),
   mismatchThrown ? '[threw qpuf_device_mismatch]' : `[keyDiffers=${tamperKeyDiffers} verifyFails=${tamperVerifyFails}]`);

// T6 — FAIL-CLOSED on bad entropy
const zero = new Uint8Array(32); // all zeros: RCT must catch the long run
const hc = healthChecks(zero);
ok('T6 degenerate entropy fails health check', !hc.passed, `[rct_max_run=${hc.rct.max_run}]`);

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail === 0 ? 0 : 1);

/**
 * test_item1.mjs — Item 1: hardware-signing swap point.
 * Proves: (a) software backend signs + verifies identically through the wrapper,
 * (b) backend attestation is honest (software => accelerated:false/attested:false),
 * (c) trust block merges with QPuF without clobbering it, (d) hardware backends
 * fail closed when selected without silicon (never silent software fallback),
 * (e) the wrapped signer is a drop-in (same publicKey/scheme/version).
 */
import { buildFragments, signTyped, verifyTyped, resolveSuite } from './src/typed.js';
import { verifyFn } from './src/key.js';
import { getQpufSigner } from './src/qpuf/index.js';
import {
  wrapWithBackend, resolveBackend, SIGN_BACKENDS, SIGN_BACKEND_IDS, buildSigningAttestation,
} from './src/hwsign.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log('  PASS', name); }
  else { fail++; console.log('  FAIL', name); }
}

const items = [{ text: 'pit limiter engaged', id: 'f1' }, { text: 'energy deploy 4MJ', id: 'f2' }];
const policy = { sign_types: ['reasoning', 'final'], absence_bound: 0, policy_id: 'item1-test' };
const suite = resolveSuite('sha-256');

console.log('\n=== I1: registry + attestation ===');
ok('I1.1 SOFTWARE is default backend', resolveBackend().id === 'SOFTWARE');
ok('I1.2 registry lists hardware paths', SIGN_BACKEND_IDS.includes('PQSHIELD_FLARE') && SIGN_BACKEND_IDS.includes('XIPHERA_XIP6220B'));
const swAtt = buildSigningAttestation(SIGN_BACKENDS.SOFTWARE);
ok('I1.3 software honest: accelerated=false', swAtt.accelerated === false);
ok('I1.4 software honest: attested=false', swAtt.attested === false);
ok('I1.5 attestation self-committed', typeof swAtt.commitment === 'string' && swAtt.commitment.length === 64);
const hwAtt = buildSigningAttestation(SIGN_BACKENDS.PQSHIELD_FLARE);
ok('I1.6 pqshield honest: accelerated=true,fips=true', hwAtt.accelerated === true && hwAtt.fips_140_3 === true);
ok('I1.7 xiphera carries CAVP cert', buildSigningAttestation(SIGN_BACKENDS.XIPHERA_XIP6220B).cavp === 'A7478');

console.log('\n=== I2: wrapped signer is a drop-in ===');
const base = getQpufSigner();
const wrapped = wrapWithBackend(base); // software
ok('I2.1 same scheme', wrapped.scheme === base.scheme);
ok('I2.2 same version', wrapped.version === base.version);
ok('I2.3 same publicKeyB64', wrapped.publicKeyB64 === base.publicKeyB64);
ok('I2.4 sign() present', typeof wrapped.sign === 'function');

console.log('\n=== I3: sign + verify through software backend ===');
const frags = buildFragments(items, suite);
const { envelope } = signTyped(frags, policy, wrapped, { useMerkle: false });
const canon = frags.map(f => ({ fragment_id: f.fragment_id, fragment_type: f.fragment_type, text_hash: f.text_hash, index: f.index }));
const pub = Uint8Array.from(Buffer.from(envelope.public_key, 'base64'));
const res = verifyTyped(envelope, canon, verifyFn, pub);
ok('I3.1 receipt verifies', res.valid === true);
ok('I3.2 trust carries QPuF attestation', envelope.trust && envelope.trust.object === 'hive.qpuf.attestation');
ok('I3.3 trust ALSO carries signing_backend', envelope.trust.signing_backend && envelope.trust.signing_backend.backend_id === 'SOFTWARE');
ok('I3.4 QPuF qrng NOT clobbered', envelope.trust.qrng && envelope.trust.puf);
ok('I3.5 chain extended with signing_backend', Array.isArray(envelope.trust.chain) && envelope.trust.chain.includes('signing_backend'));

console.log('\n=== I4: hardware backend fails CLOSED (no silent software fallback) ===');
let threw = false, msg = '';
try { wrapWithBackend(base, { backend: 'PQSHIELD_FLARE' }).sign(new Uint8Array([1, 2, 3])); }
catch (e) { threw = true; msg = e.message; }
ok('I4.1 selecting unwired hardware throws on sign()', threw);
ok('I4.2 error names the not-wired condition', /hw_backend_not_wired/.test(msg));
let threw2 = false;
try { resolveBackend('NONSENSE'); } catch (_) { threw2 = true; }
ok('I4.3 unknown backend id rejected', threw2);

console.log('\n=== I5: backend override does not affect identity, only routing ===');
const w2 = wrapWithBackend(base, { backend: 'AWS_F2_FPGA' });
ok('I5.1 attestation reflects selected hardware', w2.signing_backend.backend_id === 'AWS_F2_FPGA' && w2.signing_backend.accelerated === true);
ok('I5.2 publicKey unchanged by backend choice', w2.publicKeyB64 === base.publicKeyB64);

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail === 0 ? 0 : 1);

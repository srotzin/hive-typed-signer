// Carnac digest signing contract tests.
//
// Two layers:
//  1. Pure module (src/carnac.js): valid sign/verify, tampered digest, bad
//     signature, wrong algorithm, malformed digest, casing safety, token check.
//  2. Live HTTP (server.js booted as a child with HIVE_INTERNAL_TOKEN set):
//     auth required on digest sign, public digest verify, tamper fails, and
//     backward compatibility of the existing typed-fragment /sign + /verify.
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { SIGNER, verifyFn } from '../src/key.js';
import {
  signDigestBinding, verifyDigestBinding, normalizeAlgo, isValidSha256Hex, checkInternalToken,
} from '../src/carnac.js';
import { ok, eq, section, summary } from './_assert.js';

const here = dirname(fileURLToPath(import.meta.url));
const DIGEST = 'a'.repeat(64);

// -------------------------------------------------------------------------
// 1. Pure module tests
// -------------------------------------------------------------------------
section('carnac: algo normalization + digest validation');
{
  eq(normalizeAlgo('ml-dsa-65'), 'ML-DSA-65', 'lowercase casing accepted');
  eq(normalizeAlgo('ML-DSA-65'), 'ML-DSA-65', 'uppercase casing accepted');
  eq(normalizeAlgo('  ML-DSA-65 '), 'ML-DSA-65', 'trimmed casing accepted');
  eq(normalizeAlgo('ed25519'), null, 'other algorithm rejected');
  eq(normalizeAlgo('ml-dsa-44'), null, 'sibling algorithm rejected');
  eq(normalizeAlgo(undefined), null, 'missing algorithm rejected');
  ok(isValidSha256Hex(DIGEST), '64-hex accepted');
  ok(!isValidSha256Hex('a'.repeat(63)), '63-hex rejected');
  ok(!isValidSha256Hex('g'.repeat(64)), 'non-hex rejected');
  ok(!isValidSha256Hex(123), 'non-string rejected');
}

section('carnac: valid sign + verify roundtrip');
{
  const out = signDigestBinding(DIGEST, 'ml-dsa-65', SIGNER);
  eq(typeof out.signature, 'string', 'signature is a string');
  eq(typeof out.public_key, 'string', 'public_key is a string');
  eq(out.algo, 'ML-DSA-65', 'algo normalized in response');
  ok(out.signature.length > 3000, 'real ML-DSA-65 signature length');
  ok(!('secretKey' in out) && !('secret' in out), 'no private material returned');
  const r = verifyDigestBinding(DIGEST, out.signature, out.public_key, 'ML-DSA-65', verifyFn);
  ok(r.valid, 'valid binding verifies');
  eq(r.algo, 'ML-DSA-65', 'verify echoes normalized algo');
  // casing safety: verifying with the other casing still succeeds
  const r2 = verifyDigestBinding(DIGEST, out.signature, out.public_key, 'ml-dsa-65', verifyFn);
  ok(r2.valid, 'casing-variant algo still verifies');
}

section('carnac: tampered digest fails');
{
  const out = signDigestBinding(DIGEST, 'ML-DSA-65', SIGNER);
  const r = verifyDigestBinding('b'.repeat(64), out.signature, out.public_key, 'ML-DSA-65', verifyFn);
  ok(!r.valid, 'different digest rejected');
}

section('carnac: bad signature fails');
{
  const out = signDigestBinding(DIGEST, 'ML-DSA-65', SIGNER);
  // flip the first base64 char to a different valid char
  const flipped = (out.signature[0] === 'A' ? 'B' : 'A') + out.signature.slice(1);
  const r = verifyDigestBinding(DIGEST, flipped, out.public_key, 'ML-DSA-65', verifyFn);
  ok(!r.valid, 'tampered signature rejected');
  const r2 = verifyDigestBinding(DIGEST, 'not-a-real-sig', out.public_key, 'ML-DSA-65', verifyFn);
  ok(!r2.valid, 'garbage signature fails closed');
}

section('carnac: wrong key fails');
{
  const out = signDigestBinding(DIGEST, 'ML-DSA-65', SIGNER);
  const wrongKey = Buffer.from('c'.repeat(64), 'hex').toString('base64');
  const r = verifyDigestBinding(DIGEST, out.signature, wrongKey, 'ML-DSA-65', verifyFn);
  ok(!r.valid, 'wrong public key rejected');
}

section('carnac: wrong algorithm fails');
{
  const out = signDigestBinding(DIGEST, 'ML-DSA-65', SIGNER);
  const r = verifyDigestBinding(DIGEST, out.signature, out.public_key, 'ed25519', verifyFn);
  ok(!r.valid, 'wrong algorithm rejected');
  eq(r.algo, null, 'unsupported algo surfaced as null');
}

section('carnac: malformed digest on sign throws, on verify fails closed');
{
  let threw = false;
  try { signDigestBinding('xyz', 'ML-DSA-65', SIGNER); } catch (_) { threw = true; }
  ok(threw, 'sign rejects malformed digest');
  let threw2 = false;
  try { signDigestBinding(DIGEST, 'ed25519', SIGNER); } catch (_) { threw2 = true; }
  ok(threw2, 'sign rejects unsupported algo (no fallback)');
  const r = verifyDigestBinding('short', 'x', 'y', 'ML-DSA-65', verifyFn);
  ok(!r.valid, 'verify fails closed on malformed digest');
}

section('carnac: internal-token check (unit)');
{
  const saved = process.env.HIVE_INTERNAL_TOKEN;
  delete process.env.HIVE_INTERNAL_TOKEN;
  ok(checkInternalToken(undefined), 'no token configured -> allowed');
  process.env.HIVE_INTERNAL_TOKEN = 'super-secret';
  ok(!checkInternalToken(undefined), 'missing header rejected when configured');
  ok(!checkInternalToken('wrong'), 'wrong token rejected');
  ok(checkInternalToken('super-secret'), 'correct token accepted');
  if (saved === undefined) delete process.env.HIVE_INTERNAL_TOKEN;
  else process.env.HIVE_INTERNAL_TOKEN = saved;
}

// -------------------------------------------------------------------------
// 2. Live HTTP tests (auth configured + backward compatibility)
// -------------------------------------------------------------------------
async function post(base, path, body, headers = {}) {
  const r = await fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  let j; try { j = await r.json(); } catch { j = null; }
  return { status: r.status, body: j };
}

async function waitForHealth(base, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(base + '/health'); if (r.ok) return true; } catch (_) {}
    await new Promise(res => setTimeout(res, 100));
  }
  return false;
}

async function httpTests() {
  const PORT = 3971;
  const TOKEN = 'test-internal-token-123';
  const base = `http://127.0.0.1:${PORT}`;
  const child = spawn(process.execPath, [join(here, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), HIVE_INTERNAL_TOKEN: TOKEN, DEMO_SIGNER_SEED_HEX: 'd'.repeat(64) },
    stdio: 'ignore',
  });
  try {
    const up = await waitForHealth(base);
    ok(up, 'server booted for HTTP tests');
    if (!up) return;

    section('carnac HTTP: auth required on digest sign when configured');
    const noAuth = await post(base, '/sign', { payload_sha256: DIGEST, algo: 'ML-DSA-65' });
    eq(noAuth.status, 401, 'digest sign without token -> 401');

    const badAuth = await post(base, '/sign', { payload_sha256: DIGEST, algo: 'ML-DSA-65' }, { 'X-Hive-Internal-Token': 'nope' });
    eq(badAuth.status, 401, 'digest sign with wrong token -> 401');

    section('carnac HTTP: authorized digest sign + public verify');
    const signed = await post(base, '/sign', { payload_sha256: DIGEST, algo: 'ml-dsa-65' }, { 'X-Hive-Internal-Token': TOKEN });
    eq(signed.status, 200, 'authorized digest sign -> 200');
    eq(signed.body.algo, 'ML-DSA-65', 'response algo normalized');
    ok(typeof signed.body.signature === 'string' && typeof signed.body.public_key === 'string', 'flat string fields returned');
    ok(!('secretKey' in signed.body), 'no private material in response');

    const ver = await post(base, '/verify', {
      payload_sha256: DIGEST, signature: signed.body.signature, public_key: signed.body.public_key, algo: 'ML-DSA-65',
    });
    eq(ver.status, 200, 'digest verify -> 200 (public, no token)');
    eq(ver.body.valid, true, 'digest verify valid');
    eq(ver.body.algo, 'ML-DSA-65', 'digest verify echoes algo');

    section('carnac HTTP: tamper + wrong algo fail over the wire');
    const tamper = await post(base, '/verify', {
      payload_sha256: 'b'.repeat(64), signature: signed.body.signature, public_key: signed.body.public_key, algo: 'ML-DSA-65',
    });
    eq(tamper.body.valid, false, 'tampered digest -> valid:false');
    const wrongAlgo = await post(base, '/verify', {
      payload_sha256: DIGEST, signature: signed.body.signature, public_key: signed.body.public_key, algo: 'ed25519',
    });
    eq(wrongAlgo.body.valid, false, 'wrong algo -> valid:false');
    const badDigest = await post(base, '/sign', { payload_sha256: 'zzz', algo: 'ML-DSA-65' }, { 'X-Hive-Internal-Token': TOKEN });
    eq(badDigest.status, 400, 'malformed digest -> 400');

    section('carnac HTTP: backward compatibility of existing /sign + /verify');
    const legacy = await post(base, '/sign', { text: 'Hello world. This is a test. Final answer: 42.' });
    eq(legacy.status, 200, 'legacy text sign -> 200');
    ok(legacy.body.ok === true && legacy.body.envelope, 'legacy typed envelope returned');
    eq(legacy.body.algorithm, 'ML-DSA-65', 'legacy algorithm field preserved');
    ok(Array.isArray(legacy.body.fragments_canon), 'legacy fragments_canon preserved');
    const legacyVer = await post(base, '/verify', { envelope: legacy.body.envelope, fragments: legacy.body.fragments_canon });
    eq(legacyVer.status, 200, 'legacy verify -> 200');
    eq(legacyVer.body.valid, true, 'legacy typed receipt verifies');
  } finally {
    child.kill('SIGKILL');
  }
}

await httpTests();
summary('carnac');

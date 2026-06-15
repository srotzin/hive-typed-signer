/**
 * Hive Typed Signer — Real ML-DSA-65 (NIST FIPS 204) typed-fragment signing + verify.
 *
 * NO mock signatures. NO Ed25519. Every receipt is signed with a real post-quantum
 * ML-DSA-65 signature that verifies under the published demo public key.
 *
 * Backend for the public "try it yourself" demo at thehiveryiq.com/typed-signer/:
 * a visitor pastes text, the service decomposes it into typed fragments, signs the
 * selected set with ONE ML-DSA-65 signature, and the same service (or any third
 * party) verifies it live.
 *
 * Endpoints:
 *   GET  /            service info
 *   GET  /health      health check
 *   GET  /pubkey      published ML-DSA-65 public key (independent verify)
 *   POST /sign        { text | fragments[], sign_types?, agg_mode? } -> typed receipt
 *   POST /verify      { envelope, fragments } -> { valid, reasons, verify_us }
 *
 * Patent Pending HC-2026-001.
 */
import express from 'express';
import cors from 'cors';
import {
  buildFragments, signTyped, verifyTyped, FRAGMENT_TYPES,
} from './src/typed.js';
import { SIGNER, verifyFn, PUBLIC_KEY_INFO } from './src/key.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Hive-Typed-Signer', SIGNER.version);
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});
app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
  res.status(204).end();
});

const DEFAULT_SIGN_TYPES = ['reasoning', 'tool_call', 'final', 'decomposition'];

function textToItems(text) {
  const parts = String(text)
    .split(/(?<=[.!?])\s+|\n+/)
    .map(s => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return [{ text: String(text) }];
  return parts.slice(0, 256).map((t, i) => ({ text: t, id: `f${i + 1}` }));
}

app.get('/', (req, res) => {
  res.json({
    service: 'Hive Typed Signer',
    version: SIGNER.version,
    algorithm: 'ML-DSA-65',
    spec: 'NIST FIPS 204',
    real: true,
    mock: false,
    description: 'Real post-quantum typed-fragment signing + verify. One ML-DSA-65 signature for the whole fragment set.',
    endpoints: {
      'GET /pubkey': 'Published ML-DSA-65 public key',
      'POST /sign': 'Sign pasted text or fragments[] into a typed receipt',
      'POST /verify': 'Independently verify a typed receipt',
      'GET /health': 'Health check',
    },
    fragment_types: FRAGMENT_TYPES,
    patent_pending: 'HC-2026-001',
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

app.get('/pubkey', (req, res) => res.json(PUBLIC_KEY_INFO));

app.post('/sign', (req, res) => {
  try {
    const body = req.body || {};
    let items;
    if (Array.isArray(body.fragments) && body.fragments.length) {
      items = body.fragments.map((f, i) =>
        typeof f === 'string' ? { text: f, id: `f${i + 1}` } : f);
    } else if (typeof body.text === 'string' && body.text.trim()) {
      items = textToItems(body.text);
    } else {
      return res.status(400).json({ error: 'Provide { text } or { fragments: [...] }' });
    }
    const signTypes = Array.isArray(body.sign_types) && body.sign_types.length
      ? body.sign_types.filter(t => FRAGMENT_TYPES.includes(t))
      : DEFAULT_SIGN_TYPES;
    const useMerkle = body.agg_mode === 'merkle';

    const fragments = buildFragments(items);
    const policy = { sign_types: signTypes, absence_bound: 0, policy_id: body.policy_id || 'demo' };
    const { envelope, timing_us } = signTyped(fragments, policy, SIGNER, useMerkle);

    const fragments_canon = fragments.map(f => ({
      fragment_id: f.fragment_id,
      fragment_type: f.fragment_type,
      text_hash: f.text_hash,
      index: f.index,
    }));

    res.json({
      ok: true,
      algorithm: 'ML-DSA-65',
      spec: 'NIST FIPS 204',
      real: true,
      envelope,
      fragments_canon,
      timing_us,
      measured_floor_us: {
        sign: 77.14,
        verify: 30.74,
        note: 'liboqs C floor on a 2-vCPU box (production AVX2 lower). This public endpoint runs pure-JS noble (slower wall time) but produces the identical real ML-DSA-65 signature.',
      },
    });
  } catch (err) {
    res.status(500).json({ error: 'sign_failed', message: err.message });
  }
});

app.post('/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    const fragmentsCanon = body.fragments || body.fragments_canon;
    if (!envelope || !Array.isArray(fragmentsCanon)) {
      return res.status(400).json({ error: 'Provide { envelope, fragments }' });
    }
    const result = verifyTyped(envelope, fragmentsCanon, verifyFn, SIGNER.publicKey);
    res.json({ ...result, verified_at: new Date().toISOString(), patent_pending: 'HC-2026-001' });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

app.listen(PORT, () => {
  console.log(`Hive Typed Signer ${SIGNER.version} on :${PORT}`);
  console.log('Algorithm: ML-DSA-65 (NIST FIPS 204) — real, not mock');
});

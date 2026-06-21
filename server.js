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
  buildFragments, signTyped, verifyTyped, FRAGMENT_TYPES, HASH_SUITES, resolveSuite,
} from './src/typed.js';
import { SIGNER, verifyFn, PUBLIC_KEY_INFO } from './src/key.js';
import { getQpufSigner } from './src/qpuf/index.js';
import { buildTemporalProof, TEMPORAL_TIME_SOURCES } from './src/temporal.js';
import { wrapWithBackend, resolveBackend, SIGN_BACKENDS, SIGN_BACKEND_IDS } from './src/hwsign.js';
// SiGR product suite — each rides the same typed-signer discipline (canonicalize ->
// hash -> bind digests -> ONE ML-DSA-65 signature -> independent recompute + verify).
import { signBillReceipt, verifyBillReceipt, signInvoice, verifyInvoice } from './src/bill.js';
import { signBond, verifyBond, signMeasurement, verifyMeasurement, signSettlement, verifySettlement } from './src/bond.js';
import { signChain, verifyChain } from './src/chain.js';
import { signSubReceipt, verifySubReceipt, signConsensus, verifyConsensus } from './src/consensus.js';
// AFiR-S3 — Agentic Provenance Primitives. Each rides the same typed-signer
// discipline (canonicalize -> hash -> bind -> ONE ML-DSA-65 sig -> recompute +
// verify). Built on SiGR/AFiR/ARSC/AFiR-S2 as substrate, not rebuilt.
import { signToolScope, verifyToolScope } from './src/toolscope.js';         // HC-2026-008
import { signAgenticRun, verifyAgenticRun } from './src/agentic.js';         // HC-2026-009
import { signCern, verifyCern } from './src/cern.js';                        // HC-2026-010 (files first)
import { signReward, verifyReward } from './src/reward.js';                  // HC-2026-011
import { mintToolAnchor, verifyToolAnchor, resolveToolCall, verifyToolSavingsProof } from './src/toolreuse.js';

// item 1: signing-backend swap point. Software today; FPGA/ASIC drop-in later.
// Selected via HIVE_SIGN_BACKEND (default SOFTWARE). The wrapped signer keeps
// the identical interface and merges a backend attestation into the trust block.
const SIGN_BACKEND = resolveBackend();

// QPuF device-bound signer (quantum entropy + PuF). Derived once at boot; the
// secret key lives only in memory. Falls back gracefully if unavailable.
let QPUF = null;
try {
  QPUF = wrapWithBackend(getQpufSigner());
  console.log('QPuF signer ready:', QPUF.version, '| backend:', SIGN_BACKEND.id,
    SIGN_BACKEND.accelerated ? '(hardware-accelerated)' : '(software)');
}
catch (e) { console.error('QPuF init failed (continuing with base signer):', e.message); }

const app = express();
const PORT = process.env.PORT || 3000;

// CORS: the cors package handles both simple requests and OPTIONS preflight.
const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept'],
};
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions)); // explicit preflight for all paths (Express 5 safe)
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Hive-Typed-Signer', SIGNER.version);
  next();
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
      'POST /sign-qpuf': 'QPuF device-bound signing (quantum entropy + PuF)',
      'GET /qpuf/info': 'QPuF trust posture + public key',
      'GET /signing-backends': 'Signing-backend catalog + active selection',
      'POST /sigr/bill': 'SiGR-Bill — signed inference cost/billing receipt',
      'POST /sigr/bill/verify': 'Verify a SiGR-Bill receipt (free)',
      'POST /sigr/bond': 'SiGR-Bond — signed SLA bond + measurements',
      'POST /sigr/bond/verify': 'Verify a SiGR-Bond envelope (free)',
      'POST /sigr/chain': 'SiGR Chain — step-sealed signed agent run (flagship)',
      'POST /sigr/chain/verify': 'Verify a SiGR Chain run (free)',
      'POST /sigr/consensus': 'SiGR-Consensus — signed multi-model panel',
      'POST /sigr/consensus/verify': 'Verify a SiGR-Consensus panel (free)',
      'GET /health': 'Health check',
    },
    products: {
      'SiGR-Bill': 'HC-2026-004',
      'SiGR-Bond': 'HC-2026-005',
      'SiGR Chain': 'HC-2026-006',
      'SiGR-Consensus': 'HC-2026-007',
      'QPuF': 'HC-2026-001',
    },
    fragment_types: FRAGMENT_TYPES,
    patent_pending: 'HC-2026-001',
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

app.get('/pubkey', (req, res) => res.json(PUBLIC_KEY_INFO));

// QPuF info: the published trust posture (no secrets) + the QPuF public key.
app.get('/qpuf/info', (req, res) => {
  if (!QPUF) return res.status(503).json({ error: 'qpuf_unavailable' });
  res.json({
    name: 'QPuF',
    description: 'Quantum-entropy + Physically-Unclonable-Function hardened ML-DSA-65 signing.',
    version: QPUF.version,
    publicKey_b64: QPUF.publicKeyB64,
    publicKey_hex: QPUF.publicKeyHex,
    trust: QPUF.trust,
    signing_backend: QPUF.signing_backend,
    patent_pending: 'HC-2026-001',
  });
});

// item 1: published signing-backend catalog + active selection. No secrets.
app.get('/signing-backends', (req, res) => {
  res.json({
    object: 'hive.signing.backends',
    active: SIGN_BACKEND.id,
    swap_point: 'signer.sign(msgBytes) — software today, FPGA/ASIC drop-in',
    available: SIGN_BACKEND_IDS,
    backends: SIGN_BACKENDS,
    patent_pending: 'HC-2026-001',
  });
});

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

// QPuF signing: identical typed-fragment flow, but signed with the device-bound
// quantum+PuF key and carrying the QPuF trust block in the envelope.
app.post('/sign-qpuf', (req, res) => {
  try {
    if (!QPUF) return res.status(503).json({ error: 'qpuf_unavailable' });
    const body = req.body || {};
    let items;
    if (Array.isArray(body.fragments) && body.fragments.length) {
      items = body.fragments.map((f, i) => (typeof f === 'string' ? { text: f, id: `f${i + 1}` } : f));
    } else if (typeof body.text === 'string' && body.text.trim()) {
      items = textToItems(body.text);
    } else {
      return res.status(400).json({ error: 'Provide { text } or { fragments: [...] }' });
    }
    const signTypes = Array.isArray(body.sign_types) && body.sign_types.length
      ? body.sign_types.filter(t => FRAGMENT_TYPES.includes(t))
      : DEFAULT_SIGN_TYPES;
    const useMerkle = body.agg_mode === 'merkle';
    // item 10: optional ultra-long-life hash suite (default sha-256)
    const hashSuite = (body.hash_suite && HASH_SUITES[String(body.hash_suite).toLowerCase()])
      ? String(body.hash_suite).toLowerCase() : 'sha-256';
    // item 5: optional three-tier temporal proof bound into the signed payload
    const temporal = (body.temporal === true || (body.temporal && typeof body.temporal === 'object'))
      ? buildTemporalProof(typeof body.temporal === 'object' ? body.temporal : {})
      : null;

    const suite = resolveSuite(hashSuite);
    const fragments = buildFragments(items, suite);
    const policy = { sign_types: signTypes, absence_bound: 0, policy_id: body.policy_id || 'qpuf-demo' };
    const { envelope, timing_us } = signTyped(fragments, policy, QPUF, { useMerkle, hashSuite, temporal });

    const fragments_canon = fragments.map(f => ({
      fragment_id: f.fragment_id,
      fragment_type: f.fragment_type,
      text_hash: f.text_hash,
      index: f.index,
    }));

    res.json({
      ok: true,
      mode: 'qpuf',
      algorithm: 'ML-DSA-65',
      spec: 'NIST FIPS 204',
      real: true,
      hardening: 'QPuF (quantum entropy + PuF device binding)',
      signing_backend: SIGN_BACKEND.id,
      accelerated: SIGN_BACKEND.accelerated,
      hash_suite: hashSuite,
      temporal_proof: !!temporal,
      envelope,
      fragments_canon,
      timing_us,
    });
  } catch (err) {
    res.status(500).json({ error: 'qpuf_sign_failed', message: err.message });
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
    // Verify against the public key carried IN the envelope — this is how any
    // independent third party verifies. Works for base AND QPuF receipts. Fall
    // back to the local base key only if the envelope omits its public_key.
    let pubBytes = SIGNER.publicKey;
    if (typeof envelope.public_key === 'string' && envelope.public_key) {
      pubBytes = Uint8Array.from(Buffer.from(envelope.public_key, 'base64'));
    }
    const result = verifyTyped(envelope, fragmentsCanon, verifyFn, pubBytes);
    const qpuf = envelope.trust && envelope.trust.object === 'hive.qpuf.attestation'
      ? { hardening: 'QPuF', qrng_source: envelope.trust.qrng.source_id, puf_device_id: envelope.trust.puf.device_public_id }
      : undefined;
    // item 5/10: surface temporal proof + hash suite as verifier badges
    const temporal = envelope.temporal
      ? { time_source: envelope.temporal.tier1_capture.source.id, wall_iso: envelope.temporal.tier1_capture.wall_iso,
          tiers: ['capture', 'soft_commitment', 'finality'] }
      : undefined;
    const hash_suite = envelope.hash_suite || 'sha-256';
    // item 1: surface the signing-backend attestation carried in the trust block
    const signing_backend = envelope.trust && envelope.trust.signing_backend
      ? { backend_id: envelope.trust.signing_backend.backend_id,
          accelerated: envelope.trust.signing_backend.accelerated,
          attested: envelope.trust.signing_backend.attested,
          fips_140_3: envelope.trust.signing_backend.fips_140_3 }
      : undefined;
    res.json({ ...result, qpuf, temporal, hash_suite, signing_backend, verified_at: new Date().toISOString(), patent_pending: 'HC-2026-001' });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// ---------------------------------------------------------------------------
// SiGR product suite routes — Signed inference Guarantee Receipt
// Each product canonicalizes -> hashes -> binds digests -> ONE ML-DSA-65
// signature, then independently recomputes + verifies. Free verify, pay-to-sign.
// Verify resolves the public key carried IN the envelope (third-party-verifiable),
// falling back to the local signer key.
// ---------------------------------------------------------------------------
function pubFromEnv(env) {
  if (env && typeof env.public_key === 'string' && env.public_key) {
    return Uint8Array.from(Buffer.from(env.public_key, 'base64'));
  }
  return SIGNER.publicKey;
}

// SiGR-Bill (HC-2026-004) — signed cost/billing receipt per inference request.
app.post('/sigr/bill', (req, res) => {
  try {
    const body = req.body || {};
    const reqObj = body.request || body;
    if (!reqObj || reqObj.input_tokens === undefined || reqObj.output_tokens === undefined) {
      return res.status(400).json({ error: 'Provide { request: { request_id, model_id, input_tokens, output_tokens, price_*_micro_usd, ... } }' });
    }
    const { envelope, timing_us } = signBillReceipt(reqObj, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'SiGR-Bill', patent_pending: 'HC-2026-004', envelope, timing_us });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'bill_sign_failed', message: err.message });
  }
});
app.post('/sigr/bill/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.manifest) return res.status(400).json({ error: 'Provide { envelope }' });
    const result = verifyBillReceipt(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'SiGR-Bill', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// SiGR-Bond (HC-2026-005) — signed SLA bond + signed latency/uptime measurements.
app.post('/sigr/bond', (req, res) => {
  try {
    const body = req.body || {};
    if (body.measurement) {
      const m = body.measurement;
      if (!m.bond_id || m.observed_latency_ms === undefined) {
        return res.status(400).json({ error: 'Provide { measurement: { bond_id, request_id, observed_latency_ms, served, seq } }' });
      }
      const envelope = signMeasurement(m, SIGNER, { hashSuite: body.hash_suite });
      return res.json({ ok: true, product: 'SiGR-Bond', kind: 'measurement', patent_pending: 'HC-2026-005', envelope });
    }
    const terms = body.terms || body;
    if (!terms || !terms.bond_id || terms.penalty_micro_usd === undefined) {
      return res.status(400).json({ error: 'Provide { terms: { bond_id, customer_ref, latency_ceiling_ms, uptime_floor_ppm, penalty_micro_usd, ... } } or { measurement: {...} }' });
    }
    const envelope = signBond(terms, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'SiGR-Bond', kind: 'bond', patent_pending: 'HC-2026-005', envelope });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'bond_sign_failed', message: err.message });
  }
});
app.post('/sigr/bond/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || (!envelope.measurement && !envelope.terms)) {
      return res.status(400).json({ error: 'Provide { envelope } (a signed bond or measurement)' });
    }
    const result = envelope.measurement
      ? verifyMeasurement(envelope, verifyFn, pubFromEnv(envelope))
      : verifyBond(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'SiGR-Bond', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// SiGR Chain (flagship, HC-2026-006) — step-sealed signed agent run.
app.post('/sigr/chain', (req, res) => {
  try {
    const body = req.body || {};
    const run = body.run || body;
    if (!run || !run.run_id || !Array.isArray(run.steps) || run.steps.length === 0) {
      return res.status(400).json({ error: 'Provide { run: { run_id, agent_ref, steps: [{ step_id, kind, seq, parents, input, output }] } }' });
    }
    const { envelope, timing_us } = signChain(run, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'SiGR Chain', patent_pending: 'HC-2026-006', envelope, timing_us });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'chain_sign_failed', message: err.message });
  }
});
app.post('/sigr/chain/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !Array.isArray(envelope.steps)) return res.status(400).json({ error: 'Provide { envelope } (a signed chain run)' });
    const result = verifyChain(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'SiGR Chain', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// SiGR-Consensus (HC-2026-007) — signed multi-model consensus panel.
app.post('/sigr/consensus', (req, res) => {
  try {
    const body = req.body || {};
    const panel = body.panel || { panel_id: body.panel_id || 'panel' };
    const method = body.method || 'majority';
    // Sign each member sub-receipt first, then seal the panel over them.
    const members = Array.isArray(body.members) ? body.members : [];
    if (members.length === 0) {
      return res.status(400).json({ error: 'Provide { panel: { panel_id }, method, members: [{ panel_id, model_id, output_digest, score, seq }] }' });
    }
    const subEnvs = members.map((m, i) => signSubReceipt(m, SIGNER, { hashSuite: body.hash_suite }));
    const { envelope, timing_us } = signConsensus(panel, subEnvs, method, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'SiGR-Consensus', patent_pending: 'HC-2026-007', envelope, sub_receipts: subEnvs, timing_us });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'consensus_sign_failed', message: err.message });
  }
});
app.post('/sigr/consensus/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    const subEnvs = Array.isArray(body.sub_receipts) ? body.sub_receipts : [];
    if (!envelope || !envelope.panel_id) return res.status(400).json({ error: 'Provide { envelope, sub_receipts }' });
    const result = verifyConsensus(envelope, subEnvs, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'SiGR-Consensus', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// ===========================================================================
// AFiR-S3 — Agentic Provenance Primitives (HC-2026-008..011)
// Verified agents: receipts for what an agent does, observes, alters, forgets,
// and is rewarded for. All ride the existing ML-DSA-65 signer + zero-secret verify.
// ===========================================================================

// --- Tool-Scope Receipt (BEFORE) — HC-2026-008 ---
app.post('/sigr/toolscope', (req, res) => {
  try {
    const body = req.body || {};
    const scope = body.scope || body;
    if (!scope || !scope.scope_id || !Array.isArray(scope.tools) || scope.tools.length === 0) {
      return res.status(400).json({ error: 'Provide { scope: { scope_id, agent_ref, tools:[{tool_id, tool_hash?}], destructive_tools:[], granted_by } }' });
    }
    const { envelope, timing_us } = signToolScope(scope, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'AFiR-S3 Tool-Scope', patent_pending: 'HC-2026-008', envelope, timing_us });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'toolscope_sign_failed', message: err.message });
  }
});
app.post('/sigr/toolscope/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.scope_id) return res.status(400).json({ error: 'Provide { envelope } (a signed tool-scope)' });
    const result = verifyToolScope(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'AFiR-S3 Tool-Scope', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// --- Agentic Action Receipt (DURING) — HC-2026-009 — thin wrapper over chain.js, SCOPE-GATED ---
app.post('/sigr/agentic', (req, res) => {
  try {
    const body = req.body || {};
    const run = body.run;
    const scopes = Array.isArray(body.scopes) ? body.scopes : [];
    if (!run || !run.run_id || !Array.isArray(run.steps) || run.steps.length === 0) {
      return res.status(400).json({ error: 'Provide { run: { run_id, agent_ref, steps:[{step_id,kind,seq,parents,input,action?,tool_target?,tool_hash?,scope_ref?}] }, scopes:[ signed tool-scope envelopes ] }' });
    }
    const { envelope, timing_us } = signAgenticRun(run, scopes, SIGNER, verifyFn, pubFromEnv, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'AFiR-S3 Agentic Action', patent_pending: 'HC-2026-009', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'agentic_sign_rejected', message: err.message });
  }
});
app.post('/sigr/agentic/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    const scopes = Array.isArray(body.scopes) ? body.scopes : [];
    if (!envelope || !Array.isArray(envelope.steps)) return res.status(400).json({ error: 'Provide { envelope, scopes:[] }' });
    const result = verifyAgenticRun(envelope, scopes, verifyFn, pubFromEnv);
    res.json({ product: 'AFiR-S3 Agentic Action', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// --- AFiR-CERN: Context Ethics & Retention Notarization (DURING) — HC-2026-010 (files first) ---
app.post('/sigr/cern', (req, res) => {
  try {
    const body = req.body || {};
    const mutation = body.mutation || body;
    if (!mutation || !mutation.mutation_type) {
      return res.status(400).json({ error: 'Provide { mutation: { mutation_type, context_before|context_before_digests+root, context_after|..., altered_spans?, integrity_claim } }' });
    }
    const { envelope, timing_us } = signCern(mutation, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'AFiR-CERN', patent_pending: 'HC-2026-010', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'cern_sign_rejected', message: err.message });
  }
});
app.post('/sigr/cern/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.mutation_type) return res.status(400).json({ error: 'Provide { envelope } (a signed CERN receipt)' });
    const result = verifyCern(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'AFiR-CERN', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// --- Reward-Attestation Receipt (AFTER) — HC-2026-011 ---
app.post('/sigr/reward', (req, res) => {
  try {
    const body = req.body || {};
    const reward = body.reward_attestation || body;
    if (!reward || reward.reward === undefined || !reward.reward_model_hash) {
      return res.status(400).json({ error: 'Provide { reward_attestation: { trajectory_root|step_receipt_digests, reward, reward_model_hash, algo, episode_id? } }' });
    }
    const { envelope, timing_us } = signReward(reward, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'AFiR-S3 Reward-Attestation', patent_pending: 'HC-2026-011', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'reward_sign_rejected', message: err.message });
  }
});
app.post('/sigr/reward/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || envelope.reward === undefined) return res.status(400).json({ error: 'Provide { envelope } (a signed reward receipt)' });
    const result = verifyReward(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'AFiR-S3 Reward-Attestation', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// --- Tool-call trust-anchor reuse (AFiR-S3 §3, byte-identity R2) — mint + verify ---
app.post('/sigr/toolanchor', (req, res) => {
  try {
    const body = req.body || {};
    const call = body.call || body;
    if (!call || !call.tool_id) return res.status(400).json({ error: 'Provide { call: { tool_id, tool_hash?, input, output, deterministic:true, holder } }' });
    const { anchor, timing_us } = mintToolAnchor(call, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'AFiR-S3 Tool Anchor', patent_pending: 'HC-2026-008', anchor, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'toolanchor_mint_rejected', message: err.message });
  }
});
app.post('/sigr/toolanchor/verify', (req, res) => {
  try {
    const body = req.body || {};
    const anchor = body.anchor !== undefined ? body.anchor : body;
    if (!anchor || !anchor.identity_key) return res.status(400).json({ error: 'Provide { anchor }' });
    const result = verifyToolAnchor(anchor, verifyFn, pubFromEnv(anchor));
    res.json({ product: 'AFiR-S3 Tool Anchor', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

app.listen(PORT, () => {
  console.log(`Hive Typed Signer ${SIGNER.version} on :${PORT}`);
  console.log('Algorithm: ML-DSA-65 (NIST FIPS 204) — real, not mock');
});

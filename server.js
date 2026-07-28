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
import { signGca, verifyGca } from './src/gca.js';                            // GCA — per-claim grounding attestation
import { signGitm, verifyGitm } from './src/gitm.js';                         // GiTM — cross-signal anomaly flag
import { signCacheEntry, verifyCacheEntry } from './src/cachesign.js';         // P3 — KV cache prefix signing
import { signManifest, verifyManifest } from './src/manifest.js';              // P4 — model manifest attestation
import { signMir, verifyMir } from './src/mir.js';                              // MiR — model-identity & relineage
// Upstream Signed Pre-Effect Attestation (USPA) — the seven primitives that fire
// BEFORE an effect lands, sharing one signed envelope (src/upstream.js). Each
// binds a small declared payload into ONE ML-DSA-65 signature over a
// recomputable payload_root, and carries its own freshness window.
import { signUpstreamReceipt, verifyUpstreamReceipt, gateOnReceipts, DEFAULT_TTL, USAP_VERSION } from './src/upstream.js';
import { signPbsManifest, signPbsAttestation, verifyPbsManifest, verifyPbsAttestation, verifyPbsAttestationChain } from './src/pbs.js';                    // HC-2026-016
import { signPolicyMutation, signPolicyReadBinding, verifyPolicyMutation, verifyPolicyReadBinding, verifyPolicyMutationInHistory } from './src/refusal.js'; // HC-2026-017
import { signHowlerDrift, signHowlerCapability, signHowlerContamination, verifyHowlerDrift, verifyHowlerCapability, verifyHowlerContamination, verifyHowlerCapabilityWithSae } from './src/howler.js'; // HC-2026-018
import { signPerimeterManifest, signPerimeterAttempt, verifyPerimeterManifest, verifyPerimeterAttempt, verifyPerimeterAttemptAgainstManifest } from './src/perimeter.js'; // HC-2026-019
import { signDiurnalRegime, signDiurnalAttestation, verifyDiurnalRegime, verifyDiurnalAttestation, verifyDiurnalThresholdSatisfied } from './src/diurnal.js';             // HC-2026-020
import { signEgressManifest, signEgressMeasurement, verifyEgressManifest, verifyEgressMeasurement } from './src/egress.js';                                               // HC-2026-021
import { signForensicCredential, signForensicAnalysis, verifyForensicCredential, verifyForensicAnalysis } from './src/forensic.js';                                       // HC-2026-022
// Carnac digest signing contract — narrow backwards-compatible add-on to /sign
// and /verify: bind + sign a caller-supplied SHA-256 digest with the same real
// ML-DSA-65 engine. Never touches typed-fragment clients.
import {
  signDigestBinding, verifyDigestBinding, normalizeAlgo, isValidSha256Hex,
  checkInternalToken, authConfigured,
} from './src/carnac.js';

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

// Lightweight fixed-window in-memory rate limiter for the public Carnac digest
// verify path. Keyed by client IP. Bounds abuse without adding a dependency.
const RL_WINDOW_MS = 60_000;
const RL_MAX = Number(process.env.CARNAC_VERIFY_RATE_MAX || 240);
const rlBuckets = new Map();
function rateLimited(key) {
  const now = Date.now();
  if (rlBuckets.size > 10_000) {
    for (const [k, v] of rlBuckets) if (now >= v.reset) rlBuckets.delete(k);
  }
  let e = rlBuckets.get(key);
  if (!e || now >= e.reset) { e = { count: 0, reset: now + RL_WINDOW_MS }; rlBuckets.set(key, e); }
  e.count++;
  return e.count > RL_MAX;
}

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
      'POST /sigr/gca': 'GCA — per-claim grounding attestation (proves support, not truth)',
      'POST /sigr/gca/verify': 'Verify a GCA receipt (free)',
      'POST /sigr/gitm': 'GiTM — cross-signal anomaly flag (asserts provenance anomaly only)',
      'POST /sigr/gitm/verify': 'Verify a GiTM receipt (free)',
      'POST /sigr/cachesign': 'AFiR KV Cache Signing — sign vLLM prefix entries at write time',
      'POST /sigr/cachesign/verify': 'Verify a KV cache receipt (free)',
      'POST /sigr/manifest': 'AFiR Model Manifest — TEE-less streaming model attestation',
      'POST /sigr/manifest/verify': 'Verify a model manifest receipt (free)',
      'POST /sigr/mir': 'MiR — model-identity & relineage (binds served-model lineage, detects substitution; asserts identity only)',
      'POST /sigr/mir/verify': 'Verify a MiR receipt (free)',
      'GET /sigr/upstream': 'Upstream pre-effect suite catalog — the seven primitives and their contracts',
      'POST /sigr/upstream/gate': 'Refuse an action unless every required upstream receipt verifies fresh',
      'GET /health': 'Health check',
    },
    products: {
      'SiGR-Bill': 'HC-2026-004',
      'SiGR-Bond': 'HC-2026-005',
      'SiGR Chain': 'HC-2026-006',
      'SiGR-Consensus': 'HC-2026-007',
      'QPuF': 'HC-2026-001',
      'Provenance-Bonded Sandbox': 'HC-2026-016',
      'Refusal Ledger': 'HC-2026-017',
      'Howler': 'HC-2026-018',
      'Perimeter Bond': 'HC-2026-019',
      'Diurnal Bond': 'HC-2026-020',
      'Egress Bond': 'HC-2026-021',
      'Forensic Rail': 'HC-2026-022',
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
  const body = req.body || {};
  // Carnac digest signing contract (backwards-compatible): when a precomputed
  // digest is supplied, bind + sign exactly that digest and return flat fields.
  // Existing typed-fragment clients (text/fragments) are untouched.
  if (body.payload_sha256 !== undefined) {
    if (authConfigured() && !checkInternalToken(req.get('X-Hive-Internal-Token'))) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    if (!isValidSha256Hex(body.payload_sha256)) {
      return res.status(400).json({ error: 'invalid_payload_sha256' });
    }
    if (normalizeAlgo(body.algo) === null) {
      return res.status(400).json({ error: 'unsupported_algo' });
    }
    try {
      return res.json(signDigestBinding(body.payload_sha256, body.algo, SIGNER));
    } catch (err) {
      // Generic error — never echo the payload back.
      return res.status(400).json({ error: 'sign_failed' });
    }
  }
  try {
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
  const body = req.body || {};
  // Carnac digest verify contract (backwards-compatible): independently verify
  // a { payload_sha256, signature, public_key, algo } binding. Public + rate
  // limited. Existing typed-fragment verify ({ envelope, fragments }) untouched.
  if (body.payload_sha256 !== undefined) {
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
    if (rateLimited('verify:' + ip)) {
      return res.status(429).json({ error: 'rate_limited' });
    }
    return res.json(verifyDigestBinding(body.payload_sha256, body.signature, body.public_key, body.algo, verifyFn));
  }
  try {
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

// ===========================================================================
// GCA + GiTM — per-claim grounding attestation + cross-signal anomaly flag.
// Honest rails: GCA proves SUPPORT not truth; GiTM asserts PROVENANCE ANOMALY ONLY,
// never falsity. Both ride the existing ML-DSA-65 signer + zero-secret verify.
// ===========================================================================

// --- GCA: Per-Claim Grounding Attestation (rides ARSC) ---
app.post('/sigr/gca', (req, res) => {
  try {
    const body = req.body || {};
    const gca = body.grounding_claims || body.gca || body;
    if (!gca || !gca.method_hash || !Array.isArray(gca.claims) || gca.claims.length === 0) {
      return res.status(400).json({ error: 'Provide { grounding_claims: { method_hash, answer_id?, claims:[{ claim_id?, claim?|claim_hash, support: "0x..."|null, support_strength?|support_strength_bp? }] } }' });
    }
    const { envelope, timing_us } = signGca(gca, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'GCA', patent_pending: 'Patent Pending', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'gca_sign_rejected', message: err.message });
  }
});
app.post('/sigr/gca/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.claims_root) return res.status(400).json({ error: 'Provide { envelope } (a signed GCA receipt)' });
    const result = verifyGca(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'GCA', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// --- GiTM: Glitch in the Matrix — cross-signal anomaly flag (rides SiGR) ---
app.post('/sigr/gitm', (req, res) => {
  try {
    const body = req.body || {};
    const gitm = body.gitm || body;
    // Source the identity_flicker signal from a REAL signed MiR receipt when supplied.
    // The MiR receipt is verified here; only if valid do we take its signed
    // identity_flicker_bp as the authoritative identity signal (overriding any
    // caller-asserted number). This makes the GiTM->MiR link trustless.
    let mir_source = null;
    if (body.mir_receipt) {
      const mirResult = verifyMir(body.mir_receipt, verifyFn, pubFromEnv(body.mir_receipt));
      if (!mirResult.valid) {
        return res.status(400).json({ ok: false, error: 'mir_receipt_invalid', reasons: mirResult.reasons });
      }
      gitm.signals = gitm.signals || {};
      gitm.signals.identity_flicker_bp = body.mir_receipt.identity_flicker_bp | 0;
      mir_source = { identity_root: body.mir_receipt.identity_root, identity_flicker_bp: body.mir_receipt.identity_flicker_bp | 0 };
    }
    if (!gitm || (!gitm.signals && gitm.grounding_anomaly === undefined && gitm.cross_run_divergence === undefined)) {
      return res.status(400).json({ error: 'Provide { gitm: { subject_id?, claims_root_ref?, signals: { grounding_anomaly, identity_flicker, chain_irregularity, cross_run_divergence, under_attested_high_stakes }, trigger_bp? } } — or pass { mir_receipt } to source identity_flicker from a signed MiR receipt' });
    }
    const { envelope, timing_us } = signGitm(gitm, SIGNER, { hashSuite: body.hash_suite });
    if (mir_source) envelope.mir_source = mir_source;
    res.json({ ok: true, product: 'GiTM', patent_pending: 'Patent Pending', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'gitm_sign_rejected', message: err.message });
  }
});
app.post('/sigr/gitm/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.decision_digest) return res.status(400).json({ error: 'Provide { envelope } (a signed GiTM receipt)' });
    const result = verifyGitm(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'GiTM', ...result, verified_at: new Date().toISOString() });
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

// --- AFiR KV Cache Signing (P3) — sign vLLM prefix entries at write time ---
app.post('/sigr/cachesign', (req, res) => {
  try {
    const body = req.body || {};
    const entry = body.cache || body.entry || body;
    if (!entry || !entry.prefix_hash || !entry.model_id) {
      return res.status(400).json({ error: 'Provide { cache: { model_id, prefix_hash, block_ids?:[], token_span?:{start,end}, parent_cache_receipt? } }' });
    }
    const { envelope, timing_us } = signCacheEntry(entry, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'AFiR KV Cache Signing', patent_pending: 'Patent Pending', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'cache_sign_rejected', message: err.message });
  }
});
app.post('/sigr/cachesign/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.prefix_root) return res.status(400).json({ error: 'Provide { envelope } (a signed cache receipt)' });
    const result = verifyCacheEntry(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'AFiR KV Cache Signing', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// --- AFiR Model Manifest (P4) — TEE-less streaming model attestation ---
app.post('/sigr/manifest', (req, res) => {
  try {
    const body = req.body || {};
    const manifest = body.manifest || body;
    if (!manifest || !manifest.model_id || !manifest.weights_sha3 || !manifest.config_hash || !manifest.endpoint) {
      return res.status(400).json({ error: 'Provide { manifest: { model_id, weights_sha3, config_hash, endpoint, nullifier? } }' });
    }
    const { envelope, timing_us } = signManifest(manifest, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'AFiR Model Manifest', patent_pending: 'Patent Pending', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'manifest_sign_rejected', message: err.message });
  }
});
app.post('/sigr/manifest/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.manifest_root) return res.status(400).json({ error: 'Provide { envelope } (a signed manifest receipt)' });
    const result = verifyManifest(envelope, verifyFn, pubFromEnv(envelope));
    res.json({ product: 'AFiR Model Manifest', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// --- MiR — Model-Identity & Relineage (binds served-model lineage, detects substitution) ---
app.post('/sigr/mir', (req, res) => {
  try {
    const body = req.body || {};
    const mir = body.mir || body;
    if (!mir || !Array.isArray(mir.steps) || mir.steps.length === 0) {
      return res.status(400).json({ error: 'Provide { mir: { subject_id?, expected_model?, steps: [ { model_id, weights_sha3, config_hash, endpoint, manifest_nullifier? }, ... ] } }' });
    }
    const { envelope, timing_us } = signMir(mir, SIGNER, { hashSuite: body.hash_suite });
    res.json({ ok: true, product: 'MiR', patent_pending: 'Patent Pending', envelope, timing_us });
  } catch (err) {
    res.status(400).json({ ok: false, error: 'mir_sign_rejected', message: err.message });
  }
});
app.post('/sigr/mir/verify', (req, res) => {
  try {
    const body = req.body || {};
    const envelope = body.envelope !== undefined ? body.envelope : body;
    if (!envelope || !envelope.lineage_digest) return res.status(400).json({ error: 'Provide { envelope } (a signed MiR receipt). Optionally include { steps } to verify per-step roots against raw identities.' });
    const result = verifyMir(envelope, verifyFn, pubFromEnv(envelope), { steps: body.steps });
    res.json({ product: 'MiR', ...result, verified_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ valid: false, reasons: ['verify_error:' + err.message] });
  }
});

// ---------------------------------------------------------------------------
// Upstream Signed Pre-Effect Attestation — the seven primitives (HC-2026-016..022)
//
// These fire BEFORE an effect lands, which is what separates them from the SiGR
// family above: SiGR records what a model did, these bound what it is allowed to
// do and refuse the action when the bound is not proven. All fifteen receipt
// types share the src/upstream.js envelope, so one verifier handles every one:
// recompute payload_root from the carried payload, recompute the canonical
// envelope without its signature, check the ML-DSA-65 signature, check freshness.
//
// Signing is metered. Verification is free and needs nothing but the receipt and
// the published public key. Where a primitive has a cross-receipt coupling rule,
// the verify route accepts the extra material and runs it, mirroring the
// optional { steps } convention on /sigr/mir/verify.
// ---------------------------------------------------------------------------
const UPSTREAM_ROUTES = [
  {
    path: 'pbs/manifest', type: 'pbs.manifest', product: 'PBS Manifest', patent: 'HC-2026-016',
    key: 'env', sign: signPbsManifest, verify: verifyPbsManifest,
    hint: '{ env: { run_id, tenant_id, image_digests: [...], kernel_modules: [...], package_index, egress_acl, gpu_firmware, attestor_kid } }',
    couple: (body, envelope) => Array.isArray(body.heartbeats) && body.heartbeats.length
      ? { chain: verifyPbsAttestationChain(envelope, body.heartbeats, verifyFn, pubFromEnv(envelope)) } : null,
  },
  {
    path: 'pbs/attestation', type: 'pbs.attestation', product: 'PBS Attestation', patent: 'HC-2026-016',
    key: 'beat', sign: signPbsAttestation, verify: verifyPbsAttestation,
    hint: '{ beat: { run_id, tenant_id, heartbeat_seq, prior_accumulator_root, measurements: [ { artifact_id, measured_digest, ts } ] } }',
  },
  {
    path: 'refusal/mutation', type: 'refusal.mutation', product: 'Refusal Ledger Mutation', patent: 'HC-2026-017',
    key: 'mutation', sign: signPolicyMutation, verify: verifyPolicyMutation,
    hint: '{ mutation: { run_id, tenant_id, policy_id, ledger_seq, prior_state, new_state, prior_mutations?, operator_kid?, authorization_ref? } }',
    couple: (body, envelope) => Array.isArray(body.prior_mutations)
      ? { history: verifyPolicyMutationInHistory(envelope, body.prior_mutations, verifyFn, pubFromEnv(envelope)) } : null,
  },
  {
    path: 'refusal/binding', type: 'refusal.binding', product: 'Refusal Ledger Read Binding', patent: 'HC-2026-017',
    key: 'binding', sign: signPolicyReadBinding, verify: verifyPolicyReadBinding,
    hint: '{ binding: { run_id, tenant_id, envelope_id, envelope_bounds, policy_value_bp?, blinding_hex?, policy_id?, ledger_seq_at_read? } }',
  },
  {
    path: 'howler/drift', type: 'howler.drift', product: 'Howler Drift Alarm', patent: 'HC-2026-018',
    key: 'alarm', sign: signHowlerDrift, verify: verifyHowlerDrift,
    hint: '{ alarm: { run_id, tenant_id, trace_tokens: [...], drift_score_bp, expected_task_shape_ref?, drift_threshold_bp?, token_position_at_trigger? } }',
  },
  {
    path: 'howler/capability', type: 'howler.capability', product: 'Howler Capability Alarm', patent: 'HC-2026-018',
    key: 'alarm', sign: signHowlerCapability, verify: verifyHowlerCapability,
    hint: '{ alarm: { run_id, tenant_id, trace_tokens: [...], requested_capability_id, sae_feature_indices?, sae_feature_magnitudes_bp?, scope_ref?, sae_probe_id? } }',
    // verifyHowlerCapabilityWithSae takes a probe *function*, which cannot cross
    // JSON. Over HTTP the caller submits the vector their own probe produced from
    // the same trace, and we check it reproduces the signed digest.
    couple: (body, envelope) => (body.sae_probe && Array.isArray(body.trace_tokens))
      ? { sae_replay: verifyHowlerCapabilityWithSae(
          envelope,
          () => ({ indices: body.sae_probe.indices, magnitudes_bp: body.sae_probe.magnitudes_bp }),
          body.trace_tokens, verifyFn, pubFromEnv(envelope)) } : null,
  },
  {
    path: 'howler/contamination', type: 'howler.contamination', product: 'Howler Contamination Alarm', patent: 'HC-2026-018',
    key: 'alarm', sign: signHowlerContamination, verify: verifyHowlerContamination,
    hint: '{ alarm: { run_id, tenant_id, contamination_class, contamination_entropy_bits?, regex_pattern_id?, position_at_detect?, matched_span_digest? } }',
  },
  {
    path: 'perimeter/manifest', type: 'perimeter.manifest', product: 'Perimeter Bond Manifest', patent: 'HC-2026-019',
    key: 'manifest', sign: signPerimeterManifest, verify: verifyPerimeterManifest,
    hint: '{ manifest: { run_id, tenant_id, ebpf_program_hash, allowed_targets: [ { target_host, resolution } ], ebpf_program_kid?, enforcement_mode? } }',
  },
  {
    path: 'perimeter/attempt', type: 'perimeter.attempt', product: 'Perimeter Bond Attempt', patent: 'HC-2026-019',
    key: 'attempt', sign: signPerimeterAttempt, verify: verifyPerimeterAttempt,
    hint: '{ attempt: { run_id, tenant_id, target_host, resolution, target_port?, target_protocol?, matched_manifest_rule_id?, ebpf_program_hash?, kernel_syscall_ts? } }',
    couple: (body, envelope) => body.manifest
      ? { against_manifest: verifyPerimeterAttemptAgainstManifest(envelope, body.manifest, verifyFn, pubFromEnv(envelope)) } : null,
  },
  {
    path: 'diurnal/regime', type: 'diurnal.regime', product: 'Diurnal Bond Regime', patent: 'HC-2026-020',
    key: 'regime', sign: signDiurnalRegime, verify: verifyDiurnalRegime,
    hint: '{ regime: { run_id, tenant_id, regime, action_class?, risk_manifold?, attestor_kid_set?, regime_start_ts?, regime_end_ts? } }',
    couple: (body, envelope) => Array.isArray(body.attestations) && body.attestations.length
      ? { threshold: verifyDiurnalThresholdSatisfied(envelope, body.attestations, verifyFn, pubFromEnv(envelope)) } : null,
  },
  {
    path: 'diurnal/attestation', type: 'diurnal.attestation', product: 'Diurnal Bond Attestation', patent: 'HC-2026-020',
    key: 'attestation', sign: signDiurnalAttestation, verify: verifyDiurnalAttestation,
    hint: '{ attestation: { run_id, tenant_id, regime_ref, attestor_kid, attestor_geo_region?, countersign_ts?, action_class? } }',
  },
  {
    path: 'egress/manifest', type: 'egress.manifest', product: 'Egress Bond Manifest', patent: 'HC-2026-021',
    key: 'manifest', sign: signEgressManifest, verify: verifyEgressManifest,
    hint: '{ manifest: { run_id, tenant_id, per_class_row_caps: { class: n }, per_class_byte_caps?, classifier_weights_digest?, commitment_seed?, retroactive_invalidation?, sigr_chain_ref? } }',
  },
  {
    path: 'egress/measurement', type: 'egress.measurement', product: 'Egress Bond Measurement', patent: 'HC-2026-021',
    key: 'measurement', sign: signEgressMeasurement, verify: verifyEgressMeasurement,
    hint: '{ measurement: { run_id, tenant_id, per_class_rows_this_window: { class: n }, per_class_row_caps, prior_commitments?, commitment_seed?, window_start_ts?, window_end_ts?, sigr_chain_ref? } }',
  },
  {
    path: 'forensic/credential', type: 'forensic.credential', product: 'Forensic Rail Credential', patent: 'HC-2026-022',
    key: 'credential', sign: signForensicCredential, verify: verifyForensicCredential,
    hint: '{ credential: { run_id, tenant_id, incident_case_id, threshold_k, consortium_signers: [ { kid } ], scope?, no_execute?, no_generate_novel?, valid_from_ts?, valid_until_ts? } }',
  },
  {
    path: 'forensic/analysis', type: 'forensic.analysis', product: 'Forensic Rail Analysis', patent: 'HC-2026-022',
    key: 'analysis', sign: signForensicAnalysis, verify: verifyForensicAnalysis,
    hint: '{ analysis: { run_id, tenant_id, credential_ref, prompt_digest, output_digest, temperature_bp?, model_ref?, seed?, top_p_bp?, kv_cache_digest?, responder_kid? } }',
  },
];

for (const r of UPSTREAM_ROUTES) {
  // ---- sign (metered) ----
  app.post('/sigr/' + r.path, (req, res) => {
    try {
      const body = req.body || {};
      const payload = body[r.key] !== undefined ? body[r.key] : body;
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return res.status(400).json({ ok: false, error: 'missing_payload', expected: r.hint });
      }
      const t0 = process.hrtime.bigint();
      const envelope = r.sign(payload, SIGNER, { hashSuite: body.hash_suite });
      const sign_us = Number(process.hrtime.bigint() - t0) / 1000;
      res.json({
        ok: true, product: r.product, receipt_type: r.type,
        patent_pending: 'Patent Pending ' + r.patent,
        usap_version: USAP_VERSION, ttl_seconds: DEFAULT_TTL[r.type],
        envelope, timing_us: { sign_us },
      });
    } catch (err) {
      res.status(400).json({ ok: false, error: 'upstream_sign_rejected', receipt_type: r.type, message: err.message, expected: r.hint });
    }
  });

  // ---- verify (free) ----
  app.post('/sigr/' + r.path + '/verify', (req, res) => {
    try {
      const body = req.body || {};
      const envelope = body.envelope !== undefined ? body.envelope : body;
      if (!envelope || typeof envelope !== 'object' || !envelope.sig) {
        return res.status(400).json({ error: 'Provide { envelope } (a signed ' + r.type + ' receipt).' });
      }
      const t0 = process.hrtime.bigint();
      const result = r.verify(envelope, verifyFn, pubFromEnv(envelope), { allow_expired: body.allow_expired === true });
      const verify_us = Number(process.hrtime.bigint() - t0) / 1000;
      const extra = (r.couple && result.ok) ? r.couple(body, envelope) : null;
      res.json({
        product: r.product, receipt_type: r.type, ...result,
        ...(extra || {}), timing_us: { verify_us },
        verified_at: new Date().toISOString(),
      });
    } catch (err) {
      res.status(500).json({ ok: false, reasons: ['verify_error:' + err.message] });
    }
  });
}

// Carnac-style aggregate gate. Refuses the action unless every required receipt
// verifies fresh. This is the point of the seven: a caller proves the bound
// before the effect, and the refusal is itself a determinate answer.
app.post('/sigr/upstream/gate', (req, res) => {
  try {
    const body = req.body || {};
    const required = body.required;
    if (!Array.isArray(required) || !required.length) {
      return res.status(400).json({ error: 'Provide { required: [ { type, receipt }, ... ] } where type is one of the fifteen upstream receipt types.' });
    }
    const t0 = process.hrtime.bigint();
    const pub = pubFromEnv(required[0] && required[0].receipt);
    const result = gateOnReceipts(required, verifyFn, pub, { allow_expired: body.allow_expired === true });
    const gate_us = Number(process.hrtime.bigint() - t0) / 1000;
    res.json({
      product: 'Upstream Gate', usap_version: USAP_VERSION,
      allow: result.allow, refusals: result.refusals,
      checked: required.length, timing_us: { gate_us },
      patent_pending: 'Patent Pending HC-2026-016 through HC-2026-022',
      gated_at: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ allow: false, reasons: ['gate_error:' + err.message] });
  }
});

// Machine-readable catalog of the seven, so a caller can discover the contracts.
app.get('/sigr/upstream', (req, res) => {
  res.json({
    suite: 'Upstream Signed Pre-Effect Attestation',
    usap_version: USAP_VERSION,
    algorithm: 'ML-DSA-65',
    spec: 'NIST FIPS 204',
    description: 'Seven primitives that fire before an effect lands. Each binds a declared payload into one ML-DSA-65 signature over a recomputable payload_root, with its own freshness window.',
    primitives: {
      'Provenance-Bonded Sandbox': 'HC-2026-016',
      'Refusal Ledger':            'HC-2026-017',
      'Howler':                    'HC-2026-018',
      'Perimeter Bond':            'HC-2026-019',
      'Diurnal Bond':              'HC-2026-020',
      'Egress Bond':               'HC-2026-021',
      'Forensic Rail':             'HC-2026-022',
    },
    receipt_types: UPSTREAM_ROUTES.map(r => ({
      receipt_type: r.type, product: r.product, patent_pending: r.patent,
      sign: 'POST /sigr/' + r.path, verify: 'POST /sigr/' + r.path + '/verify',
      ttl_seconds: DEFAULT_TTL[r.type], body: r.hint,
    })),
    gate: 'POST /sigr/upstream/gate',
    verify_is_free: true,
  });
});

app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

app.listen(PORT, () => {
  console.log(`Hive Typed Signer ${SIGNER.version} on :${PORT}`);
  console.log('Algorithm: ML-DSA-65 (NIST FIPS 204) — real, not mock');
});

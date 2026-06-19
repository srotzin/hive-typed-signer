/**
 * bill.js — SiGR-Bill: cryptographically verifiable inference billing.
 *
 * THE WEDGE PRODUCT. Survey convergence: 4 of 7 models independently proposed
 * verifiable billing/metering (Claude's top pick). Rides the existing signer
 * stack almost as-is — no regulator, no enclave, no new crypto.
 *
 * What it proves: every billed unit (input tokens, output tokens, cached tokens,
 * model id, hardware backend, unit price) is bound into a per-request signed
 * receipt. Per billing cycle, the per-request roots roll up into a single signed
 * billing root the customer verifies against their OWN collected receipts.
 * Discrepancy between the signed root and the customer's set = provable overbilling.
 *
 * Trust model: zero-secret verification. The customer needs only the published
 * ML-DSA-65 public key. They never trust the provider's logs.
 *
 * Design note (survey Signal B): the cost manifest binds the RAW request/response
 * byte hash + a versioned tokenizer hash, so token counts are independently
 * RECONSTRUCTABLE rather than taken on faith. This closes the "platform controls
 * the tokenizer" attack surface to the extent the tokenizer is published.
 *
 * Reuses: canonicalize, hashHex, resolveSuite, merkleRoot, the bind-one-payload
 * pattern, and SIGNER/verifyFn — identical discipline to typed.js.
 *
 * Patent Pending HC-2026-004 (cryptographic metering + billing reconciliation
 * for inference services). Internal docket only — never emit in public artifacts.
 */
import {
  canonicalize, hashHex, resolveSuite, merkleRoot,
} from './typed.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Canonical cost-manifest shape. Every field is bound into the signed payload.
// prices are integer micro-USD to avoid float drift in reconciliation.
export function buildCostManifest(req, suite) {
  const s = suite || resolveSuite('sha-256');
  const manifest = {
    object: 'sigr.bill.manifest',
    request_id: req.request_id,
    model_id: req.model_id,                       // executed model (not requested)
    backend: req.backend || 'unspecified',         // hardware backend tier
    input_tokens: req.input_tokens | 0,
    output_tokens: req.output_tokens | 0,
    cached_tokens: req.cached_tokens | 0,
    // independently-reconstructable accounting: hashes let the customer recount
    request_bytes_hash: req.request_bytes_hash || hashHex(req.request_text || '', s),
    response_bytes_hash: req.response_bytes_hash || hashHex(req.response_text || '', s),
    tokenizer_hash: req.tokenizer_hash || 'unspecified',
    // integer micro-USD unit prices
    price_input_micro_usd: req.price_input_micro_usd | 0,
    price_output_micro_usd: req.price_output_micro_usd | 0,
    price_cached_micro_usd: req.price_cached_micro_usd | 0,
  };
  manifest.line_total_micro_usd = lineTotal(manifest);
  return manifest;
}

export function lineTotal(m) {
  return (
    m.input_tokens * m.price_input_micro_usd +
    m.output_tokens * m.price_output_micro_usd +
    m.cached_tokens * m.price_cached_micro_usd
  );
}

/**
 * signBillReceipt — one signed receipt per request. Binds:
 *   base || manifest_digest [|| temporal]  -> one payload -> one ML-DSA-65 sig.
 * Mirrors signTyped's bind discipline exactly.
 */
export function signBillReceipt(req, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);
  const temporal = opts.temporal || null;

  const manifest = buildCostManifest(req, suite);
  const manifestDigest = hashHex(canonicalize(manifest), suite);

  const baseFields = {
    object: 'sigr.bill.receipt',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const temporalDigest = temporal ? hashHex(canonicalize(temporal), suite) : zero;

  const slots = temporal ? 3 : 2;
  const bind = new Uint8Array(dl * slots);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(manifestDigest), dl);
  if (temporal) bind.set(hexToBytes(temporalDigest), dl * 2);
  const payloadHex = bytesToHex(suite.fn(bind));

  const t0 = process.hrtime.bigint();
  const sigBytes = signer.sign(hexToBytes(payloadHex));
  const t1 = process.hrtime.bigint();

  const envelope = {
    ...baseFields,
    manifest,
    manifest_digest: manifestDigest,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  if (temporal) envelope.temporal = temporal;
  if (signer.trust) envelope.trust = signer.trust;

  return { envelope, timing_us: { sign_us: Number(t1 - t0) / 1000 } };
}

/** verifyBillReceipt — independent reconstruction + signature check. */
export function verifyBillReceipt(envelope, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (envelope.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }
  const dl = suite.digest_len;
  const zero = '0'.repeat(dl * 2);

  // recompute the manifest line total — catches arithmetic tampering directly
  const m = envelope.manifest;
  if (lineTotal(m) !== m.line_total_micro_usd) reasons.push('line_total_mismatch');

  const manifestDigest = hashHex(canonicalize(m), suite);
  if (manifestDigest !== envelope.manifest_digest) reasons.push('manifest_digest_mismatch');

  const baseFields = {
    object: envelope.object,
    version: envelope.version,
    sig_scheme: envelope.sig_scheme,
    public_key: envelope.public_key,
  };
  const baseDigest = hashHex(canonicalize(baseFields), suite);
  const hasTemporal = !!envelope.temporal;
  const temporalDigest = hasTemporal ? hashHex(canonicalize(envelope.temporal), suite) : zero;

  const slots = hasTemporal ? 3 : 2;
  const bind = new Uint8Array(dl * slots);
  bind.set(hexToBytes(baseDigest), 0);
  bind.set(hexToBytes(manifestDigest), dl);
  if (hasTemporal) bind.set(hexToBytes(temporalDigest), dl * 2);
  const payloadHex = bytesToHex(suite.fn(bind));
  if (payloadHex !== envelope.payload_digest) reasons.push('payload_digest_mismatch');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(envelope.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return { valid: reasons.length === 0, reasons, line_total_micro_usd: m.line_total_micro_usd };
}

/**
 * signInvoice — roll up a billing CYCLE. The per-request receipts' payload
 * digests are the leaves of a Merkle tree; the signed invoice root is what the
 * customer reconciles against their own collected receipts.
 *
 * The customer recomputes the root from THEIR receipts and compares. A provider
 * that drops, inflates, or fabricates a line cannot produce a matching root.
 */
export function signInvoice(receiptEnvelopes, period, signer, opts = {}) {
  const suite = resolveSuite((opts.hashSuite || 'sha-256').toLowerCase());
  const dl = suite.digest_len;

  const leaves = receiptEnvelopes.map(e => e.payload_digest).sort();
  const billingRoot = merkleRoot(leaves, suite);
  const totalMicroUsd = receiptEnvelopes.reduce((a, e) => a + e.manifest.line_total_micro_usd, 0);

  const baseFields = {
    object: 'sigr.bill.invoice',
    version: signer.version,
    sig_scheme: signer.scheme,
    public_key: signer.publicKeyB64,
    period_start: period.start,
    period_end: period.end,
    customer_ref: period.customer_ref || 'unspecified',
    line_count: receiptEnvelopes.length,
    billing_root: billingRoot,
    total_micro_usd: totalMicroUsd,
  };
  const payloadHex = hashHex(canonicalize(baseFields), suite);
  const sigBytes = signer.sign(hexToBytes(payloadHex));

  const envelope = {
    ...baseFields,
    payload_digest: payloadHex,
    envelope_signature: Buffer.from(sigBytes).toString('base64'),
    issued_at: new Date().toISOString(),
    patent_pending: 'Patent Pending',
  };
  if (suite !== resolveSuite('sha-256')) envelope.hash_suite = (opts.hashSuite || '').toLowerCase();
  return envelope;
}

/**
 * verifyInvoice — the customer-side reconciliation. Pass the invoice envelope and
 * the customer's OWN collected receipt envelopes. Recomputes the billing root
 * from the customer's set and checks it matches the signed root + the signature.
 */
export function verifyInvoice(invoiceEnv, customerReceipts, verifyFn, pubBytes) {
  const reasons = [];
  const suiteName = (invoiceEnv.hash_suite || 'sha-256').toLowerCase();
  let suite;
  try { suite = resolveSuite(suiteName); }
  catch (e) { return { valid: false, reasons: ['unknown_hash_suite:' + suiteName] }; }

  const baseFields = {
    object: invoiceEnv.object,
    version: invoiceEnv.version,
    sig_scheme: invoiceEnv.sig_scheme,
    public_key: invoiceEnv.public_key,
    period_start: invoiceEnv.period_start,
    period_end: invoiceEnv.period_end,
    customer_ref: invoiceEnv.customer_ref,
    line_count: invoiceEnv.line_count,
    billing_root: invoiceEnv.billing_root,
    total_micro_usd: invoiceEnv.total_micro_usd,
  };
  const payloadHex = hashHex(canonicalize(baseFields), suite);
  if (payloadHex !== invoiceEnv.payload_digest) reasons.push('payload_digest_mismatch');

  // reconcile: recompute root from the customer's own receipts
  const leaves = customerReceipts.map(e => e.payload_digest).sort();
  const recomputedRoot = merkleRoot(leaves, suite);
  if (recomputedRoot !== invoiceEnv.billing_root) reasons.push('billing_root_mismatch_vs_customer_receipts');
  if (customerReceipts.length !== invoiceEnv.line_count) reasons.push('line_count_mismatch');

  const customerTotal = customerReceipts.reduce((a, e) => a + e.manifest.line_total_micro_usd, 0);
  if (customerTotal !== invoiceEnv.total_micro_usd) reasons.push('total_mismatch_vs_customer_receipts');

  let sigOk = false;
  try {
    const sigBytes = Uint8Array.from(Buffer.from(invoiceEnv.envelope_signature, 'base64'));
    sigOk = verifyFn(sigBytes, hexToBytes(payloadHex), pubBytes);
  } catch (e) { reasons.push('signature_error:' + e.message); }
  if (!sigOk) reasons.push('signature_invalid');

  return {
    valid: reasons.length === 0,
    reasons,
    signed_total_micro_usd: invoiceEnv.total_micro_usd,
    customer_total_micro_usd: customerTotal,
  };
}

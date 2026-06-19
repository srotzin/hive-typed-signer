// SiGR-Bill tests: per-request receipt verify + tamper detection + invoice reconcile.
import { SIGNER, verifyFn } from '../src/key.js';
import {
  buildCostManifest, lineTotal, signBillReceipt, verifyBillReceipt,
  signInvoice, verifyInvoice,
} from '../src/bill.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;

function mkReq(id, inT, outT, cT = 0) {
  return {
    request_id: id, model_id: 'llama-3.1-70b', backend: 'h100',
    input_tokens: inT, output_tokens: outT, cached_tokens: cT,
    request_text: 'req:' + id, response_text: 'resp:' + id, tokenizer_hash: 'tok-v1',
    price_input_micro_usd: 5, price_output_micro_usd: 15, price_cached_micro_usd: 2,
  };
}

section('bill: manifest + line total');
{
  const m = buildCostManifest(mkReq('r1', 100, 50));
  eq(m.line_total_micro_usd, 100 * 5 + 50 * 15, 'line total = inputs*pin + outputs*pout');
  eq(lineTotal(m), m.line_total_micro_usd, 'lineTotal matches stored');
  ok(m.request_bytes_hash.length === 64, 'request hash is sha-256 hex');
}

section('bill: per-request receipt happy path');
{
  const { envelope } = signBillReceipt(mkReq('r1', 100, 50), SIGNER);
  const r = verifyBillReceipt(envelope, verifyFn, PUB);
  ok(r.valid, 'valid receipt verifies; reasons=' + r.reasons.join(','));
  eq(r.line_total_micro_usd, 1250, 'reported line total correct');
}

section('bill: tamper detection');
{
  const { envelope } = signBillReceipt(mkReq('r1', 100, 50), SIGNER);

  const t1 = JSON.parse(JSON.stringify(envelope));
  t1.manifest.output_tokens = 5000;                 // inflate output tokens
  const r1 = verifyBillReceipt(t1, verifyFn, PUB);
  ok(!r1.valid, 'token inflation rejected');
  ok(r1.reasons.includes('line_total_mismatch') || r1.reasons.includes('manifest_digest_mismatch'),
    'token inflation flagged: ' + r1.reasons.join(','));

  const t2 = JSON.parse(JSON.stringify(envelope));
  t2.manifest.price_output_micro_usd = 99;          // bump unit price post-hoc
  t2.manifest.line_total_micro_usd = lineTotal(t2.manifest); // even if they "fix" the total
  const r2 = verifyBillReceipt(t2, verifyFn, PUB);
  ok(!r2.valid, 'price tamper rejected even with recomputed total');
  ok(r2.reasons.includes('manifest_digest_mismatch'), 'price tamper -> manifest digest: ' + r2.reasons.join(','));

  const t3 = JSON.parse(JSON.stringify(envelope));
  t3.envelope_signature = Buffer.from(new Uint8Array(64)).toString('base64');
  const r3 = verifyBillReceipt(t3, verifyFn, PUB);
  ok(!r3.valid, 'bad signature rejected');
}

section('bill: invoice cycle reconciliation');
{
  const reqs = [mkReq('a', 100, 50), mkReq('b', 200, 20), mkReq('c', 10, 10)];
  const receipts = reqs.map(r => signBillReceipt(r, SIGNER).envelope);
  const inv = signInvoice(receipts, { start: '2026-06-01', end: '2026-06-30', customer_ref: 'acme' }, SIGNER);

  const good = verifyInvoice(inv, receipts, verifyFn, PUB);
  ok(good.valid, 'honest invoice reconciles; reasons=' + good.reasons.join(','));
  eq(good.signed_total_micro_usd, good.customer_total_micro_usd, 'totals agree');

  // provider drops a line from the customer's set vs what was signed -> mismatch
  const dropped = verifyInvoice(inv, receipts.slice(0, 2), verifyFn, PUB);
  ok(!dropped.valid, 'missing line detected');
  ok(dropped.reasons.includes('billing_root_mismatch_vs_customer_receipts') ||
     dropped.reasons.includes('line_count_mismatch'), 'drop flagged: ' + dropped.reasons.join(','));

  // tamper the signed total -> payload digest mismatch
  const t = JSON.parse(JSON.stringify(inv));
  t.total_micro_usd = 1;
  const bad = verifyInvoice(t, receipts, verifyFn, PUB);
  ok(!bad.valid, 'invoice total tamper detected');
}

summary('bill');

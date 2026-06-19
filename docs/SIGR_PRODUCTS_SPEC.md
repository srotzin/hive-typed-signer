# SiGR™ Product Suite — Buildable Specs + Patent Angles

Internal engineering + IP doc. Not a public artifact. Patent dockets are internal only — emit **"Patent Pending"** publicly, never the docket number.

All four products are built on the existing `hive-typed-signer` stack and reuse the same discipline as `typed.js`:
**build a canonical object → hash each part → bind the digest slots into ONE payload → ONE ML-DSA-65 (NIST FIPS 204) signature → an independent verifier recomputes everything and checks the single signature.** Zero-secret verification: a verifier needs only the published public key.

| Product | Module | Cluster / Concept | Composite | Status |
|---|---|---|---|---|
| SiGR-Bill™ | `src/bill.js` | C4 verifiable billing (the wedge) | 17/20 | built, tests green |
| SiGR-Bond™ | `src/bond.js` | C3 SLA settlement (pay-if-slow) | 17/20 | built, tests green |
| SiGR Chain™ | `src/chain.js` | C1 agent causal-chain (flagship) | 19/20 | built, tests green |
| Consensus Receipt (Concept E) | `src/consensus.js` | internal whitespace, no LLM proposed it | 17/20 | built, tests green |

Test suite: `node test/run_all.js` → 4 files, 55 assertions, 0 failures. Each suite covers a happy path plus the full tamper matrix.

---

## 1. SiGR-Bill™ — verifiable inference billing (the wedge)

**Docket: HC-2026-004 (internal).**

### What it does
Every billed request emits a signed **cost-manifest receipt**: executed `model_id`, hardware `backend`, input/output/cached token counts, integer micro-USD unit prices, and the resulting `line_total_micro_usd` — plus the SHA-256 of the raw request and response bytes and a versioned `tokenizer_hash`, so the customer can **independently recount tokens** rather than taking them on faith. Per billing cycle, the per-request payload digests become the leaves of a Merkle tree; the signed **invoice** carries that billing root and the cycle total. The customer recomputes the root from their OWN collected receipts and compares.

### Why it wins
Highest buildability — rides the stack almost as-is, no enclave, no regulator. CFO / procurement buyer with immediate pain (usage-billed AI is unauditable today). Natural on-ramp to Bond and Chain (same buyer, same Base anchor).

### Build notes
- Integer micro-USD throughout — no float drift in reconciliation.
- `verifyBillReceipt` re-runs `lineTotal()` so arithmetic tampering is caught directly, independent of the digest check.
- Tamper matrix proven: token inflation, post-hoc price bump (even with a "fixed" total), forged signature, dropped invoice line, tampered invoice total.

### Patent angle (workspace only)
Method for **cryptographic metering and billing reconciliation of inference services**: binding executed-model identity, hardware backend, independently-reconstructable token accounting (raw-byte hash + versioned tokenizer hash), and integer-priced line totals into a per-request post-quantum-signed receipt; rolling per-request payload digests into a per-cycle Merkle billing root under one signature; and detecting overbilling by recomputing the root from the customer's independently-held receipt set. Novelty hook: the **tokenizer-hash binding** closes the "platform controls the meter" attack, distinguishing from generic signed-log art.

---

## 2. SiGR-Bond™ — SLA settlement (pay-if-slow)

**Docket: HC-2026-005 (internal).**

### What it does
The SLA terms (latency ceiling ms, uptime floor ppm, slow-tolerance ppm, penalty micro-USD, window) are signed **up front** as a bond. Each served request emits a signed **measurement receipt** carrying its attested latency and served/failed flag, with an optional temporal-proof slot for an HW-attested timestamp. At window close, measurement payload digests roll into a Merkle **window root**; `computeBreach()` — a pure, deterministic settlement function — runs identically provider-side, customer-side, and (conceptually) on-chain. The customer recomputes the window root AND re-runs the breach math from their own measurement receipts.

### Why it wins
Clearest procurement pain in the survey (5-of-7 convergence). Every enterprise AI contract already has latency/uptime language; none of it is machine-enforceable. "Pay if slow" is something procurement already understands.

### Build notes
- All ppm/integer math — `observed_uptime_ppm`, `observed_slow_ppm` computed with integer division; tolerance is "over," not "at" (10% slow at a 10% tolerance is NOT a breach, proven in tests).
- Honest-clock risk (synthesis Signal B) handled by the optional temporal slot — non-repudiable even without HW attestation; HW-PTP is the Tier-3 upgrade, not a v1 blocker.
- Tamper matrix proven: loosened ceiling post-signing, latency shave on a measurement, dropped slow call, understated breach (provider claims no payout).

### Patent angle (workspace only)
**HW-attested SLA enforcement coupling signed per-request latency to deterministic breach settlement**: binding SLA terms into a signed bond; emitting per-request signed latency measurements (optionally HW-timestamp-attested); and computing a breach/payout via a deterministic function over a Merkle window root such that the same inputs yield the same settlement provider-side, customer-side, and on-chain. Novelty hook: the **deterministic shared settlement function over a signed measurement root** — the payout is a recomputable fact, not a dashboard assertion.

---

## 3. SiGR Chain™ — agent causal-chain receipt (flagship)

**Docket: HC-2026-006 (internal).**

### What it does
A compound-AI / multi-tool agent run is modeled as a **DAG of steps**. Each step commits to (a) its own typed input/output digest and (b) the Merkle root of its **parent steps' commit digests** — so the causal edges are themselves bound under signature. At run close, all step commit digests roll into ONE **causal root** under a SINGLE ML-DSA-65 signature. One signature attests the entire trajectory. A linear run is the degenerate single-parent case; fan-out (parallel tool calls) and fan-in (merge) are first-class.

### Why it wins
Survey's clearest winner (19/20, 3 models' top pick, 5-of-7 convergence). The rare moat: the rest of the market **logs after the fact**; this **signs the state the agent saw before it acted** and chains it. Directly extends the existing fragment-signing + aggregate-root primitives.

### Build notes
- `topoOrder()` is deterministic (Kahn's, ties broken by seq then id) so signer and verifier derive the identical order.
- Verifier re-derives the order, recomputes each commit using recomputed parent commits, checks each `parent_commit_root`, re-derives the causal root, checks one signature.
- Tamper matrix proven: edited step I/O, dropped step, inserted fabricated step, parent rewrite (reorder), cycle, plus the linear degenerate case.

### Patent angle (workspace only)
**Cryptographic accountability graph for compound / multi-agent AI workflows**: representing an agent run as a DAG where each step commitment binds the typed I/O digest and the aggregate of its parents' commitment digests, and attesting the whole graph under a single aggregate post-quantum signature over a causal root — yielding provable resistance to reorder, insertion, deletion, and back-dating of steps. Novelty hooks: (1) **sign-before-act** ordering (parent sealed before child), (2) DAG (not just hash-chain list) with bound partial order, (3) single aggregate signature over the full trajectory.

---

## 4. Consensus Receipt (Concept E) — cross-model consensus attestation

**Docket: HC-2026-007 (internal). Highest-IP bet — genuine whitespace.**

### What it does
When one logical answer is produced by an **N-model panel** (ensemble / MoE / judge-of-models), each model's output is captured as a signed **sub-receipt** (model_id + output_digest + integer score). The consensus **decision** — `majority`, `quorum`, `weighted`, or `judge` — is computed by a pure deterministic function and bound, together with the SORTED panel of sub-receipt digests, under ONE aggregate ML-DSA-65 signature. The verifier re-runs the decision from the sub-receipts, so a dropped dissenter, a faked panelist, or a misreported winner all fail.

### Why it wins
**Not independently proposed by any of the 7 surveyed frontier models** — the clearest defensible lane Hive has. The building blocks (aggregate-over-sub-receipts) were validated by C1/C10 without anyone claiming the consensus framing. High-stakes AI increasingly runs panels precisely to reduce single-model error; nobody today can prove which models were polled or that the reported consensus matches the panel.

### Build notes
- Four decision methods, all integer-safe and deterministic with explicit tie-breaks (votes → weight → lowest hex).
- Verifier reconciles the panel root from the customer's own sub-receipts AND re-runs `computeConsensus()` AND checks the carried decision digest — three independent guards before the signature.
- Tamper matrix proven: swapped sub-receipt output, dropped dissenter, misreported winner; all four methods exercised.

### Patent angle (workspace only)
**Aggregate post-quantum attestation of multi-model consensus inference**: capturing each panel member's output as an independently-verifiable signed sub-receipt; binding the exact panel composition (sorted sub-receipt digests) to a deterministically-computed consensus decision; and attesting both under a single aggregate signature such that panel-tampering (dropping a dissenter, fabricating a member, or misreporting the winner) is detectable by recomputation. Novelty hook: **binding panel composition to the decision** — proving not just the answer but the integrity of the deliberation that produced it.

---

## Cross-cutting properties (all four)

- **One signature per receipt** — not one per element. Verification cost is dominated by a single ML-DSA-65 verify regardless of how many tokens / steps / panelists / line items.
- **Suite-agnostic** — SHA-256 default (wire-compatible, field omitted); SHA-384 available for ultra-long-life receipts, recorded in `hash_suite` and length-guarded against downgrade.
- **Customer-side reconciliation** — every product's strongest guarantee comes from the customer recomputing a root from receipts THEY collected, not from trusting the provider's logs.
- **Base / USDC anchoring** is the public settlement story for Bill and Bond. (Internal-only: never reference other rails publicly.)
- **Optional QPuF / temporal trust block** flows through unchanged where present (`signer.trust`, `opts.temporal`).

## Run it
```
cd hive-typed-signer
node test/run_all.js      # 4 files, 55 assertions, 0 failures
```

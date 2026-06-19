# PROVISIONAL PATENT APPLICATION — DRAFT

**Title:** Systems and Methods for Aggregate Post-Quantum Attestation of Inference-Service Receipts, with Embodiments for Verifiable Billing Reconciliation, Cryptographically-Enforced Service-Level Settlement, Causal-Graph Attestation of Multi-Step Agent Workflows, and Multi-Model Consensus Attestation

**Short title:** Signed inference Guarantee Receipt ("SiGR")

**Inventor(s):** Steven Rotzin
**Assignee:** TheHiveryIQ, Inc.
**Filing Type:** US Provisional Patent Application (35 U.S.C. § 111(b))
**Priority Date:** 2026-06-18 (target filing, on or before 2026-06-22)

---

## FIELD OF THE INVENTION

This invention relates to verifiable computing for machine-learning inference services, and more particularly to a cryptographic primitive in which the attestable artifacts of an inference service — the bill, the service-level guarantee, the causal trajectory of a multi-step agent, and the deliberation of a multi-model panel — are bound into one or more receipts under a single aggregate post-quantum digital signature, such that any third party may independently reconstruct and verify each attested fact using only a published public key, with no secret shared and no reliance on the service provider's own logs.

The invention is called the **Signed inference Guarantee Receipt** ("SiGR"). The shared construction at its core is referred to as **bind-one-payload aggregate signing**.

## BACKGROUND

Machine-learning inference is now sold as a metered utility: customers are billed per token, promised latency and uptime in service-level agreements, increasingly served by multi-step autonomous agents, and increasingly answered by panels of multiple models cross-checking one another. In every one of these dimensions, the customer is asked to **trust an unverifiable assertion**:

- **(a) Billing.** The provider reports token counts, the executed model, the hardware tier, and a price. The customer cannot reconstruct any of it. The meter, the tokenizer, and the log are all controlled by the party being paid.
- **(b) Service levels.** Latency and uptime appear on a provider dashboard. The customer cannot independently prove a breach; the same party that owes the penalty measures the metric.
- **(c) Agent workflows.** Compound, multi-tool agents make consequential decisions and leave behind logs that are editable after the fact. When a run goes wrong, reconstruction is forensic guesswork.
- **(d) Multi-model consensus.** When N models are polled to reduce single-model error, the customer receives a verdict but no proof of which models were polled, what each returned, or that the reported consensus matches the panel.

Existing approaches do not solve any of these as a verifiable fact:

Prior art in **signed logging and transparency logs** (Certificate Transparency — RFC 6962; Sigstore Rekor; Trillian) records artifacts after the fact and treats each entry as an independent attestation by a granting authority; it does not bind the executed accounting of an inference call, nor the SLA settlement math, nor the causal ordering of an agent's steps, into a single self-verifying receipt. Prior art in **usage metering and billing** (cloud metering systems, API gateways) emits provider-asserted counters with no independent reconstructability and no customer-side reconciliation primitive. Prior art in **agent tracing/observability** (LangSmith, OpenTelemetry-style traces) produces mutable, after-the-fact logs with no cryptographic resistance to reordering, insertion, deletion, or back-dating of steps. Prior art in **ensemble/mixture-of-experts inference** produces a combined output but no attestation binding the panel composition to the reported decision. Prior art in **post-quantum signatures** (NIST FIPS 204, ML-DSA) provides the signing primitive but not the application-layer constructions that make an inference bill, an SLA, an agent trajectory, or a panel consensus independently verifiable under one signature.

No prior art known to applicant teaches a single aggregate post-quantum signature binding a canonically-serialized set of inference-service facts — each independently reconstructable by a verifier from carried data and recomputed digests — such that tampering with any bound fact (an inflated token count, a shaved latency, a reordered agent step, a dropped dissenting model) is detected by recomputation rather than trust.

## SUMMARY OF THE INVENTION

The invention comprises a shared signing construction and four principal embodiments.

**0. Shared construction — bind-one-payload aggregate signing.** For a set of facts to be attested, the system: (i) serializes each fact into a canonical form with sorted keys and no insignificant whitespace; (ii) computes a fixed-length digest of each fact under a recorded hash suite; (iii) concatenates the digests into fixed-width slots of a single binding buffer; (iv) computes one payload digest over the binding buffer; and (v) produces exactly **one** post-quantum digital signature (ML-DSA-65, NIST FIPS 204) over the payload digest — not one signature per fact. A verifier, holding only the published public key and the receipt, recomputes every fact digest from carried canonical data, re-derives the binding buffer and payload digest, and verifies the single signature. The hash suite is recorded in the receipt and length-guarded so a downgrade (relabeling a wider-digest receipt under a narrower suite) fails closed. Verification is zero-secret and runs in milliseconds dominated by a single signature check regardless of the number of bound facts.

**1. Verifiable billing reconciliation embodiment ("SiGR-Bill").** Each billed inference request emits a signed cost-manifest receipt binding the executed model identifier, the hardware backend, input/output/cached token counts, integer-denominated unit prices, a computed line total, and — critically — a digest of the raw request and response bytes together with a versioned tokenizer identifier, such that the token counts are **independently reconstructable** by the customer rather than taken on faith. Per billing cycle, the per-request payload digests form the leaves of a Merkle tree whose root is bound into a signed invoice; the customer recomputes the root from the receipts the customer itself collected, and any dropped, inflated, or fabricated line yields a non-matching root.

**2. Cryptographically-enforced service-level settlement embodiment ("SiGR-Bond").** Service-level terms (latency ceiling, uptime floor, tolerance, penalty) are bound into a signed bond up front. Each served request emits a signed measurement receipt carrying its attested latency and served/failed state, optionally bound to a hardware-attested timestamp. At window close, the measurement payload digests form a Merkle window root, and a **deterministic settlement function** computes breach and payout from the bound terms and the measurements; the same function, run by provider, customer, and an on-chain settlement contract, yields the identical result, making "pay-if-slow" a recomputable fact rather than a dashboard claim.

**3. Causal-graph attestation of multi-step agent workflows embodiment ("SiGR Chain").** A multi-step or multi-agent run is represented as a directed acyclic graph of steps. Each step's commitment binds (a) a digest of the step's typed inputs and outputs and (b) an aggregate digest of the step's parent steps' commitments, so the causal edges are themselves under signature and a step is sealed before its successors execute. All step commitments are bound into one causal root under a single signature. Reordering, inserting, deleting, or back-dating any step, or introducing a cycle, is detected by the verifier's independent re-derivation of the causal order and recomputation of each commitment.

**4. Multi-model consensus attestation embodiment ("Consensus Receipt").** When a single logical answer is produced by polling N models, each model's output is captured as an independently-verifiable signed sub-receipt binding the model identifier, an output digest, and an integer score. The consensus decision — by majority, quorum, score-weighted, or designated-judge method — is computed by a deterministic function and bound, together with the sorted set of sub-receipt digests representing the exact panel, under a single aggregate signature. The verifier re-runs the decision from the sub-receipts, so dropping a dissenting model, fabricating a panelist, or misreporting the winner is detected by recomputation.

**5. Settlement and anchoring.** Receipts and roots produced by the foregoing embodiments may be anchored to a public blockchain and settled in a stablecoin unit of account (USDC on Base), such that the billing root, the SLA settlement, or any receipt digest becomes a publicly timestamped, independently-verifiable commitment.

## INDEPENDENT CLAIMS — DRAFT

### Claim 1 — Aggregate attestation of inference-service facts (master claim, broadest)

A computer-implemented method for producing an independently-verifiable attestation of one or more facts concerning a machine-learning inference service, comprising:

- **(a)** obtaining a plurality of facts characterizing an inference event, the facts comprising at least one of: a billing accounting, a service-level measurement, a causal step of a multi-step agent execution, and a per-model output of a multi-model panel;
- **(b)** serializing each fact into a canonical representation and computing, under a recorded hash suite, a fixed-length digest of each said canonical representation;
- **(c)** assembling the fixed-length digests into fixed-width slots of a single binding buffer and computing a single payload digest over the binding buffer;
- **(d)** producing exactly one post-quantum digital signature over the single payload digest, irrespective of the number of facts bound;
- **(e)** emitting a receipt comprising the canonical facts, the recorded hash suite, the single payload digest, and the single signature;
- **(f)** wherein a verifier holding a published public key and the receipt independently recomputes each fact digest from the carried canonical facts, re-derives the binding buffer and payload digest, and verifies the single signature, such that modification of any bound fact causes verification to fail without the verifier requiring any secret or any data from the service provider beyond the receipt.

### Claim 2 — Verifiable billing reconciliation (dependent on Claim 1)

The method of Claim 1, wherein the facts comprise a cost manifest binding an executed model identifier, a hardware backend identifier, token counts, integer-denominated unit prices, a computed line total, and a digest of raw request and response bytes together with a versioned tokenizer identifier; and further comprising forming, over a billing cycle, a Merkle tree whose leaves are the payload digests of a plurality of per-request receipts, binding the Merkle root into a signed invoice, and detecting overbilling by recomputing said root from receipts independently collected by a customer such that any dropped, inflated, or fabricated line yields a non-matching root.

### Claim 3 — Cryptographically-enforced service-level settlement (dependent on Claim 1)

The method of Claim 1, wherein the facts comprise service-level terms bound into a signed bond and a plurality of per-request signed measurements each carrying an attested latency and a served-state indicator; and further comprising forming a Merkle window root over the measurement payload digests and computing, by a deterministic settlement function over the bound terms and the measurements, a breach determination and a payout amount, such that the same deterministic function executed by the provider, by the customer from independently-collected measurements, and by an on-chain settlement contract yields an identical determination.

### Claim 4 — Causal-graph attestation of multi-step agent workflows (dependent on Claim 1)

The method of Claim 1, wherein the facts comprise a plurality of steps of a multi-step agent execution arranged as a directed acyclic graph, each step commitment binding (i) a digest of the step's inputs and outputs and (ii) an aggregate digest of the commitments of the step's parent steps, the step commitments being bound into a single causal root under the single signature; wherein a step is committed only after its parent steps are committed; and wherein a verifier independently re-derives a causal ordering and recomputes each step commitment, such that reordering, insertion, deletion, or back-dating of any step, or introduction of a cycle, causes verification to fail.

### Claim 5 — Multi-model consensus attestation (dependent on Claim 1)

The method of Claim 1, wherein the facts comprise, for each of N models polled to produce a single logical answer, a signed sub-receipt binding a model identifier, an output digest, and a score; and further comprising binding a sorted set of the sub-receipt digests, representing the exact panel polled, together with a consensus decision computed by a deterministic decision method selected from majority, quorum, score-weighted, and designated-judge, under the single signature; wherein a verifier re-runs the decision method from the sub-receipts such that omission of a polled model, inclusion of a non-polled model, or misreporting of the decision causes verification to fail.

### Claim 6 — Hash-suite agility with downgrade protection (dependent on Claim 1)

The method of Claim 1, wherein the recorded hash suite is selectable among a plurality of suites of differing digest lengths, the selected suite is recorded in the receipt and omitted only for a designated default suite for wire compatibility, and the verifier enforces that every digest slot is exactly the digest length of the recorded suite, such that an attempt to relabel a receipt under a narrower suite than that under which it was signed is detected and rejected.

### Claim 7 — Public anchoring and stablecoin settlement (dependent on Claim 1)

The method of Claim 1, further comprising anchoring at least one of the single payload digest, a billing Merkle root, and a service-level window root to a public blockchain, and effecting settlement of an amount determined from the receipt in a stablecoin unit of account, such that the anchored commitment is publicly timestamped and independently verifiable.

### Claim 8 — Optional hardware-rooted trust binding (dependent on Claim 1)

The method of Claim 1, wherein the receipt further binds a trust block attesting at least one of a quantum-entropy source and a physically-unclonable-function device binding associated with the signer, the trust block revealing no secret and permitting a verifier to confirm the provenance of the signing chain.

## NON-OBVIOUSNESS OVER PRIOR ART (102/103)

**Certificate Transparency (RFC 6962) / Sigstore Rekor / Trillian:** append-only logs of independently-attested artifacts whose signer identity is externally granted; they do not bind the executed accounting, SLA settlement math, agent causal order, or panel composition of an inference event into a single self-verifying receipt, nor provide customer-side reconciliation by root recomputation. **Distinguished on what is bound, the single-aggregate-signature construction, and zero-secret customer reconciliation.**

**Cloud usage metering / API-gateway billing:** emit provider-asserted counters; no independent reconstructability of token counts, no raw-byte-plus-tokenizer binding, no customer-recomputable invoice root. **Distinguished on independent reconstructability and reconciliation.**

**Agent tracing / observability (LangSmith, OpenTelemetry-style traces):** mutable, after-the-fact logs with no cryptographic resistance to reorder/insert/delete/back-date and no single-signature causal-graph commitment. **Distinguished on sign-before-act ordering and the bound causal DAG.**

**Ensemble / mixture-of-experts inference:** combine model outputs but bind neither the panel composition nor the decision to an attestation. **Distinguished on binding panel composition to a recomputable decision.**

**On-chain SLA / parametric settlement schemes:** settle on oracle-fed metrics not bound to per-request signed measurements produced by the metered service itself, and lack a single deterministic function shared across provider, customer, and chain over a signed measurement root. **Distinguished on the signed-measurement root and the shared deterministic settlement function.**

**ML-DSA / NIST FIPS 204 and prior aggregate-signature work:** provide the signing primitive; do not teach the application-layer bind-one-payload construction over canonical inference-service facts with per-fact independent reconstruction. **Distinguished on the application-layer construction and the four embodiments.**

The novel combination of **(i)** a single aggregate post-quantum signature over a binding buffer of canonical inference-service fact digests, **(ii)** per-fact independent reconstruction by a zero-secret verifier, **(iii)** customer-side reconciliation by Merkle-root recomputation for billing and SLA, **(iv)** a sign-before-act causal-DAG commitment for agent workflows, and **(v)** panel-composition-bound consensus attestation — is not taught nor suggested by any combination of the foregoing prior art.

## ENABLEMENT — REFERENCE EMBODIMENT

- **Signing primitive:** ML-DSA-65 (NIST FIPS 204) via a production lattice library; one signature per receipt over a binding-buffer payload digest.
- **Canonicalization:** JSON with sorted keys and no insignificant whitespace; digests under SHA-256 (default, field omitted for wire compatibility) or SHA-384 (recorded) for ultra-long-life receipts; length-guarded against downgrade.
- **SiGR-Bill:** `buildCostManifest`, `signBillReceipt`, `verifyBillReceipt`, `signInvoice`, `verifyInvoice`; integer micro-USD prices; per-cycle Merkle billing root.
- **SiGR-Bond:** `signBond`/`verifyBond`, `signMeasurement`/`verifyMeasurement`, deterministic `computeBreach`, `signSettlement`/`verifySettlement`; ppm integer SLA math; Merkle window root.
- **SiGR Chain:** `buildStepCommit`, deterministic topological ordering, `signChain`/`verifyChain`; DAG with parent-commitment binding; single causal root.
- **Consensus Receipt:** `signSubReceipt`/`verifySubReceipt`, deterministic `computeConsensus` (majority/quorum/weighted/judge), `signConsensus`/`verifyConsensus`; panel Merkle root bound to decision digest.
- **Verification:** zero-secret; recompute digests, re-derive payload, verify one signature; dominated by a single ML-DSA-65 verify.
- **Anchoring / settlement:** Base mainnet, USDC-denominated.
- **Reference test suite:** four embodiments exercised by a happy-path plus tamper matrix (token inflation, price tamper, dropped invoice line, latency shave, dropped slow call, understated breach, step edit/drop/insert/reorder/cycle, dropped dissenter, misreported winner); fifty-five assertions passing.

## DRAWINGS — TO BE PREPARED

- **FIG. 1** — Bind-one-payload aggregate signing: canonical facts → per-fact digests → binding buffer → single payload digest → one ML-DSA-65 signature → independent verifier.
- **FIG. 2** — SiGR-Bill: per-request cost-manifest receipt and per-cycle Merkle invoice root with customer-side reconciliation.
- **FIG. 3** — SiGR-Bond: signed bond + per-request measurements → Merkle window root → deterministic breach/settlement shared across provider, customer, and chain.
- **FIG. 4** — SiGR Chain: agent steps as a DAG, each commitment binding parent commitments, all bound to one causal root.
- **FIG. 5** — Consensus Receipt: N signed sub-receipts → sorted panel set bound to a deterministic consensus decision under one signature.

## DECLARATIONS

This provisional is filed to establish priority of art on: (a) the bind-one-payload aggregate post-quantum signing construction (Claim 1); (b) verifiable billing reconciliation (Claim 2); (c) cryptographically-enforced service-level settlement (Claim 3); (d) causal-graph attestation of multi-step agent workflows (Claim 4); (e) multi-model consensus attestation (Claim 5); (f) hash-suite agility with downgrade protection (Claim 6); (g) public anchoring and stablecoin settlement (Claim 7); and (h) optional hardware-rooted trust binding (Claim 8).

A non-provisional utility application incorporating final claim language and formal drawings will be filed within 12 months under 35 U.S.C. § 119(e). A continuation-in-part may be filed to address downstream embodiments emerging in the next 12 months.

---

**Filing checklist for outside counsel:**
- [ ] Inventor declaration (USPTO form AIA/14)
- [ ] Provisional cover sheet (SB/16)
- [ ] Specification + claims (this document, formatted to USPTO margins/numbering)
- [ ] Drawings (FIG. 1–5)
- [ ] Filing fee — $130 small entity / $65 micro entity
- [ ] Assignment recordation to TheHiveryIQ, Inc.

**Public companion language:** "The Signed inference Guarantee Receipt (SiGR) and its billing, service-level, agent-chain, and consensus embodiments are the subject of a US provisional patent application filed by TheHiveryIQ, Inc. — Patent Pending."

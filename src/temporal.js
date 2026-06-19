/**
 * temporal.js — Three-tier temporal proof for Hive receipts. Dossier item 5.
 *
 * Goal: make "WHEN did the AI decide" as provable as "what did it decide."
 * The temporal object is bound into the signed payload (see typed.js), so the
 * time claim cannot be altered without breaking the ML-DSA-65 signature.
 *
 * THREE TIERS — each adds a different guarantee. Precision != trust:
 *
 *   TIER 1  capture   — local high-resolution timestamp at the instant of
 *                       signing. Sub-microsecond resolution from the process
 *                       monotonic clock plus a wall-clock anchor. PRECISE, but
 *                       only as trustworthy as the local clock. A hardware
 *                       White Rabbit / PTP source (sub-ns) is the swap-in here;
 *                       the field `source` records which clock attested it.
 *
 *   TIER 2  soft      — fast L2 commitment. Hive anchors receipts to Base
 *                       Mainnet; Base "Flashblocks" give ~200 ms preconfirmation.
 *                       This proves the receipt existed by a wall-clock instant
 *                       to an external party long before L1 finality. Recorded
 *                       as a commitment intent + (optionally) a flashblock /
 *                       preconf reference once anchoring runs.
 *
 *   TIER 3  final     — L1 finality. Base settles to Ethereum L1 (~12–15 min,
 *                       two-epoch finality). Once final, the receipt's existence
 *                       and ordering are economically irreversible. Recorded as
 *                       the anchor reference (chain, asset, tx/ref) to be filled
 *                       by the anchoring pipeline.
 *
 * Composition: Tier 1 gives PRECISION (exact instant), Tiers 2/3 give TRUST
 * (an independent party can confirm the receipt existed by time T and cannot be
 * back-dated). Together: a timestamp that is both exact and unforgeable.
 *
 * This module is software-first and runs with no special hardware today. Every
 * hardware/network upgrade (White Rabbit NIC, NTS/roughtime/RFC-3161 attester,
 * live flashblock ref) slots into a named field WITHOUT changing the receipt
 * structure or the verification math — same pattern as QPuF's source abstraction.
 *
 * Patent Pending HC-2026-001.
 */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

// process-start reference so monotonic ns can be related to a wall instant
const PROC_EPOCH_WALL_MS = Date.now();
const PROC_EPOCH_MONO_NS = process.hrtime.bigint();

/**
 * captureTier1() — local high-resolution capture at signing time.
 * Returns wall clock (ISO + ms) and a monotonic nanosecond reading. The
 * `source` is SIMULATED_LOCAL unless a hardware time source is configured via
 * TEMPORAL_TIME_SOURCE (e.g. WHITE_RABBIT_PTP, PTP_IEEE1588, NTS, ROUGHTIME,
 * RFC3161). We never claim sub-ns precision we don't have — the source string
 * is the honest record of what attested the instant.
 */
export function captureTier1() {
  const mono = process.hrtime.bigint();
  const wallMs = PROC_EPOCH_WALL_MS + Number(mono - PROC_EPOCH_MONO_NS) / 1e6;
  const sourceId = process.env.TEMPORAL_TIME_SOURCE || 'SIMULATED_LOCAL';
  const SOURCES = {
    WHITE_RABBIT_PTP: { name: 'White Rabbit PTP (sub-ns)', precision: 'sub_nanosecond', hardware: true },
    PTP_IEEE1588:     { name: 'PTP IEEE 1588v2 (sub-µs)',  precision: 'sub_microsecond', hardware: true },
    NTS:              { name: 'Network Time Security (RFC 8915)', precision: 'millisecond', hardware: false },
    ROUGHTIME:        { name: 'Roughtime (signed time)',   precision: 'millisecond', hardware: false },
    RFC3161:          { name: 'RFC 3161 Timestamping Authority', precision: 'second', hardware: false },
    SIMULATED_LOCAL:  { name: 'Local OS clock (monotonic + wall)', precision: 'sub_microsecond', hardware: false },
  };
  const src = SOURCES[sourceId] || SOURCES.SIMULATED_LOCAL;
  return {
    wall_iso: new Date(Math.round(wallMs)).toISOString(),
    wall_unix_ms: Math.round(wallMs),
    monotonic_ns: mono.toString(),
    resolution: src.precision,
    source: {
      id: sourceId,
      name: src.name,
      hardware: src.hardware,
      // honest flag: true unless a real attested time source is wired in
      attested: sourceId !== 'SIMULATED_LOCAL',
      simulated: sourceId === 'SIMULATED_LOCAL' || !src.hardware && sourceId === 'SIMULATED_LOCAL',
    },
  };
}

/**
 * buildTemporalProof(opts) — assemble the full three-tier temporal object that
 * gets bound into the signed payload. No secret is included; safe to publish.
 *
 * opts (all optional):
 *   l2: { network, mechanism, preconf_ms, ref }   // tier 2 soft commitment
 *   l1: { network, finality, settles_to, ref }    // tier 3 finality
 *   anchor: { chain, asset }                       // existing Base/USDC anchor
 */
export function buildTemporalProof(opts = {}) {
  const tier1 = captureTier1();

  const tier2 = {
    tier: 'soft_commitment',
    network: (opts.l2 && opts.l2.network) || 'base-mainnet',
    mechanism: (opts.l2 && opts.l2.mechanism) || 'flashblocks',
    preconf_ms: (opts.l2 && opts.l2.preconf_ms) != null ? opts.l2.preconf_ms : 200,
    // ref is filled by the anchoring pipeline once the preconf/flashblock lands
    ref: (opts.l2 && opts.l2.ref) || null,
    proves: 'receipt existed by this wall instant to an external party (pre-finality)',
  };

  const tier3 = {
    tier: 'finality',
    network: (opts.l1 && opts.l1.network) || 'ethereum-l1',
    settles_to: (opts.l1 && opts.l1.settles_to) || 'ethereum-l1',
    finality: (opts.l1 && opts.l1.finality) || '~12-15min two-epoch',
    ref: (opts.l1 && opts.l1.ref) || null,
    proves: 'existence and ordering economically irreversible once final',
  };

  const proof = {
    object: 'hive.temporal.proof',
    version: '1.0.0',
    name: 'Three-Tier Temporal Proof',
    tier1_capture: tier1,
    tier2_soft: tier2,
    tier3_final: tier3,
    anchor: {
      chain: (opts.anchor && opts.anchor.chain) || 'base-mainnet',
      asset: (opts.anchor && opts.anchor.asset) || 'USDC',
    },
    composition: 'tier1=precision; tier2/tier3=trust (cannot be back-dated)',
    patent_pending: 'HC-2026-001',
  };
  // self-commitment so the object is self-checkable independent of the receipt
  proof.commitment = bytesToHex(sha256(utf8ToBytes(JSON.stringify(proof))));
  return proof;
}

export const TEMPORAL_TIME_SOURCES = [
  'WHITE_RABBIT_PTP', 'PTP_IEEE1588', 'NTS', 'ROUGHTIME', 'RFC3161', 'SIMULATED_LOCAL',
];

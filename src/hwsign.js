/**
 * hwsign.js — Hardware-signing swap point for ML-DSA-65. Dossier item 1.
 *
 * Goal: make the ML-DSA-65 signing operation a pluggable BACKEND so the exact
 * same receipt-signing call can be served by software today and by a dedicated
 * FPGA/ASIC core tomorrow — WITHOUT changing the receipt structure, the trust
 * chain, or the verification math. Same source-abstraction pattern as QPuF's
 * QRNG/PuF sources and temporal.js's time sources.
 *
 * The signer interface used everywhere in this repo is tiny:
 *     signer.sign(msgBytes) -> sigBytes        // the only hot-path call
 *     signer.publicKeyB64 / .scheme / .version // metadata
 *     signer.trust (optional)                  // publishable attestation block
 *
 * wrapWithBackend(baseSigner) returns a NEW signer with the SAME interface whose
 * .sign() routes through the configured backend. Today only SOFTWARE is wired
 * (it calls baseSigner.sign directly). An FPGA/ASIC backend slots into the
 * BACKENDS table by implementing the same one-method contract:
 *     backend.sign(msgBytes, baseSigner) -> sigBytes
 *
 * A commercial core (e.g. PQShield PQPerform-Flare over AXI4-Lite, or an AWS F2
 * FPGA image) would back that method with a register/DMA round-trip to silicon.
 * Until then we run software and HONESTLY flag accelerated:false / attested:false
 * — we never claim hardware we don't have.
 *
 * Select via env HIVE_SIGN_BACKEND (default SOFTWARE).
 *
 * Patent Pending HC-2026-001.
 */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

/**
 * Backend registry. Each entry describes a place the ML-DSA-65 signing math can
 * physically run. `accelerated` = dedicated datapath (not general CPU).
 * `attested` = the backend can prove (cert / device id) it actually ran the op.
 * `latency_us` is the published/expected per-sign figure for transparency.
 *
 * Figures sourced from item1_hw_signing_research.md (June 2026). Software
 * baseline is the live @noble/post-quantum path on this box.
 */
export const SIGN_BACKENDS = {
  SOFTWARE: {
    id: 'SOFTWARE',
    name: 'Software ML-DSA-65 (@noble/post-quantum)',
    kind: 'software',
    accelerated: false,
    attested: false,
    interface: 'in-process',
    latency_us: null, // measured live per-sign; not a fixed claim
    fips_140_3: false,
    note: 'General-CPU reference path. The swap point that hardware replaces.',
  },
  PQSHIELD_FLARE: {
    id: 'PQSHIELD_FLARE',
    name: 'PQShield PQPerform-Flare (FPGA/ASIC)',
    kind: 'fpga_asic',
    accelerated: true,
    attested: true,
    interface: 'AXI4-Lite',
    latency_us: 175, // ~35us/iter x ~5 rejection iters @322MHz, ML-DSA-65 est.
    fips_140_3: true, // CMVP certified per vendor
    target: 'Xilinx Zynq UltraScale+ / AWS F2 VU47P / GF12LP ASIC',
    note: 'Recommended hardware path. FIPS 140-3 CMVP. Not yet wired to silicon.',
  },
  XIPHERA_XIP6220B: {
    id: 'XIPHERA_XIP6220B',
    name: 'Xiphera XIP6220B xQlave (FPGA/ASIC)',
    kind: 'fpga_asic',
    accelerated: true,
    attested: true,
    interface: 'custom-64bit',
    latency_us: null, // vendor publishes only "a few thousand ops/sec"
    fips_140_3: false,
    cavp: 'A7478', // NIST CAVP validated Oct 2025
    target: 'AMD Kintex UltraScale / Zynq MPSoC',
    note: 'Pure-RTL alt. NIST CAVP A7478. Non-AXI bus needs a bridge.',
  },
  AWS_F2_FPGA: {
    id: 'AWS_F2_FPGA',
    name: 'AWS F2 FPGA (VU47P) + licensed IP core',
    kind: 'fpga_asic',
    accelerated: true,
    attested: true,
    interface: 'PCIe/AXI',
    latency_us: 200, // IP-core dependent; +5-15us PCIe round trip
    fips_140_3: false, // depends on the loaded IP core
    target: 'f2.6xlarge VU47P, $1.98/hr — zero-capex entry point',
    note: 'Cloud FPGA host for any of the above cores. Pay-per-use eval path.',
  },
};

export const SIGN_BACKEND_IDS = Object.keys(SIGN_BACKENDS);

/**
 * Backend implementations. Each implements ONE method:
 *   sign(msgBytes, baseSigner) -> Uint8Array signature
 * plus an optional async health()/probe() a real device would expose.
 *
 * Only SOFTWARE is executable today. The hardware backends are declared with a
 * sign() that fails CLOSED with a clear "not wired" error, so a misconfigured
 * deploy never silently falls back to software while claiming hardware. When a
 * device/IP core is integrated, replace the throw with the AXI/PCIe round-trip.
 */
const IMPL = {
  SOFTWARE: {
    sign(msgBytes, baseSigner) {
      return baseSigner.sign(msgBytes);
    },
    available() { return true; },
  },
  // --- hardware backends: declared, not yet wired to silicon ---
  PQSHIELD_FLARE: hardwareStub('PQSHIELD_FLARE'),
  XIPHERA_XIP6220B: hardwareStub('XIPHERA_XIP6220B'),
  AWS_F2_FPGA: hardwareStub('AWS_F2_FPGA'),
};

function hardwareStub(id) {
  return {
    sign() {
      throw new Error(
        `hw_backend_not_wired: HIVE_SIGN_BACKEND=${id} selected but no silicon is ` +
        `connected. Integrate the ${id} IP core (see item1_hw_signing_research.md) ` +
        `or set HIVE_SIGN_BACKEND=SOFTWARE. Failing closed — never silently ` +
        `signing in software while claiming hardware.`
      );
    },
    available() { return false; },
  };
}

/**
 * resolveBackend(id?) — pick the backend descriptor. Defaults to env
 * HIVE_SIGN_BACKEND, then SOFTWARE. Throws on an unknown id.
 */
export function resolveBackend(id) {
  const key = (id || process.env.HIVE_SIGN_BACKEND || 'SOFTWARE').toUpperCase();
  const desc = SIGN_BACKENDS[key];
  if (!desc) {
    throw new Error(`unknown_sign_backend: ${key} (valid: ${SIGN_BACKEND_IDS.join(', ')})`);
  }
  return desc;
}

/**
 * buildSigningAttestation(backend) — publishable trust block describing WHERE
 * the signing math physically ran. Reveals no secret. Honest about whether the
 * run was hardware-accelerated and device-attested. Self-committed with SHA-256.
 */
export function buildSigningAttestation(backend) {
  const att = {
    object: 'hive.signing.backend',
    version: '1.0.0',
    name: 'Signing Backend Attestation',
    backend_id: backend.id,
    backend_name: backend.name,
    kind: backend.kind,
    interface: backend.interface,
    accelerated: backend.accelerated,
    attested: backend.attested,
    fips_140_3: !!backend.fips_140_3,
    cavp: backend.cavp || null,
    expected_latency_us: backend.latency_us,
    signature_scheme: { algorithm: 'ML-DSA-65', spec: 'NIST FIPS 204' },
    note: backend.note,
    swap_point: 'signer.sign(msgBytes) — software today, FPGA/ASIC drop-in',
    patent_pending: 'HC-2026-001',
  };
  att.commitment = bytesToHex(sha256(utf8ToBytes(JSON.stringify(att))));
  return att;
}

/**
 * wrapWithBackend(baseSigner, opts?) — returns a signer with the SAME interface
 * whose .sign() routes through the selected backend, and whose .trust merges a
 * signing-backend attestation alongside any existing (e.g. QPuF) trust block.
 *
 * opts: { backend?: id }  // override env selection
 *
 * The returned object preserves publicKey*, scheme, version, and any pre-existing
 * trust so it remains a drop-in for SIGNER / the QPuF signer in server.js.
 */
export function wrapWithBackend(baseSigner, opts = {}) {
  const backend = resolveBackend(opts.backend);
  const impl = IMPL[backend.id];
  const attestation = buildSigningAttestation(backend);

  // Merge the backend attestation into the trust block without clobbering QPuF.
  let trust = baseSigner.trust;
  if (trust) {
    trust = { ...trust, signing_backend: attestation };
    // extend the human-readable chain if present
    if (Array.isArray(trust.chain) && !trust.chain.includes('signing_backend')) {
      trust = { ...trust, chain: [...trust.chain, 'signing_backend'] };
    }
  } else {
    trust = { object: 'hive.trust', version: '1.0.0', signing_backend: attestation };
  }

  return {
    ...baseSigner,
    scheme: baseSigner.scheme,
    version: baseSigner.version,
    publicKey: baseSigner.publicKey,
    publicKeyB64: baseSigner.publicKeyB64,
    publicKeyHex: baseSigner.publicKeyHex,
    sign(msgBytes) { return impl.sign(msgBytes, baseSigner); },
    trust,
    signing_backend: attestation, // also exposed top-level for /verify badge
  };
}

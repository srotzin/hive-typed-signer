// MiR tests: identity-continuity math (pure), substitution detection vs expected_model,
// relineage detection across steps, integer flicker scoring (weights swap weighted),
// sign+verify roundtrip, per-step-root verification against raw steps, and tamper
// detection (flicker score, identity_root, asserts declaration, substitution count).
import { SIGNER, verifyFn } from '../src/key.js';
import { signMir, verifyMir, computeLineage } from '../src/mir.js';
import { manifestRoot } from '../src/manifest.js';
import { resolveSuite, merkleRoot } from '../src/typed.js';
import { ok, eq, section, summary } from './_assert.js';

const PUB = SIGNER.publicKey;
const S = resolveSuite('sha-256');

// Three distinct served-model identities used across the tests.
const GLM = { model_id: 'zai/GLM-5.2', weights_sha3: 'a'.repeat(64), config_hash: 'c1'.repeat(32), endpoint: 'https://api.together.xyz/v1' };
const GLM_RECONF = { model_id: 'zai/GLM-5.2', weights_sha3: 'a'.repeat(64), config_hash: 'c2'.repeat(32), endpoint: 'https://api.together.xyz/v1' };
const CHEAP = { model_id: 'mini/Cheap-7B', weights_sha3: 'b'.repeat(64), config_hash: 'c1'.repeat(32), endpoint: 'https://api.together.xyz/v1' };

section('mir: stable single identity matching expectation -> flicker 0');
{
  const lin = computeLineage([GLM], 'zai/GLM-5.2', S);
  eq(lin.step_count, 1, 'one step');
  eq(lin.relineage.length, 0, 'no relineage on single step');
  ok(lin.substitution.matched_all, 'expectation matched');
  eq(lin.identity_flicker_bp, 0, 'flicker 0 when stable + matching');
  ok(lin.stable, 'stable true');
  // identity_root is merkle over the single manifest root
  const expectRoot = merkleRoot([manifestRoot(GLM.model_id, GLM.weights_sha3, GLM.config_hash, GLM.endpoint, S)], S);
  eq(lin.identity_root, expectRoot, 'identity_root = merkle over per-step manifest roots');
}

section('mir: substitution — expected GLM-5.2 but a cheaper model was served');
{
  // caller bought GLM-5.2; step 0 served the cheap model
  const lin = computeLineage([CHEAP], 'zai/GLM-5.2', S);
  ok(!lin.substitution.matched_all, 'substitution detected');
  eq(lin.substitution.mismatched_steps.length, 1, 'one mismatched step');
  eq(lin.identity_flicker_bp, 2000, 'one expectation miss = 2000bp');
  ok(!lin.stable, 'not stable under substitution');
}

section('mir: relineage — model swapped mid-session (weights change weighted)');
{
  // GLM then swapped to CHEAP: changed model_id + weights_sha3 (config same)
  const lin = computeLineage([GLM, CHEAP], 'zai/GLM-5.2', S);
  eq(lin.relineage.length, 1, 'one relineage event');
  ok(lin.relineage[0].changed_fields.includes('model_id'), 'model_id change detected');
  ok(lin.relineage[0].changed_fields.includes('weights_sha3'), 'weights_sha3 change detected');
  ok(!lin.relineage[0].changed_fields.includes('config_hash'), 'config_hash unchanged not flagged');
  // score: relineage 2500 + weights bonus 1500 + one expectation miss (CHEAP) 2000 = 6000
  eq(lin.identity_flicker_bp, 6000, 'relineage(2500)+weights(1500)+1 miss(2000)=6000bp');
}

section('mir: reconfig only (same model, config change) is a softer relineage');
{
  const lin = computeLineage([GLM, GLM_RECONF], 'zai/GLM-5.2', S);
  eq(lin.relineage.length, 1, 'config change is a relineage event');
  eq(lin.relineage[0].changed_fields.length, 1, 'only config_hash changed');
  ok(lin.relineage[0].changed_fields.includes('config_hash'), 'config_hash flagged');
  ok(lin.substitution.matched_all, 'model_id still matched expectation both steps');
  eq(lin.identity_flicker_bp, 2500, 'relineage(2500), no weights bonus, no expectation miss');
}

section('mir: flicker score caps at 10000');
{
  const many = [GLM, CHEAP, GLM, CHEAP, GLM, CHEAP];
  const lin = computeLineage(many, 'zai/GLM-5.2', S);
  eq(lin.identity_flicker_bp, 10000, 'score clamped to 10000bp');
}

section('mir: sign + verify roundtrip (stable)');
{
  const { envelope, timing_us } = signMir({ subject_id: 'ans-1', expected_model: 'zai/GLM-5.2', steps: [GLM] }, SIGNER);
  ok(typeof timing_us.sign_us === 'number', 'sign timing reported');
  eq(envelope.object, 'sigr.mir.receipt', 'receipt object tag');
  eq(envelope.asserts, 'model_identity_and_continuity_only', 'binding non-truth declaration present');
  const r = verifyMir(envelope, verifyFn, PUB);
  ok(r.valid, 'valid roundtrip: ' + r.reasons.join(','));
  eq(r.identity_flicker_bp, 0, 'verified flicker 0');
  ok(r.stable, 'verified stable');
}

section('mir: sign + verify roundtrip (substitution + relineage)');
{
  const { envelope } = signMir({ subject_id: 'ans-2', expected_model: 'zai/GLM-5.2', steps: [GLM, CHEAP] }, SIGNER);
  const r = verifyMir(envelope, verifyFn, PUB);
  ok(r.valid, 'valid roundtrip with events: ' + r.reasons.join(','));
  eq(r.identity_flicker_bp, 6000, 'verified flicker 6000bp');
  eq(r.relineage.length, 1, 'verified one relineage event');
  ok(!r.substitution.matched_all, 'verified substitution finding');
}

section('mir: verify with raw steps confirms per-step roots (strongest check)');
{
  const steps = [GLM, CHEAP];
  const { envelope } = signMir({ subject_id: 'ans-3', expected_model: 'zai/GLM-5.2', steps }, SIGNER);
  const r = verifyMir(envelope, verifyFn, PUB, { steps });
  ok(r.valid, 'valid when raw steps match per_step_roots: ' + r.reasons.join(','));
  // tamper a raw step -> per-step root must mismatch
  const tampered = [GLM, { ...CHEAP, weights_sha3: 'f'.repeat(64) }];
  const r2 = verifyMir(envelope, verifyFn, PUB, { steps: tampered });
  ok(!r2.valid, 'invalid when raw step does not match carried per_step_root');
  ok(r2.reasons.some(x => x.startsWith('step_root_mismatch_at_')), 'flags step_root_mismatch');
}

section('mir: tamper detection — flicker score inflated');
{
  const { envelope } = signMir({ subject_id: 'ans-4', expected_model: 'zai/GLM-5.2', steps: [GLM] }, SIGNER);
  const t = JSON.parse(JSON.stringify(envelope));
  t.identity_flicker_bp = 9000;
  t.lineage.identity_flicker_bp = 9000;
  const r = verifyMir(t, verifyFn, PUB);
  ok(!r.valid, 'inflated flicker rejected');
  ok(r.reasons.includes('flicker_score_mismatch'), 'flags flicker_score_mismatch');
}

section('mir: tamper detection — asserts declaration stripped');
{
  const { envelope } = signMir({ subject_id: 'ans-5', expected_model: 'zai/GLM-5.2', steps: [GLM] }, SIGNER);
  const t = JSON.parse(JSON.stringify(envelope));
  t.asserts = 'output_is_true';
  const r = verifyMir(t, verifyFn, PUB);
  ok(!r.valid, 'tampered asserts rejected');
  ok(r.reasons.includes('asserts_declaration_tampered'), 'flags asserts_declaration_tampered');
}

section('mir: tamper detection — hide a substitution (shrink mismatched_steps)');
{
  const { envelope } = signMir({ subject_id: 'ans-6', expected_model: 'zai/GLM-5.2', steps: [CHEAP] }, SIGNER);
  const t = JSON.parse(JSON.stringify(envelope));
  t.lineage.substitution.mismatched_steps = []; // pretend it matched
  t.lineage.substitution.matched_all = true;
  const r = verifyMir(t, verifyFn, PUB);
  ok(!r.valid, 'hidden substitution rejected');
}

summary('mir');

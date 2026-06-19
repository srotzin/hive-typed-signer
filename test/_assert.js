// Minimal zero-dep test harness — matches the wiped eligibility.test.js style.
// Run a file directly: `node test/<name>.test.js`. Exit code 1 on any failure.
let pass = 0, fail = 0;
const fails = [];

export function ok(cond, msg) {
  if (cond) { pass++; }
  else { fail++; fails.push(msg); console.error('  FAIL: ' + msg); }
}

export function eq(a, b, msg) {
  ok(a === b, `${msg} (expected ${JSON.stringify(b)}, got ${JSON.stringify(a)})`);
}

export function section(name) { console.log('\n' + name); }

export function summary(suite) {
  console.log(`\n${suite}: ${pass} passed, ${fail} failed`);
  if (fail > 0) {
    console.error(`\n${suite} FAILED (${fail}):`);
    for (const f of fails) console.error('  - ' + f);
    process.exit(1);
  }
}

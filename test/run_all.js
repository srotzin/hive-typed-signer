// Runs every *.test.js in this dir as a child process; exits 1 if any fails.
import { readdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawnSync } from 'child_process';

const here = dirname(fileURLToPath(import.meta.url));
const files = readdirSync(here).filter(f => f.endsWith('.test.js')).sort();
let failed = 0;
for (const f of files) {
  const r = spawnSync(process.execPath, [join(here, f)], { stdio: 'inherit' });
  if (r.status !== 0) failed++;
}
console.log(`\n=== suite: ${files.length} files, ${failed} failed ===`);
process.exit(failed === 0 ? 0 : 1);

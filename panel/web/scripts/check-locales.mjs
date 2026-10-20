// Checks that every locale has the same keys and the same {placeholders} as en.json.
// Plural variants (key.one / .few / .many / .other) are compared by their base key:
// a locale may carry any set of forms, but every form needs the same placeholders as en.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'locales');
const PLURAL = /\.(zero|one|two|few|many|other)$/;
const base = (k) => k.replace(PLURAL, '');
const holders = (s) => [...new Set([...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]))].sort().join(',');

function load(file) {
  const j = JSON.parse(readFileSync(join(dir, file), 'utf8'));
  const bases = new Map(); // base key -> set of placeholder signatures
  for (const [k, v] of Object.entries(j)) {
    if (typeof v !== 'string') throw new Error(`${file}: ${k} is not a string`);
    if (!bases.has(base(k))) bases.set(base(k), new Set());
    bases.get(base(k)).add(holders(v));
  }
  return bases;
}

const ref = load('en.json');
let bad = 0;
for (const f of readdirSync(dir).filter((x) => x.endsWith('.json') && x !== 'en.json')) {
  const cur = load(f);
  for (const k of ref.keys()) if (!cur.has(k)) { console.error(`${f}: missing ${k}`); bad++; }
  for (const k of cur.keys()) if (!ref.has(k)) { console.error(`${f}: extra ${k}`); bad++; }
  for (const [k, sig] of cur) {
    const want = ref.get(k);
    if (!want) continue;
    if (sig.size !== 1 || want.size !== 1 || [...sig][0] !== [...want][0]) {
      console.error(`${f}: placeholders differ in ${k}: [${[...sig]}] vs en [${[...want]}]`);
      bad++;
    }
  }
  console.log(`${f}: ${cur.size} keys checked`);
}
if (bad) { console.error(`${bad} problem(s)`); process.exit(1); }
console.log('locales OK');

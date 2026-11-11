import { readFileSync } from 'node:fs';

const lockfiles = ['panel/web/package-lock.json', 'tests/browser/package-lock.json'];
const allowed = new Set(['deepmerge@4.3.1:GHSA-gcqx-w48m-w2h4']);
const packages = new Map();

for (const file of lockfiles) {
  const lock = JSON.parse(readFileSync(file, 'utf8'));
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    if (!path.includes('node_modules/') || !meta.version) continue;
    const name = path.split('node_modules/').at(-1);
    packages.set(`${name}@${meta.version}`, { name, version: meta.version });
  }
}

const entries = [...packages.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
const response = await fetch('https://api.osv.dev/v1/querybatch', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    queries: entries.map(({ name, version }) => ({ package: { ecosystem: 'npm', name }, version })),
  }),
});
if (!response.ok) throw new Error(`OSV query failed: HTTP ${response.status}`);
const { results } = await response.json();
const findings = [];
for (let i = 0; i < entries.length; i++) {
  const { name, version } = entries[i];
  for (const vuln of results[i]?.vulns ?? []) {
    const key = `${name}@${version}:${vuln.id}`;
    findings.push({ key, allowed: allowed.has(key) });
  }
}
for (const finding of findings) {
  console.log(`${finding.allowed ? 'ALLOWED (upstream has no fix yet)' : 'VULNERABLE'} ${finding.key}`);
}
console.log(`Checked ${entries.length} locked npm package versions; ${findings.length} advisories.`);
if (findings.some((finding) => !finding.allowed)) process.exit(1);

// Convert actual Chromium execution ranges; never evaluate unvisited UI code.
const fs = require('node:fs/promises');
const path = require('node:path');
const v8ToIstanbul = require('v8-to-istanbul');

async function main() {
  const directory = '_tmp/evidence/js-v8';
  const files = (await fs.readdir(directory)).filter(name => name.endsWith('.json'));
  if (!files.length) throw new Error('Missing browser execution coverage');
  const covered = new Map();
  const sourcePaths = (await fs.readdir('web')).filter(name => name.endsWith('.js'));
  for (const name of sourcePaths) covered.set('web/' + name, new Map());
  const browserOnly = process.argv.includes('--browser-only');
  if (!browserOnly) {
    covered.set('scripts/ci/browser_coverage.cjs', new Map());
    const nodeDirectory = '_tmp/evidence/node-v8';
    for (const file of (await fs.readdir(nodeDirectory)).filter(name => name.endsWith('.json'))) {
      const data = JSON.parse(await fs.readFile(path.join(nodeDirectory, file), 'utf8'));
      const entries = data.result.filter(entry => entry.url === 'file://' + path.resolve('scripts/ci/browser_coverage.cjs'));
      await merge(entries, covered, true);
    }
  }
  for (const file of files) {
    const entries = JSON.parse(await fs.readFile(path.join(directory, file), 'utf8'));
    await merge(entries, covered, false);
  }
  const records = [];
  for (const [name, lines] of covered) {
    if (!lines.size) throw new Error('Missing UI file coverage: ' + name);
    const ordered = [...lines.entries()].sort((a, b) => a[0] - b[0]);
    records.push('SF:' + name, ...ordered.map(([line, hits]) => `DA:${line},${hits}`),
      'LF:' + lines.size, 'LH:' + ordered.filter(([, hits]) => hits > 0).length, 'end_of_record');
  }
  await fs.writeFile('_tmp/evidence/javascript.lcov', records.join('\n') + '\n');
}
async function merge(entries, covered, nativeNode) {
  for (const entry of entries) {
    const name = nativeNode ? 'scripts/ci/browser_coverage.cjs'
      : 'web/' + new URL(entry.url).pathname.split('/').at(-1);
    if (!covered.has(name)) continue;
    const source = await fs.readFile(name, 'utf8');
    if (!nativeNode && entry.source !== source) throw new Error('Browser coverage source mismatch');
    const converter = v8ToIstanbul(name, 0, {source});
    await converter.load();
    converter.applyCoverage(entry.functions);
    const data = Object.values(converter.toIstanbul())[0];
    const lines = covered.get(name);
    for (const [id, location] of Object.entries(data.statementMap)) {
      for (let line = location.start.line; line <= location.end.line; line++) {
        lines.set(line, Math.max(lines.get(line) || 0, data.s[id]));
      }
    }
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });

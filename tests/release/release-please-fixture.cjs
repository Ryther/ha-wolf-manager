'use strict';
// Execute actual upstream 17.6.0 updaters/Manifest with simulated GitHub history.
// Source clone must be the release-please-action v5.0.0 bundled core version.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = path.resolve(process.argv[2] || '');
assert.equal(JSON.parse(fs.readFileSync(path.join(source, 'package.json'))).version, '17.6.0');
const {Version} = require(path.join(source, 'build/src/version.js'));
const {Manifest} = require(path.join(source, 'build/src/manifest.js'));
const {GenericToml} = require(path.join(source, 'build/src/updaters/generic-toml.js'));
const {GenericJson} = require(path.join(source, 'build/src/updaters/generic-json.js'));
const {GenericYaml} = require(path.join(source, 'build/src/updaters/generic-yaml.js'));
const toml = require(path.join(source, 'node_modules/@iarna/toml'));
const yaml = require(path.join(source, 'node_modules/js-yaml'));
const config = JSON.parse(fs.readFileSync('release-please-config.json'));
const extras = config.packages['.']['extra-files'];
const current=fs.readFileSync('version.txt','utf8').trim().split('.').map(Number);
const next=`${current[0]}.${current[1]+1}.0`;
const bump=Version.parse(next);
const original = new Map(); const updated = new Map();
for (const file of extras) {
  const content = updated.get(file.path) || fs.readFileSync(file.path, 'utf8');
  if (!original.has(file.path)) original.set(file.path, content);
  const Updater = {toml: GenericToml, json: GenericJson, yaml: GenericYaml}[file.type];
  updated.set(file.path, new Updater(file.jsonpath, bump).updateContent(content));
}
assert.equal(toml.parse(updated.get('Cargo.toml')).workspace.package.version, next);
const before = toml.parse(original.get('Cargo.lock')).package;
const after = toml.parse(updated.get('Cargo.lock')).package;
const own = new Set(['wolf-core','ha-wolf-manager','wolf-manager-host']);
assert.equal(after.filter(p => own.has(p.name) && !p.source).length, 3);
for (let i=0; i<before.length; i++) {
  assert.deepEqual(after[i], own.has(before[i].name) && !before[i].source ? {...before[i],version:next} : before[i]);
}
for (const file of ['package.json','package-lock.json']) assert.equal(JSON.parse(updated.get(file)).version, next);
assert.equal(JSON.parse(updated.get('package-lock.json')).packages[''].version, next);
assert.equal(yaml.load(updated.get('wolf_manager/config.yaml')).version, next);
assert.equal(yaml.load(updated.get('wolf_manager/config.yaml')).image, 'ghcr.io/ryther/ha-wolf-manager');
for (const file of ['crates/wolf-core/Cargo.toml','crates/wolf-manager/Cargo.toml','crates/wolf-host/Cargo.toml']) {
  assert.equal(toml.parse(fs.readFileSync(file,'utf8')).package.version.workspace, true);
  assert.equal(updated.has(file), false);
}
const quiet = {info(){},warn(){},debug(){},error(){}};
const github = {
  repository: {owner:'Ryther',repo:'ha-wolf-manager',defaultBranch:'main'},
  async *releaseIterator(){}, async *tagIterator(){}, async *pullRequestIterator(){},
  async *mergeCommitIterator(){yield {sha:'a'.repeat(40),message:'feat(manager): first public implementation',files:['crates/wolf-manager/src/lib.rs']};},
  async getFileContentsOnBranch(file){return {parsedContent:fs.existsSync(file)?fs.readFileSync(file,'utf8'):'',sha:'b'.repeat(40)};},
};
const settings = {releaseType:'simple',component:'ha-wolf-manager',includeComponentInTag:false,
  initialVersion:config['initial-version'] || config.packages['.']['initial-version'],
  versionFile:'version.txt',extraFiles:extras};
async function proposal(versions) {
  const manifest = new Manifest(github,'main',{'.':settings},versions,{logger:quiet,draft:true});
  const prs = await manifest.buildPullRequests();
  assert.equal(prs.length,1);
  return prs[0].version.toString();
}
(async()=>{
  assert.equal(settings.initialVersion,'0.1.0');
  const actualManifest=JSON.parse(fs.readFileSync('.release-please-manifest.json'));
  assert.ok(Object.keys(actualManifest).every(key=>key==='.' && /^\d+\.\d+\.\d+$/.test(actualManifest[key])));
  assert.equal(await proposal({}), '0.1.0');
  // This counterexample proves why an invented initial prior release is unsafe.
  assert.equal(await proposal({'.':Version.parse('0.1.0')}),'0.2.0');
  console.log(`Actual Release Please 17.6.0: empty-history first version 0.1.0; inherited workspace/owned lock/npm/add-on ${next} bump preserved unrelated metadata.`);
})().catch(error=>{console.error(error);process.exitCode=1;});

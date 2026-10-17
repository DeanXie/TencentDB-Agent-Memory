import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { generateGatewayManifestV2 } from './generate-gateway-manifest-v2.mjs';

const sha = x => crypto.createHash('sha256').update(x).digest('hex');
function fixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'manifest-v2-node-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, 'candidate'); fs.mkdirSync(root);
  const put = (p, bytes) => { const f = path.join(root, p); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, bytes); };
  const graph = { format: 'gateway-js-dependency-staging/v1', edges: [{ status: 'UNRESOLVED' }], TRANSITIVE_CLOSURE_PROVEN: false, NATIVE_LOAD_VERIFIED: false, DEVELOPMENT_PATH_ESCAPE: false };
  const graphBytes = JSON.stringify(graph);
  const report = { format: 'gateway-js-candidate-closure/v1', entryOutput: 'app/src/gateway/server.js', CANDIDATE_BUILD_SUCCESS: true, buildExitCode: 0,
    buildTool: { name: 'esbuild', version: '0.28.2', typescriptVersion: '6.0.3', lockVersionMatched: true, lockSha256: '1'.repeat(64),
      jsEntrypoints: [{ path: 'node_modules/esbuild/lib/main.js', bytes: 1, sha256: '2'.repeat(64) }], executableIdentity: { bytes: 1, sha256: '3'.repeat(64) }, transformCalls: 1 },
    node: { version: 'v24.16.0', platform: 'win32', architecture: 'x64', moduleABI: '137', napi: '10', runtimeCompatibility: 'NOT_LOAD_VERIFIED' },
    jsDependencyStaging: { graphPath: 'js-dependency-graph.json', graphSha256: sha(graphBytes), unresolvedEdges: 1, TRANSITIVE_CLOSURE_PROVEN: false, NATIVE_LOAD_VERIFIED: false, DEVELOPMENT_PATH_ESCAPE: false },
    closureGateExitCode: 2, RELEASE_ELIGIBLE: false, RELEASE_DEPENDENCY_CLOSURE_COMPLETE: false };
  put('closure-report.json', JSON.stringify(report)); put('js-dependency-graph.json', graphBytes);
  put('app/src/gateway/server.js', 'export {};\n'); put('app/node_modules/@scope/pkg/package.json', '{"type":"module"}');
  put('app/node_modules/@scope/pkg/native.node', 'INERT_NATIVE'); put('app/node_modules/@scope/pkg/dict.txt', 'INERT_RESOURCE');
  fs.mkdirSync(path.join(root, 'empty'));
  const options = { candidateRoot: root, manifestPath: path.join(base, 'manifest-v2.json') };
  return { root, base, put, report, options, run: () => generateGatewayManifestV2(options) };
}
test('real file identities, explicit directories, scoped packages and blocked runtime states', t => {
  const f = fixture(t), r = f.run(), m = JSON.parse(fs.readFileSync(r.manifestPath, 'utf8'));
  assert.equal(m.format_version, 2); assert.equal(m.production_eligible, false); assert.equal(m.closure.unresolved_edges, 1);
  assert.ok(m.directories.includes('empty')); assert.ok(Object.isFrozen(r));
  assert.equal(m.runtime.native_load_verified, false); assert.equal(m.runtime.dependency_closure_proven, false);
  for (const x of m.files) { const b = fs.readFileSync(path.join(f.root, x.path)); assert.equal(x.sha256, sha(b)); assert.equal(x.size, b.length); }
  assert.equal(m.files.find(x => x.path.endsWith('.node')).kind, 'native');
  assert.equal(m.files.find(x => x.path.endsWith('dict.txt')).kind, 'resource');
});
test('V2 permits a file larger than V1 and more than 256 files', t => {
  const f = fixture(t); f.put('app/node_modules/@scope/pkg/large.bin', Buffer.alloc(65537));
  for (let i = 0; i < 260; i++) f.put(`app/src/m${i}.js`, 'export {};');
  assert.ok(f.run().fileCount > 256);
});
test('output cannot be inside candidate and existing output is never overwritten', t => {
  const f = fixture(t); assert.throws(() => generateGatewayManifestV2({ ...f.options, manifestPath: path.join(f.root, 'manifest.json') }), /output_scope_invalid/);
  f.run(); const before = fs.readFileSync(f.options.manifestPath); assert.throws(f.run, /output_exists/); assert.deepEqual(fs.readFileSync(f.options.manifestPath), before);
});
test('closed options reject extra fields and accessors without invoking them', t => {
  const f = fixture(t); assert.throws(() => generateGatewayManifestV2({ ...f.options, extra: true }), /options_invalid/);
  let called = false; const opts = { ...f.options }; Object.defineProperty(opts, 'candidateRoot', { get() { called = true; return f.root; } });
  assert.throws(() => generateGatewayManifestV2(opts), /options_invalid/); assert.equal(called, false);
});
for (const name of ['bad.', 'bad ', 'nul.txt', 'COM1.js', 'file~1', 'bad:stream', 'é.txt']) {
  test(`unsafe member spelling rejected: ${name}`, t => {
    const f = fixture(t); // Manifest path policy is tested even where Win32 cannot create the spelling.
    f.report.entryOutput = `app/${name}`; f.put('closure-report.json', JSON.stringify(f.report)); assert.throws(f.run, /report_invalid|path_invalid/);
  });
}
test('raw root aliases rejected before normalization', t => {
  const f = fixture(t); for (const suffix of ['.', ' ', '/..', '/./']) assert.throws(() => generateGatewayManifestV2({ ...f.options, candidateRoot: f.root + suffix }), /path_invalid/);
});
test('case-insensitive Windows spelling does not duplicate enumerated identities', t => {
  const f = fixture(t); f.put('app/UPPER.js', 'x'); f.put('app/upper.js', 'x');
  // Windows cannot represent both; even the remaining uppercase spelling must have a single enumerated identity.
  const r = f.run(), m = JSON.parse(fs.readFileSync(r.manifestPath)); const paths = m.files.map(x => x.path.toLowerCase()); assert.equal(new Set(paths).size, paths.length);
});
test('case-colliding directory enumeration is rejected before recursion', t => {
  const f = fixture(t);
  const code = `import fs from 'node:fs';import assert from 'node:assert/strict';
    import {generateGatewayManifestV2 as g} from ${JSON.stringify(new URL('./generate-gateway-manifest-v2.mjs', import.meta.url).href)};
    const o=JSON.parse(process.argv[1]),read=fs.readdirSync;
    fs.readdirSync=function(p,...args){const names=read.call(this,p,...args);return String(p)===o.candidateRoot?[...names,'APP']:names;};
    assert.throws(()=>g(o),e=>e.message==='path_alias_rejected');`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code, JSON.stringify(f.options)], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); assert.equal(fs.existsSync(f.options.manifestPath), false);
});
test('junction members rejected, no manifest produced', t => {
  const f = fixture(t), link = path.join(f.root, 'escape'); fs.symlinkSync(f.base, link, 'junction');
  assert.throws(f.run, /reparse_rejected/); assert.equal(fs.existsSync(f.options.manifestPath), false); fs.rmdirSync(link);
});
test('environment-controlled SystemRoot cannot select a candidate executable', t => {
  const f = fixture(t); f.put('System32/WindowsPowerShell/v1.0/powershell.exe', 'INERT_NOT_EXECUTABLE');
  // Change the call-time environment after Node bootstrap, so this tests our function rather
  // than Windows/OpenSSL bootstrap's separate dependency on the real SystemRoot.
  const code = `import {generateGatewayManifestV2 as g} from ${JSON.stringify(new URL('./generate-gateway-manifest-v2.mjs', import.meta.url).href)}; process.env.SystemRoot=process.argv[2]; g(JSON.parse(process.argv[1]));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code, JSON.stringify(f.options), f.root], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); assert.ok(fs.existsSync(f.options.manifestPath));
});
test('all-tag check precedes recursion even when Node does not identify the junction as a symlink', t => {
  const f = fixture(t), link = path.join(f.root, 'escape'); fs.symlinkSync(f.base, link, 'junction');
  const code = `import fs from 'node:fs';import assert from 'node:assert/strict';
    import {generateGatewayManifestV2 as g} from ${JSON.stringify(new URL('./generate-gateway-manifest-v2.mjs', import.meta.url).href)};
    const link=process.argv[2], lstat=fs.lstatSync, read=fs.readdirSync;
    fs.lstatSync=function(p,...args){const s=lstat.call(this,p,...args);if(String(p)===link){s.isSymbolicLink=()=>false;s.isDirectory=()=>true;}return s;};
    fs.readdirSync=function(p,...args){if(String(p)===link)throw new Error('entered_reparse_before_check');return read.call(this,p,...args);};
    assert.throws(()=>g(JSON.parse(process.argv[1])),e=>e.message==='reparse_rejected');`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code, JSON.stringify(f.options), link], { encoding: 'utf8' });
  fs.rmdirSync(link); assert.equal(r.status, 0, r.stderr); assert.equal(fs.existsSync(f.options.manifestPath), false);
});
test('ADS is rejected before manifest publication', t => {
  const f = fixture(t); f.put('app/src/gateway/server.js:extra', 'INERT_ADS'); assert.throws(f.run, /alternate_stream_rejected/);
});
test('native and code type labels respect Windows case semantics', t => {
  const f = fixture(t); for (const p of ['app/x.NODE', 'app/x.DLL', 'app/src/X.JS', 'app/x.JSON']) f.put(p, 'INERT');
  const m = JSON.parse(fs.readFileSync(f.run().manifestPath));
  assert.deepEqual(['app/x.NODE', 'app/x.DLL', 'app/src/X.JS', 'app/x.JSON'].map(p => m.files.find(f => f.path === p).kind), ['native', 'native', 'gateway-js', 'metadata']);
});
test('closure and graph identities must agree', t => {
  const f = fixture(t); f.put('js-dependency-graph.json', '{}'); assert.throws(f.run, /report_invalid/);
});
test('unresolved edge count cannot be understated', t => {
  const f = fixture(t); f.report.jsDependencyStaging.unresolvedEdges = 0; f.put('closure-report.json', JSON.stringify(f.report)); assert.throws(f.run, /report_invalid/);
});
test('production and native claims never pass through', t => {
  for (const key of ['RELEASE_ELIGIBLE', 'RELEASE_DEPENDENCY_CLOSURE_COMPLETE']) {
    const f = fixture(t); f.report[key] = true; f.put('closure-report.json', JSON.stringify(f.report)); assert.throws(f.run, /report_invalid/);
  }
});
test('missing entry and malformed or oversized report fail without output', t => {
  for (const mode of ['missing', 'invalid', 'oversize']) {
    const f = fixture(t); if (mode === 'missing') fs.unlinkSync(path.join(f.root, 'app/src/gateway/server.js'));
    else f.put('closure-report.json', mode === 'invalid' ? '{' : Buffer.alloc(4 * 1024 * 1024 + 1));
    assert.throws(f.run); assert.equal(fs.existsSync(f.options.manifestPath), false);
  }
});
test('file size cap is checked before hashing or allocating contents', t => {
  const f = fixture(t); const file = path.join(f.root, 'oversize.bin'); fs.closeSync(fs.openSync(file, 'w')); fs.truncateSync(file, 256 * 1024 * 1024 + 1);
  assert.throws(f.run, /resource_limit/);
});
test('cross-language Rust consumes Node manifest and rejects subsequent native/resource/report tampering', t => {
  const f = fixture(t), r = f.run(); const binary = process.env.V2_RUST_TEST_BINARY;
  assert.ok(binary, 'host harness must supply independently built Rust integration test binary');
  function check(expected) {
    const p = spawnSync(binary, ['cross_language_candidate', '--exact', '--nocapture'], { encoding: 'utf8', env: { ...process.env, V2_CROSS_ROOT: f.root, V2_CROSS_MANIFEST: r.manifestPath, V2_CROSS_EXPECT: expected } });
    assert.equal(p.status, 0, `${p.stdout}\n${p.stderr}`);
  }
  check('ok');
  const originalManifest = fs.readFileSync(r.manifestPath);
  const changed = JSON.parse(originalManifest); changed.node.moduleABI = '999';
  fs.writeFileSync(r.manifestPath, JSON.stringify(changed)); check('report_invalid');
  changed.node.moduleABI = '137'; changed.files[0].unexpected = true;
  fs.writeFileSync(r.manifestPath, JSON.stringify(changed)); check('manifest_invalid');
  fs.writeFileSync(r.manifestPath, originalManifest);
  for (const file of ['app/node_modules/@scope/pkg/native.node', 'app/node_modules/@scope/pkg/dict.txt', 'closure-report.json']) {
    const original = fs.readFileSync(path.join(f.root, file)); f.put(file, 'tamper'); check('file_identity_mismatch'); f.put(file, original);
  }
});

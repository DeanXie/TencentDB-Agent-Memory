import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { packageCandidate } from './package-protected-gateway.mjs';

const bodies = {
  'config/gateway.json': '{"synthetic":true}\n',
  'gateway/server.ts': 'export const syntheticGateway = true;\n',
  'loader/tsx.mjs': 'export {};\n',
  'runtime/node.exe': 'R1_SYNTHETIC_NODE_NOT_EXECUTABLE\n',
};
function setup(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r1-node-'));
  t.after(() => fs.rmSync(root, { recursive: true }));
  const sourceRoot = path.join(root, 'inputs');
  fs.mkdirSync(sourceRoot);
  for (const [p, body] of Object.entries(bodies)) {
    fs.mkdirSync(path.dirname(path.join(sourceRoot, p)), { recursive: true });
    fs.writeFileSync(path.join(sourceRoot, p), body);
  }
  return { root, spec: { mode: 'synthetic', sourceRoot, outputParent: root, files: Object.keys(bodies) } };
}
function reject(spec, code) { assert.throws(() => packageCandidate(spec), e => e.message === code); }

test('explicit four-file synthetic package has independent hashes and no production eligibility', t => {
  const { spec } = setup(t);
  const result = packageCandidate(spec);
  assert.ok(Object.isFrozen(result));
  assert.equal(result.productionEligible, false);
  const m = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8'));
  assert.equal(m.scope, 'synthetic-fixture');
  assert.equal(m.production_eligible, false);
  assert.equal(m.files.length, 4);
  for (const item of m.files) {
    const expected = Buffer.from(bodies[item.path]);
    assert.deepEqual(fs.readFileSync(path.join(result.payloadRoot, item.path)), expected);
    assert.equal(item.sha256, crypto.createHash('sha256').update(expected).digest('hex'));
    assert.equal(item.size, expected.length);
  }
});
test('real Gateway mode fails closed before reading development inputs', t => {
  const { spec, root } = setup(t);
  reject({ ...spec, mode: 'gateway', sourceRoot: 'Z:\\not-read' }, 'gateway_dependency_closure_unproven');
  assert.deepEqual(fs.readdirSync(root), ['inputs']);
});
test('explicit input list rejects missing required roles duplicates and undeclared dependencies', t => {
  const { spec } = setup(t);
  reject({ ...spec, files: spec.files.slice(1) }, 'manifest_invalid');
  reject({ ...spec, files: [...spec.files, spec.files[0]] }, 'manifest_invalid');
  reject({ ...spec, dependencies: ['unlisted'] }, 'manifest_invalid');
});
test('unsafe Windows paths and directory copying are rejected before writes', t => {
  const { spec, root } = setup(t);
  for (const p of ['../x', '/x', 'C:/x', '//server/share', '\\\\?\\C:\\x', 'x:y', 'con.txt', 'x.', 'x ', 'a\\b', 'a~1', 'Gateway/server.ts', 'node_modules', '.env', 'config/secret.json']) {
    assert.throws(() => packageCandidate({ ...spec, files: [...spec.files, p] }));
  }
  assert.deepEqual(fs.readdirSync(root), ['inputs']);
});
test('secret config arbitrary code dynamic imports and development references are not copied', t => {
  const { spec, root } = setup(t);
  for (const body of ['{"token":"PRIVATE_SYNTHETIC_CANARY"}', 'import("C:/dev/x.js");', 'import("not-declared");']) {
    fs.writeFileSync(path.join(spec.sourceRoot, 'gateway/server.ts'), body);
    reject(spec, 'synthetic_content_invalid');
  }
  assert.deepEqual(fs.readdirSync(root), ['inputs']);
});
test('missing inputs fail without partial output', t => {
  const { spec, root } = setup(t);
  fs.unlinkSync(path.join(spec.sourceRoot, 'loader/tsx.mjs'));
  reject(spec, 'filesystem_unavailable');
  assert.deepEqual(fs.readdirSync(root), ['inputs']);
});
test('output must be existing approved temporary parent and never a source directory', t => {
  const { spec } = setup(t);
  reject({ ...spec, outputParent: spec.sourceRoot }, 'path_invalid');
  reject({ ...spec, outputParent: path.parse(spec.outputParent).root }, 'path_invalid');
  reject({ ...spec, outputParent: path.join(spec.outputParent, 'absent') }, 'filesystem_unavailable');
});
test('Windows case aliases cannot turn the source into the output directory', t => {
  const { spec } = setup(t);
  const alias = path.join(path.dirname(spec.sourceRoot), path.basename(spec.sourceRoot).toUpperCase());
  reject({ ...spec, outputParent: alias }, 'path_invalid');
});
test('source and output ancestor junctions are rejected without following them', t => {
  const { spec, root } = setup(t);
  const alias = path.join(root, 'alias');
  fs.symlinkSync(spec.sourceRoot, alias, 'junction');
  try {
    reject({ ...spec, sourceRoot: alias }, 'reparse_rejected');
    reject({ ...spec, outputParent: alias }, 'reparse_rejected');
  } finally { fs.unlinkSync(alias); }
});
test('native and module roles are explicitly declared with inert content and hashes', t => {
  const { spec } = setup(t);
  for (const [p, body] of [['native/test.node', 'R1_SYNTHETIC_NATIVE_NOT_LOADABLE\n'], ['modules/test.mjs', 'export const syntheticDependency = true;\n']]) {
    fs.mkdirSync(path.dirname(path.join(spec.sourceRoot, p)), { recursive: true });
    fs.writeFileSync(path.join(spec.sourceRoot, p), body);
    spec.files.push(p);
  }
  const result = packageCandidate(spec);
  const m = JSON.parse(fs.readFileSync(result.manifestPath));
  assert.equal(m.files.find(f => f.path === 'native/test.node').role, 'native');
  assert.equal(m.files.find(f => f.path === 'native/test.node').loadable, true);
  assert.equal(m.files.length, 6);
});
test('arbitrary launch commands and unknown argument fields are rejected', t => {
  const { spec } = setup(t);
  reject({ ...spec, command: 'powershell anything' }, 'manifest_invalid');
  reject({ ...spec, mode: 'other' }, 'manifest_invalid');
});
test('depth limit rejects paths before any input lookup', t => {
  const { spec } = setup(t);
  reject({ ...spec, files: [...spec.files, 'modules/a/b/c/d/e/f/g/h/x.mjs'] }, 'path_invalid');
});
test('declared directory count is bounded before any input lookup', t => {
  const { spec } = setup(t);
  const extras = Array.from({ length: 180 }, (_, i) => `modules/m${i}/a/b/x.mjs`);
  reject({ ...spec, files: [...spec.files, ...extras] }, 'resource_limit');
});
test('CLI packages only explicit synthetic inputs and rejects extra command arguments', t => {
  const { spec, root } = setup(t);
  const script = new URL('./package-protected-gateway.mjs', import.meta.url);
  const args = [script.pathname.replace(/^\/(\w:)/, '$1'), '--synthetic', '--source-root', spec.sourceRoot, '--output-parent', root, ...spec.files.flatMap(p => ['--file', p])];
  const result = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).productionEligible, false);
  const bad = spawnSync(process.execPath, [...args, '--command', 'do-not-run'], { encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.equal(bad.stderr.trim(), 'manifest_invalid');
});

test('Rust consumes Node manifest and rejects cross-language tampering', { skip: !process.env.R1_RUST_TEST_EXE }, t => {
  const { spec, root } = setup(t);
  const output = packageCandidate(spec);
  const invoke = (manifest, expected) => {
    const result = spawnSync(process.env.R1_RUST_TEST_EXE, ['--exact', 'cross_language_package', '--nocapture'], {
      encoding: 'utf8', env: { ...process.env, R1_CROSS_ROOT: output.payloadRoot, R1_CROSS_MANIFEST: manifest, R1_CROSS_EXPECT: expected },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /1 passed; 0 failed/);
  };
  invoke(output.manifestPath, 'ok');
  const changed = JSON.parse(fs.readFileSync(output.manifestPath));
  changed.production_eligible = true;
  const altered = path.join(root, 'altered.json');
  fs.writeFileSync(altered, JSON.stringify(changed)); invoke(altered, 'manifest_invalid');
  const duplicate = fs.readFileSync(output.manifestPath, 'utf8').replace('"format_version":1', '"format_version":1,"format_version":1');
  fs.writeFileSync(altered, duplicate); invoke(altered, 'manifest_invalid');
  fs.writeFileSync(path.join(output.payloadRoot, 'gateway/server.ts'), 'tampered');
  invoke(output.manifestPath, 'file_identity_mismatch');
});

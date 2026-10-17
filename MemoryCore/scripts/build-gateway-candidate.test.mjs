import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { buildGatewayCandidate, checkCandidateClosure } from './build-gateway-candidate.mjs';

const script = fileURLToPath(new URL('./build-gateway-candidate.mjs', import.meta.url));
const project = path.resolve(path.dirname(script), '..');
const scope = process.env.GATEWAY_CANDIDATE_TEMP_ROOT;
assert.ok(scope && path.isAbsolute(scope), 'explicit task temporary scope is required');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function put(root, name, text) {
  const file = path.join(root, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, { flag: 'wx' });
  return file;
}
function fixture(text = 'export const value: number = 7;\n', extras = {}) {
  const root = fs.mkdtempSync(path.join(scope, 'test-'));
  const sourceRoot = path.join(root, 'source');
  const outputParent = path.join(root, 'output');
  fs.mkdirSync(sourceRoot); fs.mkdirSync(outputParent);
  put(sourceRoot, 'src/gateway/server.ts', text);
  for (const [name, body] of Object.entries(extras)) put(sourceRoot, name, body);
  return { root, sourceRoot, outputParent };
}
const options = f => ({ sourceRoot: f.sourceRoot, outputParent: f.outputParent });
const rejects = (f, extra, code) => assert.rejects(() => buildGatewayCandidate({ ...options(f), ...extra }), e => e.message === code);
function readReport(result) {
  const bytes = fs.readFileSync(result.reportPath);
  assert.ok(bytes.length <= 4 * 1024 * 1024, 'every returned report must fit its closure reader');
  assert.equal(sha(bytes), result.reportSha256);
  return JSON.parse(bytes);
}

test('real Gateway source is transformed by the locked esbuild without executing Gateway', async () => {
  const outputParent = fs.mkdtempSync(path.join(scope, 'real-output-'));
  const result = await buildGatewayCandidate({ sourceRoot: project, outputParent });
  const report = readReport(result);
  assert.equal(report.sourceOrigin, 'PROJECT_TREE');
  assert.equal(report.entry, 'src/gateway/server.ts');
  assert.equal(report.CANDIDATE_BUILD_SUCCESS, true);
  assert.equal(report.buildExitCode, 0);
  assert.equal(report.buildTool.name, 'esbuild');
  assert.ok(report.buildTool.lockVersionMatched);
  assert.ok(report.modules.length > 100, 'the actual Gateway dependency graph must participate');
  for (const item of report.modules) {
    assert.equal(item.sourceSha256, sha(fs.readFileSync(path.join(project, item.source))));
    assert.equal(item.outputSha256, sha(fs.readFileSync(path.join(result.candidateDirectory, item.output))));
  }
  assert.equal(report.entryOutput, 'app/src/gateway/server.js');
  assert.equal(report.runtimeExecution, 'NOT_EXECUTED');
  assert.equal(report.cliStartup, 'NOT_PROVEN_BY_EXECUTION');
  assert.equal(report.RELEASE_DEPENDENCY_CLOSURE_COMPLETE, false);
  assert.equal(report.RELEASE_ELIGIBLE, false);
  assert.ok(report.missingPrivateModules.some(x => x.specifier.includes('integrations/factory')));
  assert.ok(report.nonliteralDynamicImports.some(x => x.source.endsWith('clean-context-runner.ts')));
  assert.ok(report.nativeDependencies.some(x => x.path.endsWith('vec0.dll')));
  assert.ok(report.resources.some(x => x.path.endsWith('bm25_zh_default.json')));
  assert.ok(report.configAndEnvironment.risks.includes('NAPI_RS_NATIVE_LIBRARY_PATH'));
  assert.ok(report.blockers.includes('external_dependency_closure_unverified'));
  assert.equal((await checkCandidateClosure(result.reportPath)).exitCode, 2);
});

test('transforms TypeScript and preserves local js import edges without running top-level code', async () => {
  const f = fixture('import { x } from "../dep.js"; throw new Error("DO_NOT_EXECUTE"); export const value: number = x;\n', {
    'src/dep.ts': 'export const x: number = 7;\n',
  });
  const result = await buildGatewayCandidate(options(f));
  const report = readReport(result);
  assert.equal(report.sourceOrigin, 'ISOLATED_FIXTURE');
  assert.equal(report.CANDIDATE_BUILD_SUCCESS, true);
  assert.deepEqual(report.modules.map(x => x.source).sort(), ['src/dep.ts', 'src/gateway/server.ts']);
  assert.ok(report.imports.some(x => x.specifier === '../dep.js' && x.resolvedSource === 'src/dep.ts'));
  assert.notEqual(fs.readFileSync(path.join(result.candidateDirectory, report.entryOutput), 'utf8'), fs.readFileSync(path.join(f.sourceRoot, report.entry), 'utf8'));
  assert.equal(report.runtimeExecution, 'NOT_EXECUTED');
});

for (const [name, extra] of [
  ['plugin entry', { entry: 'index.ts' }],
  ['absolute entry', { entry: 'C:/unapproved/server.ts' }],
  ['arbitrary external', { external: ['*'] }],
  ['command injection', { command: 'powershell' }],
  ['custom compiler', { compiler: 'unapproved.exe' }],
]) test(`rejects ${name} before writing`, async () => {
  const f = fixture();
  await rejects(f, extra, 'options_invalid');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});

test('rejects output in the source repository', async () => {
  const f = fixture();
  await rejects(f, { outputParent: project }, 'output_scope_invalid');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('rejects relative output and raw parent traversal before writing', async () => {
  const f = fixture();
  for (const outputParent of ['relative', `${f.outputParent}/../output`]) await rejects(f, { outputParent }, 'output_scope_invalid');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('rejects source and output overlap', async () => {
  const f = fixture();
  await rejects(f, { outputParent: f.sourceRoot }, 'output_scope_invalid');
});
test('invalid TypeScript produces a failed machine report and no claimed JS candidate', async () => {
  const result = await buildGatewayCandidate(options(fixture('export const value: number = ;\n')));
  const report = readReport(result);
  assert.equal(report.CANDIDATE_BUILD_SUCCESS, false);
  assert.equal(report.buildExitCode, 1);
  assert.equal(report.RELEASE_ELIGIBLE, false);
  assert.equal(report.modules.length, 0);
  assert.ok(report.diagnostics.some(x => x.code === 'compilation_failed'));
  assert.equal(fs.existsSync(path.join(result.candidateDirectory, 'app')), false);
});
test('failed compilation source identities remain bound to the machine diagnostics', async () => {
  const f = fixture('export const broken: number = ;\n');
  const result = await buildGatewayCandidate(options(f));
  const report = readReport(result);
  assert.ok(Array.isArray(report.sources));
  assert.equal(report.sources.find(x => x.source === 'src/gateway/server.ts').sourceSha256,
    sha(fs.readFileSync(path.join(f.sourceRoot, 'src/gateway/server.ts'))));
  assert.equal(report.CANDIDATE_BUILD_SUCCESS, false);
  assert.equal((await checkCandidateClosure(result.reportPath)).exitCode, 2);
});
test('excessive import edges are rejected before producing an oversized or partial report', async () => {
  const f = fixture('import "candidate-fixture-missing";\n'.repeat(10000));
  await assert.rejects(() => buildGatewayCandidate(options(f)), e => e.message === 'source_resource_limit');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('missing literal local and external modules remain closure blockers', async () => {
  const f = fixture('import "../integrations/factory.js"; import "not-installed-r1-fixture"; export const value = 7;\n');
  const report = readReport(await buildGatewayCandidate(options(f)));
  assert.equal(report.CANDIDATE_BUILD_SUCCESS, true);
  assert.ok(report.missingPrivateModules.some(x => x.specifier === '../integrations/factory.js'));
  assert.ok(report.externalDependencies.some(x => x.specifier === 'not-installed-r1-fixture' && x.status === 'MISSING'));
  assert.ok(report.blockers.includes('missing_local_modules'));
  assert.ok(report.blockers.includes('external_dependency_closure_unverified'));
  assert.equal(report.RELEASE_DEPENDENCY_CLOSURE_COMPLETE, false);
});
test('nonliteral import and require stay unresolved and are never executed', async () => {
  const f = fixture('import { createRequire } from "node:module"; const require = createRequire(import.meta.url); const name = "DO_NOT_LOAD"; import(name); require(name);\n');
  const report = readReport(await buildGatewayCandidate(options(f)));
  assert.equal(report.nonliteralDynamicImports.length, 2);
  assert.ok(report.blockers.includes('nonliteral_dynamic_loading'));
  assert.equal(report.RELEASE_ELIGIBLE, false);
});
test('node-prefix-only sqlite is a builtin and is not reported as a missing npm dependency', async () => {
  const f = fixture('import { createRequire } from "node:module"; const require = createRequire(import.meta.url); require("node:sqlite");\n');
  const report = readReport(await buildGatewayCandidate(options(f)));
  assert.ok(report.imports.some(x => x.specifier === 'node:sqlite' && x.status === 'NODE_BUILTIN'));
  assert.equal(report.externalDependencies.some(x => x.specifier === 'node:sqlite'), false);
});
test('unresolved native packages and resource identities prevent release qualification', async () => {
  const f = fixture('import "sqlite-vec"; import "@node-rs/jieba"; import "@tencentdb-agent-memory/tcvdb-text";\n');
  const report = readReport(await buildGatewayCandidate(options(f)));
  assert.ok(report.nativeDependencies.some(x => x.status === 'MISSING'));
  assert.ok(report.resources.some(x => x.status === 'MISSING'));
  assert.ok(report.blockers.includes('native_loading_unverified'));
  assert.ok(report.blockers.includes('resource_packaging_unverified'));
  assert.equal(report.RELEASE_ELIGIBLE, false);
});
test('resolves external package identity without importing its executable body', async () => {
  const f = fixture('import "candidate-fixture-package";\n', {
    'node_modules/candidate-fixture-package/package.json': '{"name":"candidate-fixture-package","version":"1.0.0","type":"module","exports":{"import":"./entry.js"}}',
    'node_modules/candidate-fixture-package/entry.js': 'throw new Error("DO_NOT_IMPORT_EXTERNAL");\n',
  });
  const report = readReport(await buildGatewayCandidate(options(f)));
  const dependency = report.externalDependencies.find(x => x.specifier === 'candidate-fixture-package');
  assert.equal(dependency.status, 'RESOLVED_METADATA_ONLY');
  assert.equal(dependency.version, '1.0.0');
  assert.equal(dependency.transitiveClosure, 'NOT_VERIFIED');
});
test('never follows a local import outside the src boundary', async () => {
  const f = fixture('import "../../private.js";\n', { 'private.ts': 'throw new Error("PRIVATE");\n' });
  await assert.rejects(() => buildGatewayCandidate(options(f)), e => e.message === 'source_path_invalid');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('ambiguous js and ts candidates are recorded rather than silently selected', async () => {
  const f = fixture('import "../dep.js";\n', { 'src/dep.ts': 'export const x = 1;', 'src/dep.js': 'export const x = 2;' });
  const report = readReport(await buildGatewayCandidate(options(f)));
  assert.ok(report.imports.some(x => x.status === 'AMBIGUOUS'));
  assert.ok(report.blockers.includes('ambiguous_local_modules'));
});
test('explicit ts and tsx imports with the same emitted js path fail before writing app', async () => {
  const f = fixture('import "../same.ts"; import "../same.tsx";\n', {
    'src/same.ts': 'export const value: number = 1;\n',
    'src/same.tsx': 'export const value: number = 2;\n',
  });
  const result = await buildGatewayCandidate(options(f));
  const report = readReport(result);
  assert.equal(report.CANDIDATE_BUILD_SUCCESS, false);
  assert.equal(report.buildExitCode, 1);
  assert.ok(report.diagnostics.some(x => x.code === 'output_collision'));
  assert.equal(report.modules.length, 0);
  assert.equal(fs.existsSync(path.join(result.candidateDirectory, 'app')), false);
});
test('does not claim mjs startup or runtime isolation from a successful compile', async () => {
  const report = readReport(await buildGatewayCandidate(options(fixture())));
  assert.equal(report.entryOutput, 'app/src/gateway/server.js');
  assert.equal(report.cliStartup, 'NOT_PROVEN_BY_EXECUTION');
  assert.equal(report.configAndEnvironment.runtimeIsolation, 'NOT_PROVEN');
  assert.equal(report.RELEASE_ELIGIBLE, false);
});

for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'NAPI_RS_NATIVE_LIBRARY_PATH', 'ESBUILD_BINARY_PATH', 'NODE_COMPILE_CACHE', 'NODE_V8_COVERAGE']) {
  test(`rejects ${name} in a child before compiler use`, () => {
    const f = fixture();
    const env = { ...process.env, [name]: name === 'NODE_OPTIONS' ? '--no-warnings' : f.root };
    const result = spawnSync(process.execPath, [script, '--source-root', f.sourceRoot, '--output-parent', f.outputParent], { env, encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).error, 'build_environment_rejected');
    assert.deepEqual(fs.readdirSync(f.outputParent), []);
  });
}
test('a real partial-output filesystem error never returns a successful candidate or report', () => {
  const f = fixture();
  // Isolated filesystem fixture: create a regular file where the writer needs its app directory.
  // The actual compiler and all builder logic remain real; nothing executes candidate JS.
  const code = `import fs from 'node:fs'; import path from 'node:path';
    import { buildGatewayCandidate } from ${JSON.stringify(new URL('./build-gateway-candidate.mjs', import.meta.url).href)};
    const make = fs.mkdtempSync;
    fs.mkdtempSync = (...args) => { const p = make(...args); fs.writeFileSync(path.join(p, 'app'), 'isolated-output-conflict'); return p; };
    try { await buildGatewayCandidate(${JSON.stringify(options(f))}); console.log(JSON.stringify({ returnedSuccess: true })); }
    catch (e) { console.log(JSON.stringify({ returnedSuccess: false, code: e.code })); }`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const outcome = JSON.parse(result.stdout);
  assert.equal(outcome.returnedSuccess, false);
  assert.ok(['ENOTDIR', 'EEXIST'].includes(outcome.code));
  assert.equal(fs.readdirSync(f.outputParent).length, 1);
  assert.equal(fs.existsSync(path.join(f.outputParent, fs.readdirSync(f.outputParent)[0], 'closure-report.json')), false);
});
test('CLI distinguishes successful compilation from a blocked closure gate', () => {
  const f = fixture();
  const built = spawnSync(process.execPath, [script, '--source-root', f.sourceRoot, '--output-parent', f.outputParent], { encoding: 'utf8' });
  assert.equal(built.status, 0, built.stderr + built.stdout);
  const result = JSON.parse(built.stdout);
  const checked = spawnSync(process.execPath, [script, '--check-closure', result.reportPath], { encoding: 'utf8' });
  assert.equal(checked.status, 2, checked.stderr + checked.stdout);
  assert.equal(JSON.parse(checked.stdout).RELEASE_ELIGIBLE, false);
});
test('forged report success flags cannot authorize release', async () => {
  const f = fixture();
  const report = put(f.root, 'forged.json', JSON.stringify({ CANDIDATE_BUILD_SUCCESS: true, RELEASE_ELIGIBLE: true, RELEASE_DEPENDENCY_CLOSURE_COMPLETE: true }));
  const decision = await checkCandidateClosure(report);
  assert.equal(decision.exitCode, 2);
  assert.equal(decision.RELEASE_ELIGIBLE, false);
});
test('closure checker does not echo arbitrary objects or long sensitive strings from untrusted JSON', async () => {
  const f = fixture();
  const report = put(f.root, 'polluted.json', JSON.stringify({ format: 'gateway-js-candidate-closure/v1',
    blockers: [{ token: 'PRIVATE_SYNTHETIC_REPORT_CANARY' }, 'PRIVATE_SYNTHETIC_REPORT_CANARY'.repeat(100)] }));
  const decision = await checkCandidateClosure(report);
  assert.equal(decision.exitCode, 2);
  assert.equal(JSON.stringify(decision).includes('PRIVATE_SYNTHETIC_REPORT_CANARY'), false);
  assert.deepEqual(decision.blockers, ['invalid_or_untrusted_report']);
});
test('compiler JS entry identities are recorded without claiming trusted toolchain integrity', async () => {
  const report = readReport(await buildGatewayCandidate(options(fixture())));
  assert.ok(Array.isArray(report.buildTool.jsEntrypoints));
  for (const name of ['node_modules/esbuild/lib/main.js', 'node_modules/typescript/lib/typescript.js']) {
    assert.equal(report.buildTool.jsEntrypoints.find(x => x.path === name).sha256,
      sha(fs.readFileSync(path.join(project, name))));
  }
  assert.ok(report.analysisLimits.includes('tool_version_match_is_not_trusted_toolchain_integrity'));
});
test('different subpaths of one external package read its metadata only once', () => {
  const f = fixture(Array.from({ length: 8 }, (_, i) => `import "candidate-meta-package/p${i}";`).join('\n'), {
    'node_modules/candidate-meta-package/package.json': JSON.stringify({ name: 'candidate-meta-package', version: '1.0.0',
      description: 'nonsecret fixture padding'.repeat(4000), exports: { '.': './entry.js' } }),
    'node_modules/candidate-meta-package/entry.js': 'throw new Error("DO_NOT_IMPORT");',
  });
  const metadata = path.join(f.sourceRoot, 'node_modules/candidate-meta-package/package.json');
  const code = `import fs from 'node:fs'; import path from 'node:path';
    import { buildGatewayCandidate } from ${JSON.stringify(new URL('./build-gateway-candidate.mjs', import.meta.url).href)};
    const read = fs.readFileSync; let reads = 0;
    fs.readFileSync = (p, ...rest) => { if (typeof p === 'string' && path.resolve(p) === ${JSON.stringify(metadata)}) reads++; return read(p, ...rest); };
    const result = await buildGatewayCandidate(${JSON.stringify(options(f))});
    console.log(JSON.stringify({ reads, success: result.CANDIDATE_BUILD_SUCCESS }));`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { reads: 1, success: true });
});

// These fixed fixtures mirror the selected Windows package layout, not native execution.
const assetProfile = {
  'sqlite-vec': ['0.1.7-alpha.2', ['index.cjs', 'index.mjs']],
  'sqlite-vec-windows-x64': ['0.1.7-alpha.2', ['vec0.dll']],
  '@node-rs/jieba': ['2.0.2', ['index.js', 'dict.js', 'dict.txt', 'idf.txt', 'LICENSE']],
  '@node-rs/jieba-win32-x64-msvc': ['2.0.2', ['jieba.win32-x64-msvc.node']],
  '@tencentdb-agent-memory/tcvdb-text': ['0.1.1', ['dist/index.js', 'dist/types.js', 'dist/hash.js', 'dist/paths.js',
    'dist/encoder/bm25.js', 'dist/encoder/base-encoder.js', 'dist/tokenizer/jieba-tokenizer.js',
    'dist/tokenizer/base-tokenizer.js', 'data/stopwords.txt', 'LICENSE']],
  murmurhash: ['2.0.1', ['murmurhash.js']],
};
function assetFixture() {
  const f = fixture('import "sqlite-vec"; import "../integrations/factory.js"; const name = "DO_NOT_LOAD"; import(name);\n');
  const packages = {};
  for (const [name, [version, files]] of Object.entries(assetProfile)) {
    const pkg = { name, version, main: files[0] };
    if (name === 'sqlite-vec') pkg.exports = { '.': { require: './index.cjs', import: './index.mjs' } };
    if (name === '@tencentdb-agent-memory/tcvdb-text') pkg.dependencies = { '@node-rs/jieba': '^2.0.1', murmurhash: '^2.0.1' };
    if (name === '@node-rs/jieba') pkg.optionalDependencies = { '@node-rs/jieba-win32-x64-msvc': version };
    packages[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/fixture.tgz`, integrity: 'sha512-SYNTHETIC' };
    put(f.sourceRoot, `node_modules/${name}/package.json`, JSON.stringify(pkg));
    for (const file of files) put(f.sourceRoot, `node_modules/${name}/${file}`,
      /\.(?:js|cjs|mjs)$/.test(file) ? 'throw new Error("NEVER_EXECUTE_PACKAGE");\n' : `nonsecret fixture ${file}\n`);
  }
  put(f.sourceRoot, 'package-lock.json', JSON.stringify({ lockfileVersion: 3, packages }));
  return f;
}
const withAssets = f => buildGatewayCandidate({ ...options(f), stageAssets: true });

test('asset staging copies real installed locked packages without loading them', async () => {
  const result = await buildGatewayCandidate({ sourceRoot: project,
    outputParent: fs.mkdtempSync(path.join(scope, 'real-assets-')), stageAssets: true });
  const report = readReport(result), staged = report.assetStaging;
  assert.equal(staged.PACKAGE_FILES_STAGED, true);
  assert.equal(staged.PACKAGE_FILE_IDENTITIES_VERIFIED, true);
  assert.equal(staged.packages.length, 6);
  for (const file of staged.files) {
    assert.equal(file.sourceSha256, sha(fs.readFileSync(path.join(project, file.source))));
    assert.equal(file.outputSha256, sha(fs.readFileSync(path.join(result.candidateDirectory, file.output))));
    assert.equal(file.sourceSha256, file.outputSha256);
  }
  assert.ok(staged.files.some(x => x.output.endsWith('sqlite-vec-windows-x64/vec0.dll')));
  assert.ok(staged.files.some(x => x.output.endsWith('@node-rs/jieba-win32-x64-msvc/jieba.win32-x64-msvc.node')));
  assert.equal(staged.PACKAGE_TRANSITIVE_CLOSURE_PROVEN, false);
  assert.equal(staged.NATIVE_LOAD_VERIFIED, false);
  assert.equal(staged.RESOURCE_LAYOUT_VERIFIED, false);
  const resolveCode = `import { createRequire } from 'node:module'; import { pathToFileURL } from 'node:url';
    const base = pathToFileURL(${JSON.stringify(path.join(result.candidateDirectory, 'app/package.json'))}).href;
    const require = createRequire(base);
    console.log(JSON.stringify({ sqliteRequire:require.resolve('sqlite-vec'), sqliteImport:import.meta.resolve('sqlite-vec',base),
      jieba:require.resolve('@node-rs/jieba'), dict:require.resolve('@node-rs/jieba/dict.js'),
      native:require.resolve('@node-rs/jieba-win32-x64-msvc'), text:import.meta.resolve('@tencentdb-agent-memory/tcvdb-text',base),
      hash:require.resolve('murmurhash') }));`;
  const resolved = spawnSync(process.execPath, ['--experimental-import-meta-resolve', '--input-type=module', '-e', resolveCode], { encoding:'utf8' });
  assert.equal(resolved.status, 0, resolved.stderr);
  const entries = JSON.parse(resolved.stdout);
  assert.ok(entries.sqliteRequire.endsWith('index.cjs'));
  assert.ok(entries.sqliteImport.endsWith('index.mjs'));
  assert.ok(entries.text.endsWith('/dist/index.js'));
  for (const value of Object.values(entries)) assert.ok(value.replaceAll('\\', '/').includes('/app/node_modules/'));
  assert.equal(report.RELEASE_ELIGIBLE, false);
  assert.equal((await checkCandidateClosure(result.reportPath)).exitCode, 2);
});
test('selected package directories and resource-relative paths survive the copy', async () => {
  const f = assetFixture(), result = await withAssets(f), staged = readReport(result).assetStaging;
  for (const [name, [, files]] of Object.entries(assetProfile)) for (const file of ['package.json', ...files]) {
    assert.deepEqual(fs.readFileSync(path.join(result.candidateDirectory, 'app/node_modules', name, file)),
      fs.readFileSync(path.join(f.sourceRoot, 'node_modules', name, file)));
  }
  assert.equal(staged.PACKAGE_METADATA_RESOLVED, true);
  assert.equal(staged.selectedResourceLayoutVerified, true);
  assert.ok(staged.unresolvedResources.some(x => x.path.endsWith('bm25_zh_default.json')));
  assert.ok(staged.unresolvedResources.some(x => x.path.endsWith('bm25_en_default.json')));
  assert.equal(fs.existsSync(path.join(result.candidateDirectory, 'app/node_modules/@tencentdb-agent-memory/tcvdb-text/data/bm25_en_default.json')), false);
  assert.ok(staged.packages.find(x => x.name === '@tencentdb-agent-memory/tcvdb-text').dependencyEdges.some(x => x.name === 'murmurhash'));
  assert.ok(readReport(result).missingPrivateModules.length);
  assert.ok(readReport(result).nonliteralDynamicImports.length);
});
for (const file of ['sqlite-vec-windows-x64/vec0.dll', '@node-rs/jieba-win32-x64-msvc/jieba.win32-x64-msvc.node',
  '@node-rs/jieba/idf.txt', '@tencentdb-agent-memory/tcvdb-text/data/stopwords.txt', 'murmurhash/murmurhash.js']) {
  test(`asset staging rejects missing required ${file}`, async () => {
    const f = assetFixture(); fs.unlinkSync(path.join(f.sourceRoot, 'node_modules', file));
    await assert.rejects(() => withAssets(f), e => e.message === 'asset_required_file_missing');
    assert.deepEqual(fs.readdirSync(f.outputParent), []);
  });
}
test('asset staging rejects installed metadata that differs from the locked version', async () => {
  const f = assetFixture(), file = path.join(f.sourceRoot, 'node_modules/sqlite-vec/package.json');
  const pkg = JSON.parse(fs.readFileSync(file)); pkg.version = '9.0.0'; fs.writeFileSync(file, JSON.stringify(pkg));
  await assert.rejects(() => withAssets(f), e => e.message === 'asset_lock_mismatch');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('asset selection is closed and rejects caller-supplied file escape or package expansion', async () => {
  const f = assetFixture();
  for (const extra of [{ assetFiles: ['../../secret'] }, { packages: ['unknown-package'] }, { stageAssets: 'true' }]) {
    await assert.rejects(() => buildGatewayCandidate({ ...options(f), stageAssets: true, ...extra }), e => e.message === 'options_invalid');
  }
});
for (const type of ['junction', 'file']) test(`asset staging rejects ${type} links before copying`, async t => {
  const f = assetFixture(), outside = path.join(f.root, 'outside'); fs.mkdirSync(outside);
  if (type === 'junction') {
    const packageRoot = path.join(f.sourceRoot, 'node_modules/sqlite-vec');
    fs.renameSync(packageRoot, path.join(outside, 'pkg')); fs.symlinkSync(path.join(outside, 'pkg'), packageRoot, 'junction');
  } else {
    // File symlink creation may require developer mode; preserve a genuine platform limitation.
    const original = path.join(f.sourceRoot, 'node_modules/@node-rs/jieba/dict.txt');
    fs.renameSync(original, path.join(outside, 'dict.txt'));
    try { fs.symlinkSync(path.join(outside, 'dict.txt'), original, 'file'); }
    catch (e) { if (e.code !== 'EPERM') throw e; t.skip('host does not permit unprivileged file symlink creation'); return; }
  }
  await assert.rejects(() => withAssets(f), e => e.message === 'reparse_rejected');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('asset staging creates fresh outputs and never overwrites an earlier candidate', async () => {
  const f = assetFixture(), first = await withAssets(f), before = fs.readFileSync(first.reportPath);
  const second = await withAssets(f);
  assert.notEqual(first.candidateDirectory, second.candidateDirectory);
  assert.deepEqual(fs.readFileSync(first.reportPath), before);
});
function assetChild(f, setup) {
  const code = `import fs from 'node:fs'; import path from 'node:path';
    import { buildGatewayCandidate } from ${JSON.stringify(new URL('./build-gateway-candidate.mjs', import.meta.url).href)};
    ${setup}
    try { const result = await buildGatewayCandidate(${JSON.stringify({ ...options(f), stageAssets: true })}); console.log(JSON.stringify({ success: true, result })); }
    catch (e) { console.log(JSON.stringify({ success: false, code: e.code, message: e.message })); }`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); return JSON.parse(r.stdout);
}
test('asset staging detects Windows casefold collisions in a selected directory inventory', () => {
  const f = assetFixture(), original = path.join(f.sourceRoot, 'node_modules/@node-rs/jieba');
  const outcome = assetChild(f, `const read = fs.readdirSync;
    fs.readdirSync = (p, ...rest) => { const entries = read(p, ...rest); if (typeof p === 'string' && path.resolve(p) === ${JSON.stringify(original)}) {
      if (typeof entries[0] === 'string') return [...entries, 'DICT.TXT'];
      const d = entries.find(x => x.name === 'dict.txt'); return [...entries, { name:'DICT.TXT', isDirectory:()=>false, isFile:()=>true, isSymbolicLink:()=>false }];
    } return entries; };`);
  assert.equal(outcome.success, false); assert.equal(outcome.message, 'asset_path_collision');
});
test('changed source bytes and corrupted copied bytes never produce a successful report', () => {
  for (const corrupt of ['source', 'destination']) {
    const f = assetFixture();
    const outcome = assetChild(f, `const copy = fs.copyFileSync; let changed = false;
      fs.copyFileSync = (source, target, ...rest) => { const r = copy(source, target, ...rest); if (!changed) { changed = true;
        fs.appendFileSync(${JSON.stringify(corrupt)} === 'source' ? source : target, 'CHANGED'); } return r; };`);
    assert.equal(outcome.success, false); assert.equal(outcome.message, 'asset_identity_mismatch');
    for (const d of fs.readdirSync(f.outputParent)) assert.equal(fs.existsSync(path.join(f.outputParent, d, 'closure-report.json')), false);
  }
});
test('partial asset copy failure never writes a success report', () => {
  const f = assetFixture();
  const outcome = assetChild(f, `const copy = fs.copyFileSync; let calls=0;
    fs.copyFileSync = (...args) => { if (++calls === 3) throw Object.assign(new Error('isolated copy failure'), {code:'EIO'}); return copy(...args); };`);
  assert.equal(outcome.success, false); assert.equal(outcome.code, 'EIO');
  for (const d of fs.readdirSync(f.outputParent)) assert.equal(fs.existsSync(path.join(f.outputParent, d, 'closure-report.json')), false);
});
test('asset metadata parsed for selection must be the same bytes snapshotted for copying', () => {
  const f = assetFixture(), metadata = path.join(f.sourceRoot, 'node_modules/sqlite-vec/package.json');
  const outcome = assetChild(f, `const read = fs.readFileSync; let changed = false;
    fs.readFileSync = (p,...args) => { const bytes = read(p,...args); if (!changed && p === ${JSON.stringify(metadata)}) {
      changed = true; const pkg=JSON.parse(bytes);pkg.version='9.0.0';fs.writeFileSync(p,JSON.stringify(pkg)); } return bytes; };`);
  assert.equal(outcome.success, false);
  assert.equal(outcome.message, 'asset_identity_mismatch');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('asset inventory rejects a symlink even when the host cannot create file symlinks', () => {
  const f = assetFixture(), original = path.join(f.sourceRoot, 'node_modules/@node-rs/jieba');
  const outcome = assetChild(f, `const read=fs.readdirSync;
    fs.readdirSync = (p,...rest) => { const list=read(p,...rest); if(p===${JSON.stringify(original)} && rest[0]?.withFileTypes)
      return list.map(x=>x.name==='dict.txt'?{name:x.name,isSymbolicLink:()=>true}:x); return list; };`);
  assert.equal(outcome.success, false); assert.equal(outcome.message, 'reparse_rejected');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
test('output-side Windows reparse attributes reject before the first candidate write', () => {
  const f = assetFixture();
  const outcome = assetChild(f, `const child = await import('node:child_process'); const builtin=await import('node:module');
    const original=child.default.spawnSync;
    child.default.spawnSync=(exe,args,opts)=>{ if(typeof opts?.input==='string' && opts.input.includes(${JSON.stringify(f.outputParent).replaceAll('\\\\','\\\\\\\\')}))
      return {status:2,stdout:'REPARSE',stderr:''}; return original(exe,args,opts); }; builtin.syncBuiltinESMExports();`);
  assert.equal(outcome.success, false); assert.equal(outcome.message, 'reparse_rejected');
  assert.deepEqual(fs.readdirSync(f.outputParent), []);
});
for (const [field, values] of [['os', ['win32', '!win32']], ['cpu', ['x64', '!x64']]]) {
  test(`asset metadata with contradictory ${field} support fails before copying`, async () => {
    const f=assetFixture(), file=path.join(f.sourceRoot,'node_modules/@node-rs/jieba-win32-x64-msvc/package.json');
    const pkg=JSON.parse(fs.readFileSync(file));pkg[field]=values;fs.writeFileSync(file,JSON.stringify(pkg));
    await assert.rejects(()=>withAssets(f), e=>e.message==='asset_platform_unsupported');
    assert.deepEqual(fs.readdirSync(f.outputParent), []);
  });
}

function jsPackage(f, name, version, pkg = {}, files = {}, prefix = 'node_modules') {
  const relative = `${prefix}/${name}`;
  put(f.sourceRoot, `${relative}/package.json`, JSON.stringify({ name, version, main: 'index.js', ...pkg }));
  for (const [file, text] of Object.entries(files)) put(f.sourceRoot, `${relative}/${file}`, text);
  const lockFile = path.join(f.sourceRoot, 'package-lock.json'), lock = JSON.parse(fs.readFileSync(lockFile));
  lock.packages[relative] = { version, resolved: `https://registry.npmjs.org/${name}/-/fixture.tgz`, integrity:'sha512-SYNTHETIC' };
  fs.writeFileSync(lockFile, JSON.stringify(lock));
}
function jsFixture() {
  const f = assetFixture();
  fs.writeFileSync(path.join(f.sourceRoot,'src/gateway/server.ts'), 'import "fixture-dual"; import "fixture-dual/feature/a"; const require=(x)=>x;require("fixture-dual");\n');
  jsPackage(f, 'fixture-dual','1.0.0', { type:'module', exports:{'.':{import:'./esm.js',require:'./cjs.cjs'},'./feature/*':'./features/*.js'},
    imports:{'#inside':'./inside.js'}, dependencies:{'fixture-leaf':'1.0.0'} }, {
    'esm.js':'import "#inside"; import "fixture-leaf"; throw new Error("NEVER_EXECUTE_ESM");',
    'inside.js':'export const inside=1;', 'cjs.cjs':'require("fixture-leaf");throw new Error("NEVER_EXECUTE_CJS");',
    'features/a.js':'export const feature=1;', 'private.env':'PRIVATE_SYNTHETIC_NOT_TO_COPY',
  });
  jsPackage(f,'fixture-leaf','1.0.0',{}, {'index.js':'throw new Error("NEVER_EXECUTE_LEAF");'});
  return f;
}
const withJs = f => buildGatewayCandidate({ ...options(f), stageAssets:true, stageJsDependencies:true });
function readJsGraph(result) {
  const report = readReport(result), summary = report.jsDependencyStaging;
  const bytes=fs.readFileSync(path.join(result.candidateDirectory,summary.graphPath));
  assert.equal(sha(bytes),summary.graphSha256); return {report,summary,graph:JSON.parse(bytes)};
}
test('JS closure stages ESM CJS exports patterns and package imports using real Node resolution', async () => {
  const f=jsFixture(), result=await withJs(f), {summary,graph}=readJsGraph(result);
  assert.ok(graph.files.some(x=>x.source.endsWith('/fixture-dual/esm.js')));
  assert.ok(graph.files.some(x=>x.source.endsWith('/fixture-dual/cjs.cjs')));
  assert.ok(graph.edges.some(x=>x.specifier==='#inside' && x.NODE_ENTRY_RESOLUTION_VERIFIED));
  assert.ok(graph.edges.some(x=>x.specifier==='fixture-dual/feature/a' && x.NODE_ENTRY_RESOLUTION_VERIFIED));
  assert.equal(summary.DEVELOPMENT_PATH_ESCAPE,false);
  assert.equal(summary.TRANSITIVE_CLOSURE_PROVEN,false);
  assert.equal(fs.existsSync(path.join(result.candidateDirectory,'app/node_modules/fixture-dual/private.env')),false);
  assert.equal((await checkCandidateClosure(result.reportPath)).exitCode,2);
});
test('JS closure verifies copied transitive file hashes and does not inherit development targets', async () => {
  const f=jsFixture(), result=await withJs(f), {graph}=readJsGraph(result);
  assert.ok(graph.edges.some(x=>x.specifier==='fixture-leaf' && x.status==='RESOLVED' && x.NODE_ENTRY_RESOLUTION_VERIFIED));
  for(const file of graph.files){assert.equal(file.sourceSha256,sha(fs.readFileSync(path.join(f.sourceRoot,file.source))));
    assert.equal(file.outputSha256,sha(fs.readFileSync(path.join(result.candidateDirectory,file.output))));}
  for(const edge of graph.edges.filter(x=>x.status==='RESOLVED')) {
    assert.equal(edge.NODE_ENTRY_RESOLUTION_VERIFIED,true); assert.ok(edge.candidateTarget.startsWith('app/node_modules/'));
  }
});
test('JS closure preserves nested different versions instead of flattening packages', async () => {
  const f=assetFixture();fs.writeFileSync(path.join(f.sourceRoot,'src/gateway/server.ts'),'import "fixture-left";import "fixture-right";');
  for(const [parent,v] of [['fixture-left','1.0.0'],['fixture-right','2.0.0']]) {
    jsPackage(f,parent,'1.0.0',{dependencies:{'fixture-shared':v}},{'index.js':'require("fixture-shared");'});
    jsPackage(f,'fixture-shared',v,{}, {'index.js':`exports.version=${JSON.stringify(v)};`},`node_modules/${parent}/node_modules`);
  }
  const result=await withJs(f), {graph}=readJsGraph(result);
  assert.deepEqual(graph.packages.filter(x=>x.name==='fixture-shared').map(x=>x.version).sort(),['1.0.0','2.0.0']);
  for(const parent of ['fixture-left','fixture-right']) assert.ok(fs.existsSync(path.join(result.candidateDirectory,`app/node_modules/${parent}/node_modules/fixture-shared/index.js`)));
  assert.ok(graph.edges.filter(x=>x.specifier==='fixture-shared').every(x=>x.NODE_ENTRY_RESOLUTION_VERIFIED));
});
test('JS closure keeps missing declared and runtime transitive dependencies unresolved', async () => {
  const f=jsFixture(), file=path.join(f.sourceRoot,'node_modules/fixture-leaf/index.js');fs.writeFileSync(file,'require("fixture-transitive-missing");');
  const result=await withJs(f), {report,summary,graph}=readJsGraph(result);
  assert.ok(graph.edges.some(x=>x.specifier==='fixture-transitive-missing' && x.status==='UNRESOLVED'));
  assert.ok(summary.unresolvedEdges>0);assert.equal(summary.TRANSITIVE_CLOSURE_PROVEN,false);
  assert.equal(report.RELEASE_ELIGIBLE,false);assert.equal((await checkCandidateClosure(result.reportPath)).exitCode,2);
});
test('JS closure preserves all previously selected native and resource bytes', async () => {
  const f=jsFixture(), result=await withJs(f), {report}=readJsGraph(result);
  for(const file of report.assetStaging.files) assert.equal(sha(fs.readFileSync(path.join(result.candidateDirectory,file.output))),file.sourceSha256);
  assert.equal(report.assetStaging.NATIVE_LOAD_VERIFIED,false);
  assert.equal(report.assetStaging.unresolvedResources.length,2);
});
test('JS closure rejects relative package path escape before output creation', async () => {
  const f=jsFixture();fs.writeFileSync(path.join(f.sourceRoot,'node_modules/fixture-leaf/index.js'),'require("../../secret.js");');
  put(f.sourceRoot,'secret.js','throw new Error("NOT_A_PACKAGE");');
  await assert.rejects(()=>withJs(f), e=>e.message==='js_path_escape');assert.deepEqual(fs.readdirSync(f.outputParent),[]);
});
test('JS closure rejects external package Junctions', async () => {
  const f=jsFixture(), original=path.join(f.sourceRoot,'node_modules/fixture-leaf'), outside=path.join(f.root,'outside-leaf');
  fs.renameSync(original,outside);fs.symlinkSync(outside,original,'junction');
  await assert.rejects(()=>withJs(f), e=>e.message==='reparse_rejected');assert.deepEqual(fs.readdirSync(f.outputParent),[]);
});
test('JS closure rejects a nested package whose installed version disagrees with its exact lock path', async () => {
  const f=jsFixture(), p=path.join(f.sourceRoot,'node_modules/fixture-leaf/package.json');
  const pkg=JSON.parse(fs.readFileSync(p));pkg.version='9.0.0';fs.writeFileSync(p,JSON.stringify(pkg));
  await assert.rejects(()=>withJs(f), e=>e.message==='js_lock_mismatch');assert.deepEqual(fs.readdirSync(f.outputParent),[]);
});
test('JS closure retains nonliteral loading without executing it or copying arbitrary files', async () => {
  const f=jsFixture();fs.writeFileSync(path.join(f.sourceRoot,'node_modules/fixture-leaf/index.js'),'const unknown="DO_NOT_EXECUTE";require(unknown);');
  const {graph,summary}=readJsGraph(await withJs(f));
  assert.ok(graph.edges.some(x=>x.reason==='NONLITERAL_LOADING' && x.status==='UNRESOLVED'));
  assert.equal(summary.TRANSITIVE_CLOSURE_PROVEN,false);
});
function jsChild(f, setup) {
  const code=`import fs from 'node:fs';import path from 'node:path';import {buildGatewayCandidate} from ${JSON.stringify(new URL('./build-gateway-candidate.mjs',import.meta.url).href)};
    ${setup}
    try{const result=await buildGatewayCandidate(${JSON.stringify({...options(f),stageAssets:true,stageJsDependencies:true})});console.log(JSON.stringify({success:true,result}));}
    catch(e){console.log(JSON.stringify({success:false,code:e.code,message:e.message}));}`;
  const r=spawnSync(process.execPath,['--input-type=module','-e',code],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);
}
test('JS closure detects source changes and destination tampering during copy', () => {
  for(const kind of ['source','destination']) {
    const f=jsFixture();const outcome=jsChild(f,`const copy=fs.copyFileSync;let changed=false;fs.copyFileSync=(src,dst,...args)=>{const r=copy(src,dst,...args);
      if(!changed && src.includes('fixture-leaf') && src.endsWith('index.js')){changed=true;fs.appendFileSync(${JSON.stringify(kind)}==='source'?src:dst,'CHANGED');}return r;};`);
    assert.equal(outcome.success,false);assert.equal(outcome.message,'asset_identity_mismatch');
    for(const d of fs.readdirSync(f.outputParent))assert.equal(fs.existsSync(path.join(f.outputParent,d,'closure-report.json')),false);
  }
});
test('JS closure partial copy failure never emits a successful closure report', () => {
  const f=jsFixture();const outcome=jsChild(f,`const copy=fs.copyFileSync;fs.copyFileSync=(src,...args)=>{if(src.includes('fixture-leaf'))throw Object.assign(new Error('isolated'),{code:'EIO'});return copy(src,...args);};`);
  assert.equal(outcome.success,false);assert.equal(outcome.code,'EIO');
  for(const d of fs.readdirSync(f.outputParent))assert.equal(fs.existsSync(path.join(f.outputParent,d,'closure-report.json')),false);
});
test('JS closure rejects Windows case aliases in a dependency directory', () => {
  const f=jsFixture(), dir=path.join(f.sourceRoot,'node_modules/fixture-leaf');
  const outcome=jsChild(f,`const read=fs.readdirSync;fs.readdirSync=(p,...args)=>{const list=read(p,...args);if(p===${JSON.stringify(dir)} && typeof list[0]==='string')return [...list,'INDEX.JS'];return list;};`);
  assert.equal(outcome.success,false);assert.equal(outcome.message,'asset_path_collision');
});
test('JS closure rejects lockfile changes after native staging and during JS copying', () => {
  const f=jsFixture(), lockFile=path.join(f.sourceRoot,'package-lock.json');
  const outcome=jsChild(f,`const copy=fs.copyFileSync;let changed=false;fs.copyFileSync=(src,...rest)=>{const result=copy(src,...rest);
    if(!changed && src.includes('fixture-leaf')){changed=true;fs.appendFileSync(${JSON.stringify(lockFile)},' ');}return result;};`);
  assert.equal(outcome.success,false);assert.equal(outcome.message,'asset_identity_mismatch');
  for(const d of fs.readdirSync(f.outputParent))assert.equal(fs.existsSync(path.join(f.outputParent,d,'closure-report.json')),false);
});
for(const mismatch of [false,true]) test(`JS closure registers relative nested package ownership${mismatch?' and rejects its lock mismatch':''}`, async()=>{
  const f=assetFixture();fs.writeFileSync(path.join(f.sourceRoot,'src/gateway/server.ts'),'import "fixture-outer";');
  jsPackage(f,'fixture-outer','1.0.0',{}, {'index.js':'require("./node_modules/fixture-inner/index.js");'});
  jsPackage(f,'fixture-inner','1.0.0',{dependencies:{'fixture-declared-leaf':'1.0.0'}},{'index.js':'exports.value=1;'},'node_modules/fixture-outer/node_modules');
  jsPackage(f,'fixture-declared-leaf','1.0.0',{}, {'index.js':'exports.leaf=1;'});
  if(mismatch){const p=path.join(f.sourceRoot,'node_modules/fixture-outer/node_modules/fixture-inner/package.json');
    const pkg=JSON.parse(fs.readFileSync(p));pkg.version='9.0.0';fs.writeFileSync(p,JSON.stringify(pkg));
    await assert.rejects(()=>withJs(f),e=>e.message==='js_lock_mismatch');assert.deepEqual(fs.readdirSync(f.outputParent),[]);
  }else{const {graph}=readJsGraph(await withJs(f));
    assert.ok(graph.packages.some(x=>x.name==='fixture-inner'));assert.ok(graph.packages.some(x=>x.name==='fixture-declared-leaf'));
    assert.ok(graph.edges.some(x=>x.specifier==='fixture-declared-leaf'&&x.status==='RESOLVED'));
  }
});
for(const self of [false,true])test(`JS closure uses nearest nested package scope for ${self?'self reference':'imports'}`,async()=>{
  const f=assetFixture();fs.writeFileSync(path.join(f.sourceRoot,'src/gateway/server.ts'),'import "fixture-scope";');
  jsPackage(f,'fixture-scope','1.0.0',{type:'module',exports:'./sub/entry.js'}, {
    'sub/package.json':JSON.stringify({name:'fixture-local-scope',type:'module',imports:{'#inside':'./inside.js'},exports:{'./inside':'./inside.js'}}),
    'sub/entry.js':self?'import "fixture-local-scope/inside";':'import "#inside";', 'sub/inside.js':'export const inside=1;'
  });
  const {graph}=readJsGraph(await withJs(f)), spec=self?'fixture-local-scope/inside':'#inside';
  assert.ok(graph.edges.some(x=>x.specifier===spec&&x.status==='RESOLVED'&&x.NODE_ENTRY_RESOLUTION_VERIFIED));
  assert.ok(graph.files.some(x=>x.source.endsWith('/fixture-scope/sub/inside.js')));
});
test('JS closure rejects a resolver result that escapes back to the development tree',()=>{
  const f=jsFixture();const outcome=jsChild(f,`const child=await import('node:child_process');const builtin=await import('node:module');const run=child.default.spawnSync;
    child.default.spawnSync=(exe,args,opts)=>{const r=run(exe,args,opts);if(args?.some(x=>typeof x==='string'&&x.includes('gateway-metadata-resolver-v1'))&&opts?.input){
      const requests=JSON.parse(opts.input);if(requests.some(q=>q.parent.startsWith(${JSON.stringify(f.outputParent)}))){const rows=JSON.parse(r.stdout);
        const row=rows.find(x=>x.target&&!x.target.startsWith('node:'));if(row)row.target=${JSON.stringify(path.join(f.sourceRoot,'node_modules/fixture-leaf/index.js'))};
        return {...r,stdout:JSON.stringify(rows)};}}return r;};builtin.syncBuiltinESMExports();`);
  assert.equal(outcome.success,false);assert.equal(outcome.message,'js_development_path_escape');
});
test('JS closure does not claim Node entry verification when no entry was resolved',async()=>{
  const f=assetFixture();fs.writeFileSync(path.join(f.sourceRoot,'src/gateway/server.ts'),'export const value=1;');
  for(const name of Object.keys(assetProfile)){const p=path.join(f.sourceRoot,'node_modules',name,'package.json');const pkg=JSON.parse(fs.readFileSync(p));
    delete pkg.dependencies;delete pkg.optionalDependencies;delete pkg.peerDependencies;fs.writeFileSync(p,JSON.stringify(pkg));}
  const {summary,graph}=readJsGraph(await withJs(f));assert.equal(graph.edges.filter(x=>x.status==='RESOLVED').length,0);
  assert.equal(summary.NODE_ENTRY_RESOLUTION_VERIFIED,false);
});
test('JS closure keeps optional peer declarations and referenced BM25 models unresolved',async()=>{
  const f=jsFixture(), p=path.join(f.sourceRoot,'node_modules/fixture-leaf/package.json'), pkg=JSON.parse(fs.readFileSync(p));
  pkg.optionalDependencies={'fixture-optional-missing':'1'};pkg.peerDependencies={'fixture-peer-missing':'1'};fs.writeFileSync(p,JSON.stringify(pkg));
  fs.writeFileSync(path.join(f.sourceRoot,'node_modules/fixture-leaf/index.js'),'require("@tencentdb-agent-memory/tcvdb-text/data/bm25_zh_default.json");');
  put(f.sourceRoot,'node_modules/@tencentdb-agent-memory/tcvdb-text/data/bm25_zh_default.json','{"synthetic":true}');
  const result=await withJs(f),{summary,graph}=readJsGraph(result);
  for(const specifier of ['fixture-optional-missing','fixture-peer-missing'])assert.ok(graph.edges.some(x=>x.specifier===specifier&&x.status==='UNRESOLVED'));
  assert.ok(graph.edges.some(x=>x.reason==='RESOURCE_SCOPE_UNRESOLVED'));
  assert.equal(fs.existsSync(path.join(result.candidateDirectory,'app/node_modules/@tencentdb-agent-memory/tcvdb-text/data/bm25_zh_default.json')),false);
  assert.equal(summary.TRANSITIVE_CLOSURE_PROVEN,false);
});
for(const fileModule of [false,true])test(`JS closure refuses unowned relative node_modules ${fileModule?'file modules':'packages without metadata'}`,async()=>{
  const f=assetFixture();fs.writeFileSync(path.join(f.sourceRoot,'src/gateway/server.ts'),'import "fixture-outer";');
  jsPackage(f,'fixture-outer','1.0.0',{}, {'index.js':fileModule?'require("./node_modules/untracked.js");':'require("./node_modules/untracked/index.js");'});
  put(f.sourceRoot,`node_modules/fixture-outer/node_modules/${fileModule?'untracked.js':'untracked/index.js'}`,'exports.value=1;');
  await assert.rejects(()=>withJs(f),e=>['asset_required_file_missing','js_lock_mismatch'].includes(e.message));
  assert.deepEqual(fs.readdirSync(f.outputParent),[]);
});
test('JS closure rechecks the earlier native asset identities after JS copying',()=>{
  const f=jsFixture();const outcome=jsChild(f,`const copy=fs.copyFileSync;let changed=false;fs.copyFileSync=(src,dst,...rest)=>{const r=copy(src,dst,...rest);
    if(!changed&&src.includes('fixture-leaf')){changed=true;let p=path.dirname(dst);while(path.basename(p)!=='app')p=path.dirname(p);
      fs.appendFileSync(path.join(p,'node_modules/sqlite-vec-windows-x64/vec0.dll'),'CHANGED');}return r;};`);
  assert.equal(outcome.success,false);assert.equal(outcome.message,'asset_identity_mismatch');
});

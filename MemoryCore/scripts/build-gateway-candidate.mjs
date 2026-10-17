// Offline compiler/diagnostic gate only. Never launches Gateway or grants release authority.
// Reads are point-in-time; this is not a protected loader or a hostile-writer boundary.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { isBuiltin, createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const PROJECT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = 'src/gateway/server.ts';
const FORMAT = 'gateway-js-candidate-closure/v1';
const MAX_REPORT = 4 * 1024 * 1024;
const BLOCKERS = new Set(['external_dependency_closure_unverified', 'native_loading_unverified', 'resource_packaging_unverified',
  'conditional_exclusions_unverified', 'runtime_configuration_unisolated', 'static_candidate_not_release_validation',
  'missing_local_modules', 'ambiguous_local_modules', 'nonliteral_dynamic_loading', 'candidate_compilation_failed']);
const INJECTORS = ['NODE_OPTIONS', 'NODE_PATH', 'NODE_COMPILE_CACHE', 'NODE_V8_COVERAGE',
  'NAPI_RS_NATIVE_LIBRARY_PATH', 'NAPI_RS_FORCE_WASI', 'ESBUILD_BINARY_PATH', 'TSX_TSCONFIG_PATH'];
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw new Error(code); };
const within = (root, file) => { const r = path.relative(root, file); return r === '' || (!r.startsWith(`..${path.sep}`) && r !== '..' && !path.isAbsolute(r)); };
const rel = (root, file) => path.relative(root, file).split(path.sep).join('/');

function environment() {
  if (process.platform !== 'win32') fail('platform_unavailable');
  if (INJECTORS.some(name => process.env[name])) fail('build_environment_rejected');
}
function checkedPath(input, code, directory = true) {
  if (typeof input !== 'string' || !path.isAbsolute(input) || input.length > 2000 ||
      !/^[a-z]:[\\/]/i.test(input) || input.slice(3).split(/[\\/]/).some(p => !p || p === '.' || p === '..' || /[. ]$/.test(p) || /[<>:"|?*\x00-\x1f]/.test(p))) fail(code);
  const absolute = path.resolve(input);
  for (let current = absolute; ; current = path.dirname(current)) {
    const info = fs.lstatSync(current);
    if (info.isSymbolicLink()) fail('reparse_rejected');
    if (current === path.dirname(current)) break;
  }
  if (fs.realpathSync.native(absolute).toLowerCase() !== absolute.toLowerCase()) fail('reparse_rejected');
  const info = fs.statSync(absolute);
  if (directory ? !info.isDirectory() : !info.isFile()) fail(code);
  return absolute;
}
function authorizedScope() {
  const scope = checkedPath(process.env.GATEWAY_CANDIDATE_TEMP_ROOT, 'output_scope_invalid');
  // Host supplies this task scope; it is a write limiter, not an identity or authorization proof.
  if (!within(path.resolve(os.tmpdir()), scope) || within(path.resolve(PROJECT, '..'), scope) ||
      within(path.resolve(PROJECT, '../../CodexMemoryGovernance'), scope)) fail('output_scope_invalid');
  return scope;
}
function checkedOptions(options) {
  if (!options || Object.getPrototypeOf(options) !== Object.prototype ||
      !['outputParent,sourceRoot', 'outputParent,sourceRoot,stageAssets', 'outputParent,sourceRoot,stageAssets,stageJsDependencies'].includes(Reflect.ownKeys(options).sort().join(','))) fail('options_invalid');
  const staging = Object.getOwnPropertyDescriptor(options, 'stageAssets');
  if (staging && (!Object.hasOwn(staging, 'value') || staging.value !== true)) fail('options_invalid');
  const jsStaging = Object.getOwnPropertyDescriptor(options, 'stageJsDependencies');
  if (jsStaging && (!Object.hasOwn(jsStaging, 'value') || jsStaging.value !== true || staging?.value !== true)) fail('options_invalid');
  for (const name of ['sourceRoot', 'outputParent']) {
    const descriptor = Object.getOwnPropertyDescriptor(options, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string') fail('options_invalid');
  }
  const scope = authorizedScope();
  const sourceRoot = checkedPath(options.sourceRoot, 'source_path_invalid');
  const outputParent = checkedPath(options.outputParent, 'output_scope_invalid');
  if ((sourceRoot !== PROJECT && !within(scope, sourceRoot)) || !within(scope, outputParent) ||
      within(sourceRoot, outputParent) || within(outputParent, sourceRoot)) fail('output_scope_invalid');
  return { scope, sourceRoot, outputParent, stageAssets: staging?.value === true, stageJsDependencies: jsStaging?.value === true };
}
function readSource(file) {
  checkedPath(file, 'source_path_invalid', false);
  if (fs.statSync(file).size > 4 * 1024 * 1024) fail('source_resource_limit');
  const bytes = fs.readFileSync(file);
  if (bytes.length > 4 * 1024 * 1024) fail('source_resource_limit');
  return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), sha256: sha(bytes), bytes: bytes.length };
}
function identity(file) {
  checkedPath(file, 'dependency_path_invalid', false);
  const size = fs.statSync(file).size;
  if (size > 512 * 1024 * 1024) fail('dependency_resource_limit');
  const fd = fs.openSync(file, 'r');
  const hash = crypto.createHash('sha256');
  try {
    const buffer = Buffer.alloc(64 * 1024);
    let n; while ((n = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) hash.update(buffer.subarray(0, n));
  } finally { fs.closeSync(fd); }
  return { bytes: size, sha256: hash.digest('hex') };
}
function dependencyIdentityReader() {
  const cache = new Map(), metadataCache = new Map(); let total = 0;
  const reserve = size => {
    total += size;
    if (total > 512 * 1024 * 1024) fail('dependency_resource_limit');
  };
  const identify = file => {
    if (!cache.has(file)) {
      checkedPath(file, 'dependency_path_invalid', false);
      const size = fs.statSync(file).size;
      reserve(size);
      cache.set(file, identity(file));
    }
    return cache.get(file);
  };
  const metadata = file => {
    checkedPath(file, 'dependency_path_invalid', false);
    const key = fs.realpathSync.native(file);
    if (!metadataCache.has(key)) {
      const size = fs.statSync(file).size;
      if (size > 1024 * 1024) fail('dependency_resource_limit');
      reserve(size);
      const bytes = fs.readFileSync(file);
      if (bytes.length !== size) fail('dependency_changed_during_build');
      metadataCache.set(key, { pkg: JSON.parse(bytes), sha256: sha(bytes) });
    }
    return metadataCache.get(key);
  };
  return { identify, metadata };
}
function tools() {
  const lockBytes = fs.readFileSync(path.join(PROJECT, 'package-lock.json'));
  const lock = JSON.parse(lockBytes);
  const versions = {};
  for (const name of ['esbuild', 'typescript', '@esbuild/win32-x64']) {
    const file = path.join(PROJECT, 'node_modules', name, 'package.json');
    checkedPath(file, 'toolchain_unavailable', false);
    const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (pkg.version !== lock.packages?.[`node_modules/${name}`]?.version) fail('toolchain_lock_mismatch');
    versions[name] = pkg.version;
  }
  const require = createRequire(path.join(PROJECT, 'package.json'));
  const jsEntrypoints = ['esbuild', 'typescript'].map(name => {
    const file = require.resolve(name);
    if (!within(path.join(PROJECT, 'node_modules', name), file)) fail('toolchain_unavailable');
    return { path: rel(PROJECT, file), ...identity(file) };
  });
  return { esbuild: require('esbuild'), ts: require('typescript'), versions,
    jsEntrypoints, lockSha256: sha(lockBytes), executable: identity(path.join(PROJECT, 'node_modules/@esbuild/win32-x64/esbuild.exe')) };
}
function localTarget(sourceRoot, from, specifier) {
  const target = path.resolve(path.dirname(from), specifier);
  if (!within(path.join(sourceRoot, 'src'), target)) fail('source_path_invalid');
  const candidates = [...new Set([target, target.replace(/\.js$/, '.ts'), target.replace(/\.js$/, '.tsx'),
    target.replace(/\.js$/, '.jsx'), `${target}.ts`, path.join(target, 'index.ts')])]
    .filter(file => fs.existsSync(file) && fs.lstatSync(file).isFile());
  return candidates;
}
function selectedExport(value, mode) {
  if (typeof value === 'string') return value;
  if (!value || Array.isArray(value) || typeof value !== 'object') return null;
  for (const [condition, target] of Object.entries(value)) {
    if (['node', 'node-addons', mode, 'default'].includes(condition)) {
      const result = selectedExport(target, mode); if (result) return result;
    }
  }
  return null;
}
function external(sourceRoot, edge, dependencies) {
  const name = edge.specifier.startsWith('@') ? edge.specifier.split('/').slice(0, 2).join('/') : edge.specifier.split('/')[0];
  const record = { ...edge, package: name, status: 'MISSING', transitiveClosure: 'NOT_VERIFIED' };
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name) || edge.specifier.includes('..') || edge.specifier.includes('\\')) return record;
  const root = path.join(sourceRoot, 'node_modules', name);
  const metadata = path.join(root, 'package.json');
  if (!fs.existsSync(metadata)) return record;
  const { pkg, sha256 } = dependencies.metadata(metadata);
  record.version = pkg.version; record.packageJsonSha256 = sha256;
  const subpath = edge.specifier.slice(name.length);
  let target;
  if (pkg.exports !== undefined) {
    const exports = pkg.exports;
    const mapped = exports && typeof exports === 'object' && Object.keys(exports).some(k => k.startsWith('.'))
      ? exports[subpath ? `.${subpath}` : '.'] : (subpath ? null : exports);
    target = selectedExport(mapped, edge.kind === 'require' ? 'require' : 'import');
    if (target && !target.startsWith('./')) target = null;
  } else target = subpath ? `.${subpath}` : (pkg.main || './index.js');
  if (target) {
    const file = path.resolve(root, target);
    if (!within(root, file)) fail('dependency_path_invalid');
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      record.resolvedPath = rel(sourceRoot, file); record.fileIdentity = dependencies.identify(file);
      record.status = 'RESOLVED_METADATA_ONLY';
    }
  }
  // This bounded resolver is deliberately not a claim of full Node exports-pattern resolution.
  if (record.status === 'MISSING') record.status = 'PACKAGE_PRESENT_RESOLUTION_UNVERIFIED';
  return record;
}
function analyze(sourceRoot, ts) {
  const queue = [path.join(sourceRoot, ENTRY)], seen = new Set(), sources = [], imports = [], nonliteral = [];
  let total = 0;
  while (queue.length) {
    const file = queue.shift(); if (seen.has(file)) continue; seen.add(file);
    if (seen.size > 512) fail('source_resource_limit');
    const input = readSource(file); total += input.bytes; if (total > 32 * 1024 * 1024) fail('source_resource_limit');
    const name = rel(sourceRoot, file);
    if (!/\.(?:ts|tsx|js|jsx)$/.test(name)) fail('source_path_invalid');
    const ast = ts.createSourceFile(file, input.text, ts.ScriptTarget.Latest, true);
    sources.push({ name, file, ...input });
    function edge(node, specifier, kind) {
      const record = { source: name, line: ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1, specifier, kind };
      if (specifier.startsWith('.')) {
        const targets = localTarget(sourceRoot, file, specifier);
        record.status = targets.length === 1 ? 'RESOLVED_SOURCE' : targets.length ? 'AMBIGUOUS' : 'MISSING';
        if (targets.length === 1) { record.resolvedSource = rel(sourceRoot, targets[0]); queue.push(targets[0]); }
      } else if (isBuiltin(specifier)) record.status = 'NODE_BUILTIN';
      else record.status = 'EXTERNAL';
      imports.push(record);
    }
    function visit(node) {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        const c = node.importClause;
        const typeOnly = c && (c.isTypeOnly || (!c.name && c.namedBindings && ts.isNamedImports(c.namedBindings) &&
          c.namedBindings.elements.length > 0 && c.namedBindings.elements.every(e => e.isTypeOnly)));
        if (!typeOnly) edge(node, node.moduleSpecifier.text, 'static-import');
      } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier) && !node.isTypeOnly) edge(node, node.moduleSpecifier.text, 'export');
      else if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) && node.expression.text === 'require'))) {
        const argument = node.arguments[0], kind = node.expression.kind === ts.SyntaxKind.ImportKeyword ? 'dynamic-import' : 'require';
        if (argument && (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument))) edge(node, argument.text, kind);
        else nonliteral.push({ source: name, line: ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1, kind, status: 'UNRESOLVED' });
      }
      if (imports.length + nonliteral.length > 2048) fail('source_resource_limit');
      ts.forEachChild(node, visit);
    }
    visit(ast);
  }
  return { sources, imports, nonliteral };
}
function asset(sourceRoot, name, identify) {
  const file = path.join(sourceRoot, name);
  return fs.existsSync(file) ? { path: name, status: 'PRESENT_NOT_LOAD_VERIFIED', ...identify(file) } : { path: name, status: 'MISSING' };
}

// Reviewed Windows-x64 selection only. No recursive npm closure or package code execution.
const ASSET_PROFILE = {
  'sqlite-vec': ['0.1.7-alpha.2', ['index.cjs', 'index.mjs']],
  'sqlite-vec-windows-x64': ['0.1.7-alpha.2', ['vec0.dll']],
  '@node-rs/jieba': ['2.0.2', ['index.js', 'dict.js', 'dict.txt', 'idf.txt', 'LICENSE']],
  '@node-rs/jieba-win32-x64-msvc': ['2.0.2', ['jieba.win32-x64-msvc.node']],
  '@tencentdb-agent-memory/tcvdb-text': ['0.1.1', ['dist/index.js', 'dist/types.js', 'dist/hash.js', 'dist/paths.js',
    'dist/encoder/bm25.js', 'dist/encoder/base-encoder.js', 'dist/tokenizer/jieba-tokenizer.js',
    'dist/tokenizer/base-tokenizer.js', 'data/stopwords.txt', 'LICENSE']],
  murmurhash: ['2.0.1', ['murmurhash.js']],
};
const assetName = name => typeof name === 'string' && name.length <= 240 &&
  !/[<>:"|?*\x00-\x1f\\/]/.test(name) && !/[. ]$/.test(name) && name !== '.' && name !== '..' &&
  !/^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\.|$)/i.test(name);
function assetPath(file, directory = false) {
  if (!fs.existsSync(file)) fail('asset_required_file_missing');
  checkedPath(file, 'asset_path_invalid', directory);
  // Enumerated long names, not a '~1' pattern, reject an 8.3 alias at any component.
  for (let current = file; current !== path.dirname(current); current = path.dirname(current)) {
    if (!assetName(path.basename(current))) fail('asset_path_invalid');
    const matches = fs.readdirSync(path.dirname(current)).filter(n => n.toLowerCase() === path.basename(current).toLowerCase());
    if (matches.length !== 1) fail(matches.length ? 'asset_path_collision' : 'asset_path_alias_rejected');
  }
}
function assetInventory(root) {
  const items = []; let count = 0;
  function walk(dir, depth) {
    if (depth > 12) fail('asset_resource_limit');
    const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    const names = new Set();
    for (const entry of entries) {
      if (++count > 2048) fail('asset_resource_limit');
      if (!assetName(entry.name)) fail('asset_path_invalid');
      const folded = entry.name.toLowerCase();
      if (names.has(folded)) fail('asset_path_collision'); names.add(folded);
      if (entry.isSymbolicLink()) fail('reparse_rejected');
      const file = path.join(dir, entry.name);
      const info = fs.lstatSync(file);
      if (info.isSymbolicLink()) fail('reparse_rejected');
      if (info.isDirectory()) { items.push({ path: rel(root, file), kind: 'directory' }); walk(file, depth + 1); }
      else if (info.isFile()) items.push({ path: rel(root, file), kind: 'file', bytes: info.size });
      else fail('asset_path_invalid');
    }
  }
  walk(root, 0); return items;
}
function windowsNoReparse(files, treeRoots = []) {
  // Fixed read-only OS query also rejects reparse tags not exposed as symlinks by Node.
  const paths = new Set();
  for (const file of files) for (let p = file; ; p = path.dirname(p)) {
    paths.add(p); if (p === path.dirname(p)) break;
  }
  const executable = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  const command = '$ErrorActionPreference="Stop"; try { $inputData=([Console]::In.ReadToEnd() | ConvertFrom-Json); foreach($p in $inputData.paths) { if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { [Console]::Out.Write("REPARSE"); exit 2 } }; $queue=[Collections.Generic.Queue[string]]::new(); foreach($p in $inputData.treeRoots){$queue.Enqueue($p)}; $count=0; while($queue.Count -gt 0){$dir=$queue.Dequeue(); foreach($p in [IO.Directory]::EnumerateFileSystemEntries($dir)){if((++$count) -gt 12288){throw "limit"};$attributes=[IO.File]::GetAttributes($p);if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){[Console]::Out.Write("REPARSE");exit 2};if(($attributes -band [IO.FileAttributes]::Directory) -ne 0){$queue.Enqueue($p)}}}; [Console]::Out.Write("OK") } catch { [Console]::Out.Write("FAILED"); exit 1 }';
  const result = spawnSync(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], {
    input: JSON.stringify({ paths: [...paths], treeRoots }), encoding: 'utf8', timeout: 30000, maxBuffer: 4096,
  });
  if (result.status === 2 && result.stdout === 'REPARSE') fail('reparse_rejected');
  if (result.status !== 0 || result.stdout !== 'OK') fail('asset_windows_path_check_failed');
}
function assetIdentity(file) {
  assetPath(file);
  const fd = fs.openSync(file, 'r');
  try {
    const before = fs.fstatSync(fd), digest = crypto.createHash('sha256'); let total = 0;
    if (before.size > 64 * 1024 * 1024) fail('asset_resource_limit');
    const buffer = Buffer.alloc(64 * 1024); let n;
    while ((n = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
      total += n; if (total > 64 * 1024 * 1024) fail('asset_resource_limit'); digest.update(buffer.subarray(0, n));
    }
    const after = fs.fstatSync(fd);
    if (before.size !== total || after.size !== total || before.mtimeMs !== after.mtimeMs) fail('asset_identity_mismatch');
    return { bytes: total, sha256: digest.digest('hex') };
  } finally { fs.closeSync(fd); }
}
function prepareAssetStaging(sourceRoot) {
  if (process.arch !== 'x64') fail('asset_platform_unsupported');
  const lockPath = path.join(sourceRoot, 'package-lock.json');
  assetPath(lockPath);
  const packageRoots = Object.keys(ASSET_PROFILE).map(name => path.join(sourceRoot, 'node_modules', name));
  for (const root of packageRoots) assetPath(root, true);
  // Inspect each directory's tag before enumerating through it or reading package bytes.
  windowsNoReparse([lockPath, ...packageRoots], packageRoots);
  if (fs.statSync(lockPath).size > 16 * 1024 * 1024) fail('asset_resource_limit');
  const lockBytes = fs.readFileSync(lockPath), lock = JSON.parse(lockBytes);
  if (lockBytes.length > 16 * 1024 * 1024) fail('asset_resource_limit');
  const files = [], packages = [], inventoryPaths = [lockPath], inventory = [];
  let total = 0;
  for (const [name, [version, selected]] of Object.entries(ASSET_PROFILE)) {
    const root = path.join(sourceRoot, 'node_modules', name), metaFile = path.join(root, 'package.json');
    assetPath(root, true); assetPath(metaFile);
    if (fs.statSync(metaFile).size > 1024 * 1024) fail('asset_resource_limit');
    const metaBytes = fs.readFileSync(metaFile);
    if (metaBytes.length > 1024 * 1024) fail('asset_resource_limit');
    const pkg = JSON.parse(metaBytes), locked = lock.packages?.[`node_modules/${name}`];
    if (pkg.name !== name || pkg.version !== version || locked?.version !== version ||
        typeof locked.integrity !== 'string' || !locked.integrity.startsWith('sha512-') ||
        typeof locked.resolved !== 'string' || !locked.resolved.startsWith('https://registry.npmjs.org/')) fail('asset_lock_mismatch');
    if ((pkg.os && (!Array.isArray(pkg.os) || !pkg.os.includes('win32') || pkg.os.includes('!win32'))) ||
        (pkg.cpu && (!Array.isArray(pkg.cpu) || !pkg.cpu.includes('x64') || pkg.cpu.includes('!x64')))) fail('asset_platform_unsupported');
    const listing = assetInventory(root);
    inventory.push({ package: name, sha256: sha(JSON.stringify(listing)), entries: listing.length,
      identityScope: 'ENTRY_NAMES_TYPES_SIZES_NOT_UNSELECTED_FILE_CONTENTS' });
    inventoryPaths.push(root, ...listing.map(x => path.join(root, x.path)));
    const entries = name === 'sqlite-vec' ? ['index.cjs', 'index.mjs'] :
      name === 'sqlite-vec-windows-x64' ? [] : [name === 'murmurhash' ? 'murmurhash.js' : selected[0]];
    if (name !== 'sqlite-vec-windows-x64') {
      const target = pkg.main === 'murmurhash' ? 'murmurhash.js' : pkg.main?.replace(/^\.\//, '');
      if (!entries.includes(target)) fail('asset_entry_unverified');
      if (pkg.exports !== undefined) {
        const exported = pkg.exports['.'] ?? pkg.exports;
        const imported = selectedExport(exported, 'import');
        if (!imported || !entries.includes(imported.replace(/^\.\//, ''))) fail('asset_entry_unverified');
        if (name === 'sqlite-vec' && selectedExport(exported, 'require') !== './index.cjs') fail('asset_entry_unverified');
      }
    }
    const dependencyEdges = [];
    for (const kind of ['dependencies', 'optionalDependencies']) {
      const declarations = pkg[kind] ?? {};
      if (!declarations || Array.isArray(declarations) || typeof declarations !== 'object' || Object.keys(declarations).length > 128) fail('asset_metadata_invalid');
      for (const [dependency, range] of Object.entries(declarations)) {
        if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(dependency) || typeof range !== 'string' || range.length > 100) fail('asset_metadata_invalid');
        dependencyEdges.push({ name: dependency, range, kind,
          status: Object.hasOwn(ASSET_PROFILE, dependency) ? 'SELECTED_VERSION_COMPATIBILITY_NOT_PROVEN' : 'UNRESOLVED_NOT_SELECTED' });
      }
    }
    packages.push({ name, version, lockSource: 'registry.npmjs.org', lockIntegrity: locked.integrity,
      metadata: { main: pkg.main ?? null, exports: pkg.exports ?? null, engines: pkg.engines ?? null },
      entries, dependencyEdges, PACKAGE_METADATA_RESOLVED: true, PACKAGE_TRANSITIVE_CLOSURE_PROVEN: false });
    for (const file of ['package.json', ...selected]) {
      const source = path.join(root, file), id = assetIdentity(source);
      if (file === 'package.json' && id.sha256 !== sha(metaBytes)) fail('asset_identity_mismatch');
      total += id.bytes; if (total > 128 * 1024 * 1024) fail('asset_resource_limit');
      files.push({ source: rel(sourceRoot, source), output: `app/node_modules/${name}/${file}`, sourceSha256: id.sha256, bytes: id.bytes });
    }
  }
  windowsNoReparse(inventoryPaths);
  return { files, packages, inventory, total, lockPath, lockSha256: sha(lockBytes) };
}
function copyAssetStaging(plan, sourceRoot, candidateDirectory) {
  const parents = [...new Set(plan.files.map(item => path.dirname(path.join(candidateDirectory, item.output))))];
  for (const parent of parents) fs.mkdirSync(parent, { recursive: true });
  windowsNoReparse(parents);
  for (const item of plan.files) {
    const source = path.join(sourceRoot, item.source), target = path.join(candidateDirectory, item.output);
    if (assetIdentity(source).sha256 !== item.sourceSha256) fail('asset_identity_mismatch');
    assetPath(path.dirname(target), true);
    fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
    const copied = assetIdentity(target);
    if (copied.sha256 !== item.sourceSha256 || copied.bytes !== item.bytes || assetIdentity(source).sha256 !== item.sourceSha256) fail('asset_identity_mismatch');
    item.outputSha256 = copied.sha256;
  }
  windowsNoReparse(plan.files.flatMap(x => [path.join(sourceRoot, x.source), path.join(candidateDirectory, x.output)]));
  if (assetIdentity(plan.lockPath).sha256 !== plan.lockSha256 || plan.files.some(x =>
    assetIdentity(path.join(sourceRoot, x.source)).sha256 !== x.sourceSha256 ||
    assetIdentity(path.join(candidateDirectory, x.output)).sha256 !== x.outputSha256)) fail('asset_identity_mismatch');
  return { requested: true, profile: 'selected-native-assets-win32-x64/v1',
    PACKAGE_METADATA_RESOLVED: true, PACKAGE_FILES_STAGED: true, PACKAGE_FILE_IDENTITIES_VERIFIED: true,
    PACKAGE_TRANSITIVE_CLOSURE_PROVEN: false, NATIVE_LOAD_VERIFIED: false, RESOURCE_LAYOUT_VERIFIED: false,
    selectedResourceLayoutVerified: true, stagedFileCount: plan.files.length, stagedTotalBytes: plan.total,
    lockSha256: plan.lockSha256, files: plan.files, packages: plan.packages, directoryInventories: plan.inventory,
    selectedTreeSha256: sha(JSON.stringify(plan.files.map(x => [x.output, x.bytes, x.outputSha256]))),
    unresolvedResources: ['bm25_zh_default.json', 'bm25_en_default.json'].map(name => ({
      path: `node_modules/@tencentdb-agent-memory/tcvdb-text/data/${name}`, status: 'UNRESOLVED_RUNTIME_LANGUAGE_SCOPE_NOT_APPROVED', staged: false })),
    limits: ['copy_only_no_package_or_native_execution', 'lock_metadata_match_not_tarball_integrity',
      'non_atomic_windows_path_and_file_checks_TOCTOU_remains', 'unselected_package_files_not_copied',
      'jieba_generated_loader_version_check_and_WASI_fallback_unverified', 'no_runtime_ABI_or_configuration_validation'],
  };
}

function nodeResolveOnly(requests) {
  // Fixed metadata-only Node APIs. Never import/require any requested package body.
  const code = `// gateway-metadata-resolver-v1
    import fs from 'node:fs';import {createRequire} from 'node:module';import {pathToFileURL,fileURLToPath} from 'node:url';
    const input=JSON.parse(fs.readFileSync(0,'utf8'));
    const output=input.map(q=>{try{const parent=pathToFileURL(q.parent).href;
      const target=q.mode==='require'?createRequire(parent).resolve(q.specifier):import.meta.resolve(q.specifier,parent);
      return {target:target.startsWith('file:')?fileURLToPath(target):target};
    }catch(e){return {error:typeof e.code==='string'?e.code:'RESOLUTION_ERROR'};}});
    process.stdout.write(JSON.stringify(output));`;
  const result = spawnSync(process.execPath, ['--experimental-import-meta-resolve', '--input-type=module', '-e', code], {
    input: JSON.stringify(requests), encoding: 'utf8', timeout: 30000, maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) fail('js_resolver_unavailable');
  const output = JSON.parse(result.stdout);
  if (!Array.isArray(output) || output.length !== requests.length) fail('js_resolver_invalid');
  return output;
}
function prepareJsStaging(sourceRoot, gatewayGraph, assetPlan, ts) {
  const lockBytes = fs.readFileSync(assetPlan.lockPath), lock = JSON.parse(lockBytes);
  if (sha(lockBytes) !== assetPlan.lockSha256) fail('asset_identity_mismatch');
  const modulesRoot = path.join(sourceRoot, 'node_modules');
  const packages = new Map(), files = new Map(), queue = [], requests = [], edges = [];
  const shared = new Map(assetPlan.files.map(x => [x.source.toLowerCase(), x]));
  let total = 0;
  const missing = (edge, reason) => { edges.push({ ...edge, status: 'UNRESOLVED', reason, NODE_ENTRY_RESOLUTION_VERIFIED: false }); };
  function addFile(file, owner, expected) {
    if (!within(modulesRoot, file)) fail('js_path_escape');
    assetPath(file);
    const canonical = fs.realpathSync.native(file), key = canonical.toLowerCase();
    if (files.has(key)) {
      if (expected && files.get(key).sourceSha256 !== expected) fail('asset_identity_mismatch');
      return;
    }
    const id = assetIdentity(canonical);
    if (expected && id.sha256 !== expected) fail('asset_identity_mismatch');
    total += id.bytes;
    if (total > 256 * 1024 * 1024 || files.size >= 8192) fail('js_resource_limit');
    const source = rel(sourceRoot, canonical), already = shared.get(source.toLowerCase());
    if (already && already.sourceSha256 !== id.sha256) fail('asset_identity_mismatch');
    files.set(key, { source, output: `app/${source}`, sourceSha256: id.sha256, bytes: id.bytes,
      packageRoot: owner.root, sharedAsset: !!already });
    if (/\.(?:js|cjs|mjs)$/.test(canonical)) queue.push({ file: canonical, owner });
    // Nested package.json files can change Node type/imports scope; copy the real scopes too.
    for (let dir = path.dirname(canonical); dir !== owner.absolute && within(owner.absolute, dir); dir = path.dirname(dir)) {
      const scopeFile = path.join(dir, 'package.json');
      if (fs.existsSync(scopeFile)) addFile(scopeFile, owner);
    }
  }
  function register(root) {
    assetPath(root, true);
    const absolute = fs.realpathSync.native(root), key = absolute.toLowerCase();
    if (!within(modulesRoot, absolute)) fail('js_path_escape');
    if (packages.has(key)) return packages.get(key);
    if (packages.size >= 512) fail('js_resource_limit');
    const metadata = path.join(absolute, 'package.json');
    assetPath(metadata); windowsNoReparse([absolute, metadata]);
    if (fs.statSync(metadata).size > 1024 * 1024) fail('js_resource_limit');
    const bytes = fs.readFileSync(metadata); if (bytes.length > 1024 * 1024) fail('js_resource_limit');
    const pkg = JSON.parse(bytes), relative = rel(sourceRoot, absolute), locked = lock.packages?.[relative];
    if (typeof pkg.name !== 'string' || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(pkg.name) ||
        typeof pkg.version !== 'string' || pkg.version.length > 100 || locked?.version !== pkg.version || locked.link ||
        typeof locked.integrity !== 'string' || typeof locked.resolved !== 'string' ||
        !locked.resolved.startsWith('https://registry.npmjs.org/')) fail('js_lock_mismatch');
    const owner = { absolute, root: relative, name: pkg.name, version: pkg.version, pkg,
      metadataSha256: sha(bytes), PACKAGE_RESOLVED: true, TRANSITIVE_CLOSURE_PROVEN: false, NATIVE_LOAD_VERIFIED: false };
    packages.set(key, owner); addFile(metadata, owner, sha(bytes));
    for (const kind of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      const declared = pkg[kind] ?? {};
      if (!declared || Array.isArray(declared) || typeof declared !== 'object' || Object.keys(declared).length > 256) fail('js_metadata_invalid');
      for (const [specifier, range] of Object.entries(declared)) {
        if (typeof range !== 'string' || range.length > 200) fail('js_metadata_invalid');
        const edge = { parent: metadata, owner, specifier, mode: pkg.type === 'module' ? 'import' : 'require', kind, range };
        if (kind === 'dependencies') requests.push(edge);
        else missing(record(edge), 'OPTIONAL_OR_PEER_NOT_ASSUMED_EXCLUDED');
      }
    }
    return owner;
  }
  function record(edge) {
    return { source: rel(sourceRoot, edge.parent), owner: edge.owner?.root ?? null, specifier: edge.specifier,
      mode: edge.mode, kind: edge.kind, ...(edge.line ? { line: edge.line } : {}), ...(edge.range ? { range: edge.range } : {}) };
  }
  function locate(specifier, parent, owner) {
    const name = specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0];
    if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name) || specifier.split('/').some(x => x === '..' || x === '.') || /[\\:\x00-\x1f]/.test(specifier)) fail('js_path_escape');
    if (owner) {
      for (let dir = path.dirname(parent); within(owner.absolute, dir); dir = path.dirname(dir)) {
        const scopeFile = path.join(dir, 'package.json');
        if (fs.existsSync(scopeFile)) {
          const bytes = fs.readFileSync(scopeFile), snapshot = files.get(fs.realpathSync.native(scopeFile).toLowerCase());
          if (bytes.length > 1024 * 1024 || !snapshot || sha(bytes) !== snapshot.sourceSha256) fail('asset_identity_mismatch');
          const scope = JSON.parse(bytes);
          if (scope.name === name && scope.exports !== undefined) return owner;
          break;
        }
        if (dir === owner.absolute) break;
      }
    }
    for (let dir = path.dirname(parent); within(sourceRoot, dir); dir = path.dirname(dir)) {
      if (path.basename(dir) !== 'node_modules') {
        const root = path.join(dir, 'node_modules', name);
        if (fs.existsSync(root)) return register(root);
      }
      if (dir === sourceRoot) break;
    }
    return null;
  }
  function ownerOf(file) {
    for (let dir = path.dirname(file); within(modulesRoot, dir); dir = path.dirname(dir)) {
      // Crossing an npm namespace without a package root is not outer-package content.
      if (path.basename(dir) === 'node_modules') fail('js_lock_mismatch');
      const parent = path.dirname(dir), npmRoot = path.basename(parent) === 'node_modules' ||
        (path.basename(parent).startsWith('@') && path.basename(path.dirname(parent)) === 'node_modules');
      if (npmRoot || (lock.packages?.[rel(sourceRoot, dir)] && fs.existsSync(path.join(dir, 'package.json')))) return register(dir);
      if (dir === modulesRoot) break;
    }
    fail('js_path_escape');
  }
  function parseModule(item) {
    const bytes = fs.readFileSync(item.file);
    if (bytes.length > 16 * 1024 * 1024) fail('js_resource_limit');
    if (sha(bytes) !== files.get(item.file.toLowerCase()).sourceSha256) fail('asset_identity_mismatch');
    const ast = ts.createSourceFile(item.file, new TextDecoder('utf8', { fatal: true }).decode(bytes), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    function visit(node) {
      let arg, mode, kind;
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
        arg = node.moduleSpecifier; mode = 'import'; kind = 'static';
      } else if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(node.expression) && ['require', '__require'].includes(node.expression.text)) ||
          (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression) &&
            node.expression.expression.text === 'require' && node.expression.name.text === 'resolve'))) {
        arg = node.arguments[0]; mode = node.expression.kind === ts.SyntaxKind.ImportKeyword ? 'import' : 'require'; kind = 'runtime-literal';
      }
      if (mode) {
        const edge = { parent: item.file, owner: item.owner, mode, kind,
          line: ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1 };
        if (arg && (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))) requests.push({ ...edge, specifier: arg.text });
        else missing({ ...record({ ...edge, specifier: null }) }, 'NONLITERAL_LOADING');
      }
      ts.forEachChild(node, visit);
    }
    visit(ast);
  }
  for (const file of assetPlan.files) {
    const parts = file.source.split('/'); const count = parts[1].startsWith('@') ? 3 : 2;
    const owner = register(path.join(sourceRoot, ...parts.slice(0, count)));
    if (/\.(?:js|cjs|mjs)$/.test(file.source)) addFile(path.join(sourceRoot, file.source), owner, file.sourceSha256);
  }
  for (const edge of gatewayGraph.imports.filter(x => x.status === 'EXTERNAL')) requests.push({
    parent: path.join(sourceRoot, edge.source), specifier: edge.specifier, mode: edge.kind === 'require' ? 'require' : 'import',
    kind: 'gateway-external', line: edge.line,
  });
  let rounds = 0;
  while (requests.length || queue.length) {
    if (++rounds > 128 || edges.length + requests.length > 24000) fail('js_resource_limit');
    const batch = requests.splice(0), pending = [];
    for (const edge of batch) {
      const entry = record(edge), spec = edge.specifier;
      if (typeof spec !== 'string' || spec.length > 1024) fail('js_metadata_invalid');
      if (isBuiltin(spec)) { edges.push({ ...entry, status: 'BUILTIN' }); continue; }
      let expectedOwner;
      if (spec.startsWith('.')) {
        if (!edge.owner || !within(edge.owner.absolute, path.resolve(path.dirname(edge.parent), spec))) fail('js_path_escape');
        expectedOwner = edge.owner;
      } else if (spec.startsWith('#')) {
        // Node chooses the nearest package scope, which may differ from lock ownership.
        if (!edge.owner) { missing(entry, 'PACKAGE_IMPORTS_UNDEFINED'); continue; }
      } else {
        expectedOwner = locate(spec, edge.parent, edge.owner);
        if (!expectedOwner) { missing(entry, 'PACKAGE_MISSING'); continue; }
      }
      pending.push({ edge, entry, expectedOwner });
    }
    const resolved = pending.length ? nodeResolveOnly(pending.map(x => ({ parent: x.edge.parent, specifier: x.edge.specifier, mode: x.edge.mode }))) : [];
    const checkTargets = resolved.filter(x => typeof x.target === 'string' && path.isAbsolute(x.target) &&
      within(modulesRoot, x.target) && fs.existsSync(x.target)).map(x => x.target);
    if (checkTargets.length) windowsNoReparse(checkTargets);
    for (let i = 0; i < pending.length; i++) {
      const { edge, entry, expectedOwner } = pending[i], outcome = resolved[i];
      if (outcome.error) { missing(entry, outcome.error); continue; }
      const target = outcome.target;
      if (typeof target === 'string' && isBuiltin(target)) { edges.push({ ...entry, status: 'BUILTIN' }); continue; }
      if (typeof target !== 'string' || !path.isAbsolute(target) || !within(modulesRoot, target)) fail('js_path_escape');
      if (!fs.existsSync(target) || !fs.statSync(target).isFile()) { missing(entry, 'TARGET_MISSING'); continue; }
      const owner = ownerOf(target);
      assetPath(target);
      const canonical = fs.realpathSync.native(target), source = rel(sourceRoot, canonical), isShared = shared.has(source.toLowerCase());
      if (/bm25_(?:zh|en)_default\.json$/.test(source)) { missing(entry, 'RESOURCE_SCOPE_UNRESOLVED'); continue; }
      if (!/\.(?:js|cjs|mjs|json)$/.test(target) && !isShared) { missing(entry, 'NATIVE_OR_OTHER_ASSET_NOT_SELECTED'); continue; }
      addFile(canonical, owner);
      edges.push({ ...entry, status: 'RESOLVED', target: source, targetPackage: owner.root, NODE_ENTRY_RESOLUTION_VERIFIED: false });
    }
    for (const item of queue.splice(0)) parseModule(item);
  }
  const selected = [...files.values()].sort((a, b) => a.source < b.source ? -1 : a.source > b.source ? 1 : 0);
  windowsNoReparse(selected.map(x => path.join(sourceRoot, x.source)));
  if (selected.some(x => assetIdentity(path.join(sourceRoot, x.source)).sha256 !== x.sourceSha256)) fail('asset_identity_mismatch');
  return { selected, packages: [...packages.values()], edges, sourceRoot, lockSha256: assetPlan.lockSha256 };
}
function copyJsStaging(plan, candidateDirectory, sharedAssets) {
  const parents = [...new Set(plan.selected.map(x => path.dirname(path.join(candidateDirectory, x.output))))];
  for (const dir of parents) fs.mkdirSync(dir, { recursive: true }); windowsNoReparse(parents);
  const shared = new Set(sharedAssets.files.map(x => x.output.toLowerCase()));
  for (const file of plan.selected) {
    const source = path.join(plan.sourceRoot, file.source), target = path.join(candidateDirectory, file.output);
    if (assetIdentity(source).sha256 !== file.sourceSha256) fail('asset_identity_mismatch');
    if (!shared.has(file.output.toLowerCase())) fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
    const id = assetIdentity(target);
    if (id.sha256 !== file.sourceSha256 || id.bytes !== file.bytes) fail('asset_identity_mismatch');
    file.outputSha256 = id.sha256;
  }
  const pending = plan.edges.filter(x => x.status === 'RESOLVED');
  const candidateParent = edge => path.join(candidateDirectory, 'app', edge.source.replace(/\.(?:ts|tsx)$/, '.js'));
  const outcomes = nodeResolveOnly(pending.map(x => ({ parent: candidateParent(x), specifier: x.specifier, mode: x.mode })));
  for (let i = 0; i < pending.length; i++) {
    const edge = pending[i], result = outcomes[i];
    if (result.error) fail('js_candidate_resolution_mismatch');
    const expected = path.join(candidateDirectory, 'app', edge.target);
    if (typeof result.target !== 'string' || !within(path.join(candidateDirectory, 'app/node_modules'), result.target)) fail('js_development_path_escape');
    if (!fs.existsSync(result.target) || fs.realpathSync.native(result.target).toLowerCase() !== fs.realpathSync.native(expected).toLowerCase()) fail('js_candidate_resolution_mismatch');
    edge.candidateTarget = rel(candidateDirectory, result.target); edge.NODE_ENTRY_RESOLUTION_VERIFIED = true;
  }
  windowsNoReparse([...plan.selected, ...sharedAssets.files].map(x => path.join(candidateDirectory, x.output)));
  if (sharedAssets.files.some(x => assetIdentity(path.join(plan.sourceRoot, x.source)).sha256 !== x.sourceSha256 ||
      assetIdentity(path.join(candidateDirectory, x.output)).sha256 !== x.outputSha256) ||
      assetIdentity(path.join(plan.sourceRoot, 'package-lock.json')).sha256 !== plan.lockSha256 || plan.selected.some(x => assetIdentity(path.join(plan.sourceRoot, x.source)).sha256 !== x.sourceSha256 ||
      assetIdentity(path.join(candidateDirectory, x.output)).sha256 !== x.outputSha256)) fail('asset_identity_mismatch');
  const packages = plan.packages.map(({ absolute, pkg, ...record }) => ({ ...record, PACKAGE_STAGED: true,
    PACKAGE_FILES_VERIFIED: true, TRANSITIVE_EDGES_RESOLVED: plan.edges.filter(x => x.owner === record.root && x.status === 'RESOLVED').length,
    NODE_ENTRY_RESOLUTION_VERIFIED: plan.edges.some(x => x.targetPackage === record.root && x.NODE_ENTRY_RESOLUTION_VERIFIED),
    DEVELOPMENT_PATH_ESCAPE: false }));
  const graph = { format: 'gateway-js-dependency-staging/v1', packages, files: plan.selected, edges: plan.edges,
    limits: ['STATIC_LITERAL_AND_DECLARED_EDGES_ONLY', 'OPTIONAL_PEER_DYNAMIC_AND_RUNTIME_RESOURCE_SELECTION_UNRESOLVED',
      'NATIVE_LOAD_NOT_EXECUTED', 'LOCK_METADATA_NOT_TARBALL_TRUST', 'NONATOMIC_TOCTOU_REMAINS'],
    TRANSITIVE_CLOSURE_PROVEN: false, NATIVE_LOAD_VERIFIED: false, DEVELOPMENT_PATH_ESCAPE: false };
  const bytes = `${JSON.stringify(graph, null, 2)}\n`;
  if (Buffer.byteLength(bytes) > 32 * 1024 * 1024) fail('js_resource_limit');
  const graphPath = 'js-dependency-graph.json';
  fs.writeFileSync(path.join(candidateDirectory, graphPath), bytes, { flag: 'wx' });
  return { graphPath, graphSha256: sha(bytes), packagesDiscovered: packages.length, packagesStaged: packages.length,
    stagedFiles: plan.selected.length, stagedBytes: plan.selected.reduce((n, x) => n + x.bytes, 0),
    resolvedEdges: pending.length, unresolvedEdges: plan.edges.filter(x => x.status === 'UNRESOLVED').length,
    NODE_ENTRY_RESOLUTION_VERIFIED: pending.length > 0, DEVELOPMENT_PATH_ESCAPE: false, TRANSITIVE_CLOSURE_PROVEN: false, NATIVE_LOAD_VERIFIED: false };
}

export async function buildGatewayCandidate(options) {
  environment();
  const { scope, sourceRoot, outputParent, stageAssets, stageJsDependencies } = checkedOptions(options);
  if (stageAssets) windowsNoReparse([scope, sourceRoot, outputParent]);
  const assetPlan = stageAssets ? prepareAssetStaging(sourceRoot) : null;
  const tool = tools();
  const graph = analyze(sourceRoot, tool.ts);
  const jsPlan = stageJsDependencies ? prepareJsStaging(sourceRoot, graph, assetPlan, tool.ts) : null;
  const dependencies = dependencyIdentityReader(), resolutionCache = new Map();
  const externalDependencies = graph.imports.filter(x => x.status === 'EXTERNAL').map(edge => {
    const key = JSON.stringify([edge.specifier, edge.kind === 'require' ? 'require' : 'import']);
    if (!resolutionCache.has(key)) resolutionCache.set(key, external(sourceRoot, edge, dependencies));
    return { ...resolutionCache.get(key), ...edge, status: resolutionCache.get(key).status };
  });
  const nativeDependencies = ['node_modules/sqlite-vec-windows-x64/vec0.dll',
    'node_modules/@node-rs/jieba-win32-x64-msvc/jieba.win32-x64-msvc.node'].map(p => asset(sourceRoot, p, dependencies.identify));
  const resources = ['node_modules/@node-rs/jieba/dict.txt', 'node_modules/@node-rs/jieba/idf.txt',
    'node_modules/@tencentdb-agent-memory/tcvdb-text/data/bm25_zh_default.json',
    'node_modules/@tencentdb-agent-memory/tcvdb-text/data/bm25_en_default.json',
    'node_modules/@tencentdb-agent-memory/tcvdb-text/data/stopwords.txt',
    'src/metadata/config/metadata_config_params.json'].map(p => asset(sourceRoot, p, dependencies.identify));
  const missingPrivateModules = graph.imports.filter(x => x.status === 'MISSING' && x.specifier.includes('integrations/'));
  const blockers = ['external_dependency_closure_unverified', 'native_loading_unverified', 'resource_packaging_unverified',
    'conditional_exclusions_unverified', 'runtime_configuration_unisolated', 'static_candidate_not_release_validation'];
  if (graph.imports.some(x => x.status === 'MISSING')) blockers.push('missing_local_modules');
  if (graph.imports.some(x => x.status === 'AMBIGUOUS')) blockers.push('ambiguous_local_modules');
  if (graph.nonliteral.length) blockers.push('nonliteral_dynamic_loading');
  const compiled = [], diagnostics = [];
  for (const source of graph.sources) {
    try {
      const result = tool.esbuild.transformSync(source.text, {
        loader: path.extname(source.file).slice(1), format: 'esm', target: 'node24',
        sourcefile: source.name, sourcemap: false, legalComments: 'none',
      });
      compiled.push({ source: source.name, sourceSha256: source.sha256, sourceBytes: source.bytes,
        output: `app/${source.name.replace(/\.(?:ts|tsx|jsx)$/, '.js')}`, outputSha256: sha(result.code),
        outputBytes: Buffer.byteLength(result.code), code: result.code });
    } catch (error) {
      diagnostics.push({ code: 'compilation_failed', source: source.name,
        locations: (error.errors ?? []).map(x => ({ line: x.location?.line ?? null, column: x.location?.column ?? null })) });
    }
  }
  // Detect source drift in this window; this still cannot defeat hostile concurrent mutation.
  if (graph.sources.some(x => identity(x.file).sha256 !== x.sha256)) fail('source_changed_during_build');
  const outputs = new Set();
  for (const item of compiled) {
    const key = item.output.toLowerCase();
    if (outputs.has(key)) diagnostics.push({ code: 'output_collision', source: item.source });
    outputs.add(key);
  }
  const success = diagnostics.length === 0;
  if (!success) blockers.push('candidate_compilation_failed');
  const report = {
    format: FORMAT, createdUTC: new Date().toISOString(), sourceOrigin: sourceRoot === PROJECT ? 'PROJECT_TREE' : 'ISOLATED_FIXTURE',
    entry: ENTRY, entryOutput: 'app/src/gateway/server.js',
    CANDIDATE_BUILD_SUCCESS: success, buildExitCode: success ? 0 : 1,
    buildTool: { name: 'esbuild', version: tool.versions.esbuild, typescriptVersion: tool.versions.typescript,
      lockVersionMatched: true, lockSha256: tool.lockSha256, jsEntrypoints: tool.jsEntrypoints,
      executableIdentity: tool.executable, transformCalls: graph.sources.length },
    node: { version: process.version, platform: process.platform, architecture: process.arch,
      moduleABI: process.versions.modules, napi: process.versions.napi, runtimeCompatibility: 'NOT_LOAD_VERIFIED' },
    runtimeExecution: 'NOT_EXECUTED', cliStartup: 'NOT_PROVEN_BY_EXECUTION',
    sources: graph.sources.map(x => ({ source: x.name, sourceSha256: x.sha256, sourceBytes: x.bytes })),
    modules: success ? compiled.map(({ code, ...record }) => record) : [],
    imports: graph.imports, literalDynamicImports: graph.imports.filter(x => x.kind === 'dynamic-import'),
    nonliteralDynamicImports: graph.nonliteral, missingPrivateModules, externalDependencies, nativeDependencies, resources,
    conditionalDependencies: ['Factory', 'Redis', 'COS', 'Observability', 'MongoDB', 'OpenClaw', 'node-llama-cpp']
      .map(name => ({ name, exclusion: 'NOT_PROVEN' })),
    configAndEnvironment: { runtimeIsolation: 'NOT_PROVEN', risks: ['NODE_OPTIONS', 'NODE_PATH',
      'NAPI_RS_NATIVE_LIBRARY_PATH', 'CWD', 'HOME', 'config_search_fallback', 'user_module_and_transform_cache'],
      compilerEnvironmentCheck: 'CURRENT_PROCESS_ONLY_NOT_BOOTSTRAP_PROTECTION' },
    analysisLimits: [stageJsDependencies ? 'external_transitive_dependencies_not_exhaustively_traversed' : 'external_transitive_dependencies_not_traversed', 'exports_patterns_and_custom_conditions_not_exhaustive',
      'require_aliases_eval_and_runtime_generated_paths_not_exhaustive', 'all_native_modules_and_resources_not_exhaustive',
      'source_and_filesystem_snapshot_nonatomic', 'no_protected_runtime_loader', 'tool_version_match_is_not_trusted_toolchain_integrity'],
    diagnostics, blockers, closureGateExitCode: 2, RELEASE_DEPENDENCY_CLOSURE_COMPLETE: false, RELEASE_ELIGIBLE: false,
  };
  const bytes = `${JSON.stringify(report, null, 2)}\n`;
  if (Buffer.byteLength(bytes) > MAX_REPORT) fail('report_resource_limit');
  const candidateDirectory = fs.mkdtempSync(path.join(outputParent, 'gateway-js-candidate-'));
  if (stageAssets) windowsNoReparse([candidateDirectory]);
  // A failed/partial write is never returned as a successful candidate. No existing tree is cleaned.
  if (success) {
    const parents = [...new Set(compiled.map(item => path.dirname(path.join(candidateDirectory, item.output))))];
    for (const parent of parents) fs.mkdirSync(parent, { recursive: true });
    if (stageAssets) windowsNoReparse(parents);
    for (const item of compiled) {
      const file = path.join(candidateDirectory, item.output);
      fs.writeFileSync(file, item.code, { flag: 'wx' });
    }
    fs.writeFileSync(path.join(candidateDirectory, 'app/package.json'), '{"type":"module","private":true}\n', { flag: 'wx' });
  }
  if (assetPlan && success) report.assetStaging = copyAssetStaging(assetPlan, sourceRoot, candidateDirectory);
  else report.assetStaging = { requested: stageAssets, PACKAGE_FILES_STAGED: false, PACKAGE_TRANSITIVE_CLOSURE_PROVEN: false, NATIVE_LOAD_VERIFIED: false };
  if (jsPlan && success) report.jsDependencyStaging = copyJsStaging(jsPlan, candidateDirectory, report.assetStaging);
  const finalBytes = `${JSON.stringify(report, null, 2)}\n`;
  if (Buffer.byteLength(finalBytes) > MAX_REPORT) fail('report_resource_limit');
  const reportPath = path.join(candidateDirectory, 'closure-report.json');
  fs.writeFileSync(reportPath, finalBytes, { flag: 'wx' });
  return Object.freeze({ candidateDirectory, reportPath, reportSha256: sha(finalBytes), buildExitCode: report.buildExitCode,
    CANDIDATE_BUILD_SUCCESS: success, RELEASE_DEPENDENCY_CLOSURE_COMPLETE: false, RELEASE_ELIGIBLE: false });
}

export async function checkCandidateClosure(reportPath) {
  environment();
  const scope = authorizedScope();
  const file = checkedPath(reportPath, 'report_path_invalid', false);
  if (!within(scope, file) || fs.statSync(file).size > MAX_REPORT) fail('report_path_invalid');
  const report = JSON.parse(fs.readFileSync(file, 'utf8'));
  // Untrusted JSON cannot grant release. This version has no complete external closure or protected loader.
  return { exitCode: 2, RELEASE_DEPENDENCY_CLOSURE_COMPLETE: false, RELEASE_ELIGIBLE: false,
    blockers: report.format === FORMAT && Array.isArray(report.blockers) && report.blockers.length <= BLOCKERS.size &&
      report.blockers.every(code => typeof code === 'string' && BLOCKERS.has(code))
      ? [...report.blockers, 'diagnostic_report_is_not_release_authority'] : ['invalid_or_untrusted_report'] };
}

async function main() {
  const args = process.argv.slice(2);
  const stageJsDependencies = args[0] === '--with-js-dependencies';
  const stageAssets = stageJsDependencies || args[0] === '--with-assets';
  if (stageAssets) args.shift();
  if (args.length === 2 && args[0] === '--check-closure') {
    const decision = await checkCandidateClosure(args[1]); console.log(JSON.stringify(decision)); process.exitCode = decision.exitCode; return;
  }
  if (args.length !== 4 || args[0] !== '--source-root' || args[2] !== '--output-parent') fail('options_invalid');
  const result = await buildGatewayCandidate({ sourceRoot: args[1], outputParent: args[3], ...(stageAssets ? { stageAssets: true } : {}),
    ...(stageJsDependencies ? { stageJsDependencies: true } : {}) });
  console.log(JSON.stringify(result)); process.exitCode = result.buildExitCode;
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => { console.log(JSON.stringify({ error: /^[a-z_]+$/.test(error.message) ? error.message : 'candidate_build_failed' })); process.exitCode = 1; });
}

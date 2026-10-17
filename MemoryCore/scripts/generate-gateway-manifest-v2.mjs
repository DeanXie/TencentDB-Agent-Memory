// Candidate content inventory only. No package execution, issuer trust or release authority.
// Checks are non-atomic and do not provide protected runtime loading against concurrent writers.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
const LIMITS = Object.freeze({ manifest: 8 * 1024 * 1024, files: 16384, directories: 16384, file: 256 * 1024 * 1024, total: 1024 * 1024 * 1024, depth: 32 });
const fail = code => { throw new Error(code); };
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const digest = s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const within = (r, p) => { const x = path.relative(r, p); return x === '' || (x !== '..' && !x.startsWith(`..${path.sep}`) && !path.isAbsolute(x)); };
function member(p) {
  return typeof p === 'string' && p.length > 0 && p.length <= 2048 && p.split('/').length <= LIMITS.depth && p.split('/').every(s =>
    s.length > 0 && s.length <= 255 && s !== '.' && s !== '..' && !/[. ]$/.test(s) && /^[a-z0-9._@+-]+$/i.test(s) &&
    !/^(con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\.|$)/i.test(s));
}
function absolute(raw) {
  if (typeof raw !== 'string' || raw.length > 32760 || !/^[a-z]:[\\/]/i.test(raw) ||
      raw.slice(3).split(/[\\/]/).some(s => !s || s === '.' || s === '..' || /[. ]$/.test(s) || /[<>:"|?*\x00-\x1f]/.test(s) || /^(con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)/i.test(s))) fail('path_invalid');
  return path.resolve(raw);
}
function checkedDirectory(raw) {
  const p = absolute(raw);
  const ancestors = [];
  for (let current = p; ; current = path.dirname(current)) { ancestors.push(current); if (current === path.dirname(current)) break; }
  // Inspect drive-to-leaf before resolving or enumerating through an unchecked ancestor.
  windowsMetadata(ancestors.reverse());
  for (let current = p; ; current = path.dirname(current)) {
    const s = fs.lstatSync(current); if (s.isSymbolicLink()) fail('reparse_rejected'); if (!s.isDirectory()) fail('path_invalid');
    if (current === path.dirname(current)) break;
  }
  // Node's resolved spelling is a consistency check, not a runtime trust proof. Rust separately
  // performs Win32 long-name and handle identity checks for root and every enumerated directory.
  if (fs.realpathSync.native(p).toLowerCase() !== p.toLowerCase()) fail('path_alias_rejected');
  return p;
}
function windowsMetadata(paths) {
  // Fixed command, path values on stdin, no command interpolation. Reject every reparse tag and ADS.
  const script = `$ErrorActionPreference='Stop'; try { $paths=ConvertFrom-Json ([Console]::In.ReadToEnd()); foreach($p in $paths){ if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){[Console]::Out.Write('reparse_rejected');exit 2}; foreach($s in (Get-Item -LiteralPath $p -Stream * -ErrorAction Stop)){if($s.Stream -ne ':$DATA'){[Console]::Out.Write('alternate_stream_rejected');exit 2}} }; [Console]::Out.Write('ok') } catch { [Console]::Out.Write('filesystem_unavailable');exit 2 }`;
  // Explicit supported host installation, NOT SystemRoot/PATH supplied by a candidate caller.
  // Other Windows installations fail closed until independently approved; this is not an issuer.
  const system = 'C:\\Windows';
  const r = spawnSync(path.join(system, 'System32/WindowsPowerShell/v1.0/powershell.exe'),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { input: JSON.stringify(paths), encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 65536,
      env: { SystemRoot: system, windir: system, SystemDrive: 'C:', PATH: path.join(system, 'System32'),
        PSModulePath: path.join(system, 'System32/WindowsPowerShell/v1.0/Modules'),
        PSModuleAnalysisCachePath: path.join(os.tmpdir(), 'manifest-v2-powershell-cache'), TEMP: os.tmpdir(), TMP: os.tmpdir() } });
  if (r.status !== 0 || r.stdout !== 'ok') fail(['reparse_rejected', 'alternate_stream_rejected'].includes(r.stdout) ? r.stdout : 'filesystem_unavailable');
}
function identity(file, expected) {
  const fd = fs.openSync(file, 'r'); const hash = crypto.createHash('sha256'); let size = 0;
  try {
    const b = Buffer.alloc(65536); let n;
    while ((n = fs.readSync(fd, b, 0, b.length, null)) > 0) { size += n; if (size > expected || size > LIMITS.file) fail('file_changed'); hash.update(b.subarray(0, n)); }
    if (size !== expected) fail('file_changed');
    return { size, sha256: hash.digest('hex') };
  } finally { fs.closeSync(fd); }
}
function kind(p) {
  p = p.toLowerCase();
  if (['closure-report.json', 'js-dependency-graph.json'].includes(p)) return 'report';
  if (/\.(node|dll)$/.test(p)) return 'native';
  if (p.endsWith('.json')) return 'metadata';
  if (p.startsWith('app/src/') && p.endsWith('.js')) return 'gateway-js';
  if (/\.(js|mjs|cjs)$/.test(p)) return 'package-js';
  return 'resource';
}
function boundedJson(root, name, cap) {
  const file = path.join(root, name), size = fs.lstatSync(file).size;
  if (size > cap) fail('resource_limit');
  const fd = fs.openSync(file, 'r');
  try { const bytes = Buffer.alloc(size + 1), n = fs.readSync(fd, bytes, 0, bytes.length, 0); if (n !== size) fail('file_changed'); return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, n))); }
  catch (e) { if (['resource_limit', 'file_changed'].includes(e.message)) throw e; fail('report_invalid'); }
  finally { fs.closeSync(fd); }
}
function facts(report, graph, files) {
  const n = report.node, b = report.buildTool, s = report.jsDependencyStaging;
  const get = p => files.find(f => f.path === p);
  if (report.format !== 'gateway-js-candidate-closure/v1' || report.entryOutput !== 'app/src/gateway/server.js' ||
      report.CANDIDATE_BUILD_SUCCESS !== true || report.buildExitCode !== 0 || report.closureGateExitCode !== 2 ||
      report.RELEASE_ELIGIBLE !== false || report.RELEASE_DEPENDENCY_CLOSURE_COMPLETE !== false || !get(report.entryOutput) ||
      !n || n.platform !== 'win32' || n.architecture !== 'x64' || n.runtimeCompatibility !== 'NOT_LOAD_VERIFIED' ||
      !/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-z0-9.-]+)?$/i.test(n.version) || n.version.length > 40 ||
      typeof n.moduleABI !== 'string' || !/^[0-9]{1,10}$/.test(n.moduleABI) || typeof n.napi !== 'string' || !/^[0-9]{1,10}$/.test(n.napi) ||
      !b || b.name !== 'esbuild' || typeof b.version !== 'string' || b.version.length > 40 || typeof b.typescriptVersion !== 'string' || b.typescriptVersion.length > 40 || b.lockVersionMatched !== true || !digest(b.lockSha256) ||
      !Number.isSafeInteger(b.transformCalls) || b.transformCalls < 1 || b.transformCalls > LIMITS.files ||
      !Array.isArray(b.jsEntrypoints) || b.jsEntrypoints.length < 1 || b.jsEntrypoints.length > 8 ||
      !b.jsEntrypoints.every(x => member(x.path) && digest(x.sha256) && Number.isSafeInteger(x.bytes) && x.bytes >= 0 && x.bytes <= LIMITS.file) ||
      !b.executableIdentity || !digest(b.executableIdentity.sha256) || !Number.isSafeInteger(b.executableIdentity.bytes) || b.executableIdentity.bytes < 0 || b.executableIdentity.bytes > LIMITS.file ||
      !s || s.graphPath !== 'js-dependency-graph.json' || s.graphSha256 !== get(s.graphPath)?.sha256 || !Number.isSafeInteger(s.unresolvedEdges) || s.unresolvedEdges < 0 || s.unresolvedEdges > 100000 ||
      s.TRANSITIVE_CLOSURE_PROVEN !== false || s.NATIVE_LOAD_VERIFIED !== false || s.DEVELOPMENT_PATH_ESCAPE !== false ||
      graph.format !== 'gateway-js-dependency-staging/v1' || graph.TRANSITIVE_CLOSURE_PROVEN !== false || graph.NATIVE_LOAD_VERIFIED !== false || graph.DEVELOPMENT_PATH_ESCAPE !== false ||
      !Array.isArray(graph.edges) || graph.edges.length > 100000 || graph.edges.filter(e => e.status === 'UNRESOLVED').length !== s.unresolvedEdges) fail('report_invalid');
  // Closed projection, never spread caller-controlled metadata into the V2 schema.
  return { node: { version: n.version, platform: n.platform, architecture: n.architecture, moduleABI: n.moduleABI, napi: n.napi, runtimeCompatibility: n.runtimeCompatibility },
    build_tool: { name: b.name, version: b.version, typescriptVersion: b.typescriptVersion, lockVersionMatched: b.lockVersionMatched, lockSha256: b.lockSha256,
      jsEntrypoints: b.jsEntrypoints.map(x => ({ path: x.path, bytes: x.bytes, sha256: x.sha256 })), executableIdentity: { bytes: b.executableIdentity.bytes, sha256: b.executableIdentity.sha256 }, transformCalls: b.transformCalls },
    closure: { path: 'closure-report.json', sha256: get('closure-report.json').sha256, graph_path: s.graphPath, graph_sha256: s.graphSha256, unresolved_edges: s.unresolvedEdges } };
}
export function generateGatewayManifestV2(options) {
  if (process.platform !== 'win32') fail('platform_unavailable');
  if (!options || Object.getPrototypeOf(options) !== Object.prototype || Reflect.ownKeys(options).sort().join(',') !== 'candidateRoot,manifestPath') fail('options_invalid');
  for (const name of ['candidateRoot', 'manifestPath']) { const d = Object.getOwnPropertyDescriptor(options, name); if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'string') fail('options_invalid'); }
  const root = checkedDirectory(options.candidateRoot), output = absolute(options.manifestPath), parent = checkedDirectory(path.dirname(output));
  const scope = checkedDirectory(process.env.GATEWAY_CANDIDATE_TEMP_ROOT);
  if (!within(path.resolve(os.tmpdir()), scope) || !within(scope, root) || !within(scope, parent) || within(root, output)) fail('output_scope_invalid');
  if (fs.existsSync(output)) fail('output_exists');
  const files = [], directories = [], paths = [root, parent], aliases = new Set(); let total = 0, count = 0;
  for (let current = root; current !== path.dirname(current); current = path.dirname(current)) paths.push(current);
  // Breadth-first batches keep all-tag checks cheap without entering unchecked directories.
  let pending = [''];
  while (pending.length) {
    const next = [], batch = [];
    for (const rel of pending) for (const child of fs.readdirSync(path.join(root, rel))) {
      if (++count > LIMITS.files + LIMITS.directories) fail('resource_limit');
      const p = rel ? `${rel}/${child}` : child; if (!member(p)) fail('path_invalid');
      const lower = p.toLowerCase(); if (aliases.has(lower)) fail('path_alias_rejected'); aliases.add(lower);
      const file = path.join(root, p), s = fs.lstatSync(file); if (s.isSymbolicLink()) fail('reparse_rejected'); paths.push(file); batch.push(file);
      if (s.isDirectory()) { if (directories.length >= LIMITS.directories) fail('resource_limit'); directories.push(p); next.push(p); }
      else { if (!s.isFile()) fail('file_type_invalid'); if (s.size > LIMITS.file || files.length >= LIMITS.files || (total += s.size) > LIMITS.total) fail('resource_limit'); files.push({ path: p, size: s.size, kind: kind(p) }); }
    }
    if (batch.length) windowsMetadata(batch);
    pending = next;
  }
  windowsMetadata([...new Set(paths)]);
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0); directories.sort();
  for (const file of files) file.sha256 = identity(path.join(root, file.path), file.size).sha256;
  const report = boundedJson(root, 'closure-report.json', 4 * 1024 * 1024), graph = boundedJson(root, 'js-dependency-graph.json', 32 * 1024 * 1024);
  const m = { format_version: 2, platform: 'windows', architecture: 'x86_64', validation_scope: 'candidate-static-tree', production_eligible: false,
    entry: 'app/src/gateway/server.js', node_identity_scope: 'reported-target-not-packaged', ...facts(report, graph, files),
    runtime: { dependency_closure_proven: false, native_load_verified: false, config_isolation: false, protected_service: false, trusted_issuer: false }, directories, files };
  const bytes = Buffer.from(`${JSON.stringify(m, null, 2)}\n`); if (bytes.length > LIMITS.manifest) fail('resource_limit');
  // Publication is create-only and happens after full checks. A failed/partial write grants nothing;
  // consumers must independently parse and validate the complete manifest and tree.
  fs.writeFileSync(output, bytes, { flag: 'wx' });
  return Object.freeze({ manifestPath: output, manifestSha256: sha(bytes), fileCount: files.length, directoryCount: directories.length, totalBytes: total, productionEligible: false });
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const a = process.argv.slice(2); if (a.length !== 4 || a[0] !== '--candidate-root' || a[2] !== '--manifest') fail('options_invalid');
    console.log(JSON.stringify(generateGatewayManifestV2({ candidateRoot: a[1], manifestPath: a[3] })));
  } catch (e) { console.log(JSON.stringify({ error: /^[a-z_]+$/.test(e.message) ? e.message : 'manifest_generation_failed' })); process.exitCode = 1; }
}

// Offline R1 synthetic candidate generator; never launches or installs anything.
// This deliberately cannot package the real Gateway: its dynamic/native closure is unproven.
// Path checks precede reads/writes and do not resist a concurrently hostile filesystem writer.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const fixed = Object.freeze({
  'config/gateway.json': ['config', '{"synthetic":true}\n'],
  'gateway/server.ts': ['entry', 'export const syntheticGateway = true;\n'],
  'loader/tsx.mjs': ['loader', 'export {};\n'],
  'runtime/node.exe': ['runtime', 'R1_SYNTHETIC_NODE_NOT_EXECUTABLE\n'],
});
const fail = code => { throw new Error(code); };
function safeRelative(p) {
  return typeof p === 'string' && p.length <= 200 && p.length > 0 && p.split('/').length <= 8 && p.split('/').every(s => {
    const stem = s.split('.')[0];
    return s.length <= 100 && /^[a-z0-9][a-z0-9._-]*$/.test(s) && !s.endsWith('.') &&
      !/^(con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])$/.test(stem);
  });
}
function template(p) {
  if (Object.hasOwn(fixed, p)) return fixed[p];
  if (p.startsWith('modules/') && p.endsWith('.mjs')) return ['module', 'export const syntheticDependency = true;\n'];
  if (p.startsWith('native/') && p.endsWith('.node')) return ['native', 'R1_SYNTHETIC_NATIVE_NOT_LOADABLE\n'];
  fail('manifest_invalid');
}
function beneath(parent, child) {
  const rel = path.relative(parent, child);
  return rel !== '' && !rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel);
}
function checkAncestors(p) {
  for (let current = p; ; current = path.dirname(current)) {
    const info = fs.lstatSync(current);
    if (info.isSymbolicLink()) fail('reparse_rejected');
    if (current === path.dirname(current)) break;
  }
  // Resolving a different target is also a rejection; never copy through a mapping.
  if (fs.realpathSync.native(p).toLowerCase() !== path.resolve(p).toLowerCase()) fail('reparse_rejected');
}
function temporaryDirectory(p) {
  if (typeof p !== 'string' || !path.isAbsolute(p) || !beneath(os.tmpdir(), p) || p.split(/[\\/]/).includes('..')) fail('path_invalid');
  checkAncestors(p);
  if (!fs.lstatSync(p).isDirectory()) fail('path_invalid');
}

export function packageCandidate(spec) {
  try {
    if (spec?.mode === 'gateway') fail('gateway_dependency_closure_unproven');
    if (!spec || Object.getPrototypeOf(spec) !== Object.prototype ||
        Object.keys(spec).sort().join(',') !== 'files,mode,outputParent,sourceRoot' || spec.mode !== 'synthetic') fail('manifest_invalid');
    const { sourceRoot, outputParent, files } = spec;
    if (!Array.isArray(files) || files.length < 4 || files.length > 256 ||
        Reflect.ownKeys(files).length !== files.length + 1) fail('manifest_invalid');
    const paths = [];
    for (let i = 0; i < files.length; i++) {
      const d = Object.getOwnPropertyDescriptor(files, String(i));
      if (!d || !Object.hasOwn(d, 'value') || !safeRelative(d.value)) fail('path_invalid');
      template(d.value); paths.push(d.value);
    }
    paths.sort();
    if (new Set(paths).size !== paths.length || Object.keys(fixed).some(p => !paths.includes(p))) fail('manifest_invalid');
    const directories = new Set();
    for (const p of paths) {
      if (paths.some(other => other !== p && p.startsWith(`${other}/`))) fail('manifest_invalid');
      const parts = p.split('/');
      for (let i = 1; i < parts.length; i++) directories.add(parts.slice(0, i).join('/'));
    }
    if (directories.size + paths.length > 512) fail('resource_limit');
    temporaryDirectory(sourceRoot); temporaryDirectory(outputParent);
    if (path.relative(sourceRoot, outputParent) === '' || beneath(sourceRoot, outputParent)) fail('path_invalid');
    let total = 0;
    // Validate every input before creating output. No arbitrary data/config/module copying.
    const inputs = paths.map(p => {
      const input = path.join(sourceRoot, p);
      checkAncestors(input);
      const info = fs.lstatSync(input);
      if (!info.isFile()) fail('file_type_invalid');
      total += info.size;
      if (info.size > 65_536 || total > 1_048_576) fail('resource_limit');
      const [role, text] = template(p);
      const bytes = fs.readFileSync(input);
      if (!bytes.equals(Buffer.from(text))) fail('synthetic_content_invalid');
      return { bytes, entry: { path: p, role, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), size: bytes.length, file_type: 'regular', loadable: role !== 'config', dependencies: [] } };
    });
    const manifest = {
      format_version: 1, platform: 'windows', architecture: 'x86_64',
      scope: 'synthetic-fixture', validation_scope: 'static-tree', production_eligible: false,
      entry: 'gateway/server.ts', node: 'runtime/node.exe', loader: 'loader/tsx.mjs', config: 'config/gateway.json',
      node_version: 'synthetic', loader_version: 'synthetic', loading_policy: 'closed-synthetic-v1',
      files: inputs.map(i => i.entry),
    };
    // An I/O failure after this point may leave an incomplete new directory for diagnosis.
    // It is never returned as a successful package; publication is not atomic in R1.
    const output = fs.mkdtempSync(path.join(outputParent, 'r1-candidate-'));
    const payloadRoot = path.join(output, 'payload'); fs.mkdirSync(payloadRoot);
    for (const { bytes, entry } of inputs) {
      const destination = path.join(payloadRoot, entry.path);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, bytes, { flag: 'wx' });
    }
    const manifestPath = path.join(output, 'manifest.json');
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`, { flag: 'wx' });
    return Object.freeze({ payloadRoot, manifestPath, productionEligible: false });
  } catch (error) {
    // Never echo source contents, caller paths, raw filesystem errors or credentials.
    if (error && ['ENOENT', 'EACCES', 'EPERM', 'ENOTDIR'].includes(error.code)) fail('filesystem_unavailable');
    if (error && /^[a-z_]+$/.test(error.message)) throw error;
    fail('packaging_failed');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.shift() !== '--synthetic') fail('manifest_invalid');
    const spec = { mode: 'synthetic', files: [] };
    while (args.length) {
      const key = args.shift(); const value = args.shift();
      if (!value) fail('manifest_invalid');
      if (key === '--file') spec.files.push(value);
      else if (key === '--source-root' && spec.sourceRoot === undefined) spec.sourceRoot = value;
      else if (key === '--output-parent' && spec.outputParent === undefined) spec.outputParent = value;
      else fail('manifest_invalid');
    }
    console.log(JSON.stringify(packageCandidate(spec)));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}

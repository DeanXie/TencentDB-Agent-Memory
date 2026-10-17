//! V2 verifies bounded candidate contents, NOT dependency closure, loaded code or issuer trust.
//! All reads are path-based, point-in-time observations. Hostile replacement TOCTOU remains.
use crate::release::{
    no_extra_streams_v2 as no_extra_streams, no_reparse, validate_root_v2 as validate_root,
    ReleaseError,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};
const MAX_MANIFEST: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 16384;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_TREE: u64 = 1024 * 1024 * 1024;
type Result<T> = std::result::Result<T, ReleaseError>;
fn need(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(ReleaseError(code))
    }
}
#[derive(Debug)]
pub struct ReleaseV2Report {
    pub file_count: usize,
    pub total_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u32,
    platform: String,
    architecture: String,
    validation_scope: String,
    production_eligible: bool,
    entry: String,
    node: Node,
    node_identity_scope: String,
    build_tool: Build,
    closure: Closure,
    runtime: Runtime,
    directories: Vec<String>,
    files: Vec<Entry>,
}
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Node {
    version: String,
    platform: String,
    architecture: String,
    #[serde(rename = "moduleABI")]
    module_abi: String,
    napi: String,
    runtime_compatibility: String,
}
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Build {
    name: String,
    version: String,
    typescript_version: String,
    lock_version_matched: bool,
    lock_sha256: String,
    js_entrypoints: Vec<ToolFile>,
    executable_identity: Identity,
    transform_calls: u64,
}
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Identity {
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ToolFile {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Closure {
    path: String,
    sha256: String,
    graph_path: String,
    graph_sha256: String,
    unresolved_edges: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    dependency_closure_proven: bool,
    native_load_verified: bool,
    config_isolation: bool,
    protected_service: bool,
    trusted_issuer: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    sha256: String,
    size: u64,
    kind: String,
}
// ASCII spelling only. Case is preserved; case-folded collisions and all supplied '~' aliases
// fail closed. Actual root/ancestor short names use the shared Win32 long-name/object check.
fn path_valid(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 2048
        && p.split('/').count() <= 32
        && p.split('/').all(|s| {
            let stem = s.split('.').next().unwrap_or("").to_ascii_lowercase();
            let numbered = stem
                .strip_prefix("com")
                .or_else(|| stem.strip_prefix("lpt"));
            !s.is_empty()
                && s.len() <= 255
                && s != "."
                && s != ".."
                && !s.ends_with('.')
                && !s.ends_with(' ')
                && !matches!(
                    stem.as_str(),
                    "con" | "prn" | "aux" | "nul" | "clock$" | "conin$" | "conout$"
                )
                && !matches!(
                    numbered,
                    Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                )
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._@+-".contains(&b))
        })
}
fn digest_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn kind(p: &str) -> &'static str {
    let lower = p.to_ascii_lowercase();
    let p = lower.as_str();
    if matches!(p, "closure-report.json" | "js-dependency-graph.json") {
        "report"
    } else if p.ends_with(".node") || p.ends_with(".dll") {
        "native"
    } else if p.ends_with(".json") {
        "metadata"
    } else if p.starts_with("app/src/") && p.ends_with(".js") {
        "gateway-js"
    } else if [".js", ".mjs", ".cjs"].iter().any(|x| p.ends_with(x)) {
        "package-js"
    } else {
        "resource"
    }
}
fn hash_file(path: &Path, expected: &Entry) -> Result<()> {
    let info = no_reparse(path)?;
    no_extra_streams(path)?;
    need(
        info.is_file() && info.len() == expected.size,
        "file_identity_mismatch",
    )?;
    let mut file = fs::File::open(path).map_err(|_| ReleaseError("filesystem_unavailable"))?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| ReleaseError("filesystem_unavailable"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        need(total <= expected.size, "file_identity_mismatch")?;
        hash.update(&buffer[..n]);
    }
    need(
        total == expected.size && format!("{:x}", hash.finalize()) == expected.sha256,
        "file_identity_mismatch",
    )
}
fn visit(
    root: &Path,
    rel: &str,
    files: &mut BTreeSet<String>,
    dirs: &mut BTreeSet<String>,
    count: &mut usize,
    total: &mut u64,
) -> Result<()> {
    for child in fs::read_dir(root.join(rel)).map_err(|_| ReleaseError("filesystem_unavailable"))? {
        let child = child.map_err(|_| ReleaseError("filesystem_unavailable"))?;
        *count += 1;
        need(*count <= MAX_FILES * 2, "resource_limit")?;
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| ReleaseError("path_invalid"))?;
        let p = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        need(path_valid(&p), "path_invalid")?;
        let info = no_reparse(&child.path())?;
        no_extra_streams(&child.path())?;
        if info.is_dir() {
            need(dirs.len() < MAX_FILES, "resource_limit")?;
            validate_root(&child.path())?;
            dirs.insert(p.clone());
            visit(root, &p, files, dirs, count, total)?;
        } else {
            need(info.is_file(), "file_type_invalid")?;
            need(
                info.len() <= MAX_FILE && files.len() < MAX_FILES,
                "resource_limit",
            )?;
            *total = total
                .checked_add(info.len())
                .ok_or(ReleaseError("resource_limit"))?;
            need(*total <= MAX_TREE, "resource_limit")?;
            files.insert(p);
        }
    }
    Ok(())
}
fn read_json(root: &Path, p: &str, cap: u64) -> Result<Value> {
    let file = root.join(p);
    need(no_reparse(&file)?.len() <= cap, "resource_limit")?;
    let mut bytes = Vec::new();
    fs::File::open(file)
        .map_err(|_| ReleaseError("filesystem_unavailable"))?
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReleaseError("filesystem_unavailable"))?;
    need(bytes.len() as u64 <= cap, "resource_limit")?;
    serde_json::from_slice(&bytes).map_err(|_| ReleaseError("report_invalid"))
}
fn report_matches(root: &Path, m: &Manifest, entries: &BTreeMap<&str, &Entry>) -> Result<()> {
    let c = &m.closure;
    need(
        c.path == "closure-report.json"
            && c.graph_path == "js-dependency-graph.json"
            && c.unresolved_edges <= 100000,
        "report_invalid",
    )?;
    need(
        entries
            .get(c.path.as_str())
            .is_some_and(|x| x.sha256 == c.sha256)
            && entries
                .get(c.graph_path.as_str())
                .is_some_and(|x| x.sha256 == c.graph_sha256),
        "report_invalid",
    )?;
    let r = read_json(root, &c.path, 4 * 1024 * 1024)?;
    let node: Node =
        serde_json::from_value(r["node"].clone()).map_err(|_| ReleaseError("report_invalid"))?;
    let build: Build = serde_json::from_value(r["buildTool"].clone())
        .map_err(|_| ReleaseError("report_invalid"))?;
    let s = &r["jsDependencyStaging"];
    need(
        r["format"] == "gateway-js-candidate-closure/v1"
            && r["entryOutput"] == m.entry
            && r["CANDIDATE_BUILD_SUCCESS"] == true
            && r["buildExitCode"] == 0
            && r["closureGateExitCode"] == 2
            && r["RELEASE_ELIGIBLE"] == false
            && r["RELEASE_DEPENDENCY_CLOSURE_COMPLETE"] == false
            && node == m.node
            && build == m.build_tool
            && s["graphPath"] == c.graph_path
            && s["graphSha256"] == c.graph_sha256
            && s["unresolvedEdges"].as_u64() == Some(c.unresolved_edges)
            && s["TRANSITIVE_CLOSURE_PROVEN"] == false
            && s["NATIVE_LOAD_VERIFIED"] == false
            && s["DEVELOPMENT_PATH_ESCAPE"] == false,
        "report_invalid",
    )?;
    let graph = read_json(root, &c.graph_path, 32 * 1024 * 1024)?;
    let edges = graph["edges"]
        .as_array()
        .ok_or(ReleaseError("report_invalid"))?;
    need(
        edges.len() <= 100000
            && graph["format"] == "gateway-js-dependency-staging/v1"
            && graph["TRANSITIVE_CLOSURE_PROVEN"] == false
            && graph["NATIVE_LOAD_VERIFIED"] == false
            && graph["DEVELOPMENT_PATH_ESCAPE"] == false
            && edges.iter().filter(|e| e["status"] == "UNRESOLVED").count() as u64
                == c.unresolved_edges,
        "report_invalid",
    )
}
pub fn validate_release_v2(root: &Path, manifest: &[u8]) -> Result<ReleaseV2Report> {
    need(manifest.len() <= MAX_MANIFEST, "resource_limit")?;
    let m: Manifest =
        serde_json::from_slice(manifest).map_err(|_| ReleaseError("manifest_invalid"))?;
    need(
        m.format_version == 2
            && m.platform == "windows"
            && m.architecture == "x86_64"
            && m.validation_scope == "candidate-static-tree"
            && !m.production_eligible
            && m.entry == "app/src/gateway/server.js"
            && m.node_identity_scope == "reported-target-not-packaged"
            && !m.runtime.dependency_closure_proven
            && !m.runtime.native_load_verified
            && !m.runtime.config_isolation
            && !m.runtime.protected_service
            && !m.runtime.trusted_issuer,
        "manifest_invalid",
    )?;
    need(
        !m.files.is_empty() && m.files.len() <= MAX_FILES && m.directories.len() <= MAX_FILES,
        "resource_limit",
    )?;
    need(
        m.node.platform == "win32"
            && m.node.architecture == "x64"
            && m.node.runtime_compatibility == "NOT_LOAD_VERIFIED"
            && m.node.version.len() <= 40
            && m.node.version.starts_with('v')
            && !m.node.module_abi.is_empty()
            && m.node.module_abi.len() <= 10
            && m.node.module_abi.bytes().all(|b| b.is_ascii_digit())
            && !m.node.napi.is_empty()
            && m.node.napi.len() <= 10
            && m.node.napi.bytes().all(|b| b.is_ascii_digit())
            && m.build_tool.name == "esbuild"
            && m.build_tool.version.len() <= 40
            && m.build_tool.typescript_version.len() <= 40
            && m.build_tool.lock_version_matched
            && digest_valid(&m.build_tool.lock_sha256)
            && digest_valid(&m.build_tool.executable_identity.sha256)
            && m.build_tool.executable_identity.bytes <= MAX_FILE
            && !m.build_tool.js_entrypoints.is_empty()
            && m.build_tool.js_entrypoints.len() <= 8
            && m.build_tool.transform_calls > 0
            && m.build_tool.transform_calls <= MAX_FILES as u64
            && m.build_tool
                .js_entrypoints
                .iter()
                .all(|x| path_valid(&x.path) && digest_valid(&x.sha256) && x.bytes <= MAX_FILE),
        "manifest_invalid",
    )?;
    let mut aliases = BTreeSet::new();
    let mut entries = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    let mut previous = "";
    let mut total = 0u64;
    for item in &m.files {
        need(path_valid(&item.path), "path_invalid")?;
        need(
            aliases.insert(item.path.to_ascii_lowercase()),
            "path_alias_rejected",
        )?;
        need(
            item.path.as_str() > previous
                && digest_valid(&item.sha256)
                && item.kind == kind(&item.path),
            "manifest_invalid",
        )?;
        previous = &item.path;
        need(item.size <= MAX_FILE, "resource_limit")?;
        total = total
            .checked_add(item.size)
            .ok_or(ReleaseError("resource_limit"))?;
        need(total <= MAX_TREE, "resource_limit")?;
        entries.insert(item.path.as_str(), item);
    }
    previous = "";
    for p in &m.directories {
        need(path_valid(p), "path_invalid")?;
        need(
            !entries.contains_key(p.as_str()) && p.as_str() > previous,
            "manifest_invalid",
        )?;
        need(
            aliases.insert(p.to_ascii_lowercase()),
            "path_alias_rejected",
        )?;
        previous = p;
        dirs.insert(p.clone());
    }
    for p in entries
        .keys()
        .copied()
        .chain(dirs.iter().map(String::as_str))
    {
        if let Some((parent, _)) = p.rsplit_once('/') {
            need(dirs.contains(parent), "manifest_invalid")?;
        }
    }
    need(entries.contains_key(m.entry.as_str()), "manifest_invalid")?;
    validate_root(root)?;
    no_extra_streams(root)?;
    let mut actual_files = BTreeSet::new();
    let mut actual_dirs = BTreeSet::new();
    let mut actual_total = 0;
    visit(
        root,
        "",
        &mut actual_files,
        &mut actual_dirs,
        &mut 0,
        &mut actual_total,
    )?;
    need(
        actual_files == entries.keys().map(|p| p.to_string()).collect() && actual_dirs == dirs,
        "tree_mismatch",
    )?;
    for x in &m.files {
        hash_file(&root.join(&x.path), x)?;
    }
    report_matches(root, &m, &entries)?;
    Ok(ReleaseV2Report {
        file_count: m.files.len(),
        total_bytes: total,
    })
}

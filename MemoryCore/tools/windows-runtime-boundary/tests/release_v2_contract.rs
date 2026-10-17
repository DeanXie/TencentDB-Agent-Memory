use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use windows_runtime_boundary::{validate_release, validate_release_v2};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
struct Fixture {
    root: PathBuf,
    manifest: Value,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "v2-rust-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let graph = json!({"format":"gateway-js-dependency-staging/v1","edges":[{"status":"UNRESOLVED"}],"TRANSITIVE_CLOSURE_PROVEN":false,"NATIVE_LOAD_VERIFIED":false,"DEVELOPMENT_PATH_ESCAPE":false});
        let graph_bytes = serde_json::to_vec(&graph).unwrap();
        let node = json!({"version":"v24.16.0","platform":"win32","architecture":"x64","moduleABI":"137","napi":"10","runtimeCompatibility":"NOT_LOAD_VERIFIED"});
        let build = json!({"name":"esbuild","version":"0.28.2","typescriptVersion":"6.0.3","lockVersionMatched":true,"lockSha256":"1".repeat(64),"jsEntrypoints":[{"path":"node_modules/esbuild/lib/main.js","bytes":1,"sha256":"2".repeat(64)}],"executableIdentity":{"bytes":1,"sha256":"3".repeat(64)},"transformCalls":1});
        let report = json!({"format":"gateway-js-candidate-closure/v1","entryOutput":"app/src/gateway/server.js","CANDIDATE_BUILD_SUCCESS":true,"buildExitCode":0,"buildTool":build,"node":node,"jsDependencyStaging":{"graphPath":"js-dependency-graph.json","graphSha256":hash(&graph_bytes),"unresolvedEdges":1,"TRANSITIVE_CLOSURE_PROVEN":false,"NATIVE_LOAD_VERIFIED":false,"DEVELOPMENT_PATH_ESCAPE":false},"closureGateExitCode":2,"RELEASE_ELIGIBLE":false,"RELEASE_DEPENDENCY_CLOSURE_COMPLETE":false});
        let report_bytes = serde_json::to_vec(&report).unwrap();
        let mut f = Self {
            root,
            manifest: json!({"format_version":2,"platform":"windows","architecture":"x86_64","validation_scope":"candidate-static-tree","production_eligible":false,"entry":"app/src/gateway/server.js","node":node,"node_identity_scope":"reported-target-not-packaged","build_tool":build,"closure":{"path":"closure-report.json","sha256":hash(&report_bytes),"graph_path":"js-dependency-graph.json","graph_sha256":hash(&graph_bytes),"unresolved_edges":1},"runtime":{"dependency_closure_proven":false,"native_load_verified":false,"config_isolation":false,"protected_service":false,"trusted_issuer":false},"directories":[],"files":[]}),
        };
        f.put("closure-report.json", &report_bytes, "report");
        f.put("js-dependency-graph.json", &graph_bytes, "report");
        f.put("app/src/gateway/server.js", b"export {};\n", "gateway-js");
        f.put(
            "app/node_modules/@scope/pkg/package.json",
            b"{}",
            "metadata",
        );
        f.put(
            "app/node_modules/@scope/pkg/native.node",
            b"INERT_NATIVE",
            "native",
        );
        f.put(
            "app/node_modules/@scope/pkg/dict.txt",
            b"INERT_RESOURCE",
            "resource",
        );
        f.sort();
        f
    }
    fn put(&mut self, p: &str, b: &[u8], kind: &str) {
        fs::create_dir_all(self.root.join(p).parent().unwrap()).unwrap();
        fs::write(self.root.join(p), b).unwrap();
        self.manifest["files"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":p,"sha256":hash(b),"size":b.len(),"kind":kind}));
    }
    fn sort(&mut self) {
        self.manifest["files"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        let mut dirs = BTreeSet::new();
        for f in self.manifest["files"].as_array().unwrap() {
            let mut p = f["path"].as_str().unwrap();
            while let Some((parent, _)) = p.rsplit_once('/') {
                dirs.insert(parent);
                p = parent;
            }
        }
        self.manifest["directories"] = json!(dirs);
    }
    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.manifest).unwrap()
    }
    fn reject(&self, code: &str) {
        assert_eq!(
            validate_release_v2(&self.root, &self.bytes())
                .unwrap_err()
                .code(),
            code
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn valid_scoped_tree_independent_hashes_and_blocked_runtime() {
    let f = Fixture::new();
    let r = validate_release_v2(&f.root, &f.bytes()).unwrap();
    assert_eq!(r.file_count, 6);
    assert!(r.total_bytes > 0);
}

#[test]
fn long_valid_candidate_paths_do_not_depend_on_legacy_win32_max_path() {
    let mut f = Fixture::new();
    let p = format!("app/{}/{}/resource.bin", "a".repeat(80), "b".repeat(80));
    f.put(&p, b"INERT_LONG_PATH", "resource");
    f.sort();
    assert!(f.root.join(&p).as_os_str().len() > 260);
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{
            Foundation::{GetLastError, INVALID_HANDLE_VALUE},
            Storage::FileSystem::{
                FindClose, FindFirstStreamW, FindStreamInfoStandard, GetLongPathNameW,
                WIN32_FIND_STREAM_DATA,
            },
        };
        for extended in [false, true] {
            let file = f.root.join(&p);
            let spelling = if extended {
                format!("\\\\?\\{}", file.display().to_string().replace('/', "\\"))
            } else {
                file.display().to_string()
            };
            let input: Vec<_> = std::ffi::OsStr::new(&spelling)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let mut out = vec![0u16; 32768];
            let mut stream = WIN32_FIND_STREAM_DATA::default();
            unsafe {
                let n = GetLongPathNameW(input.as_ptr(), out.as_mut_ptr(), out.len() as u32);
                let error = if n == 0 { GetLastError() } else { 0 };
                let handle = FindFirstStreamW(
                    input.as_ptr(),
                    FindStreamInfoStandard,
                    (&mut stream as *mut WIN32_FIND_STREAM_DATA).cast(),
                    0,
                );
                let stream_error = if handle == INVALID_HANDLE_VALUE {
                    GetLastError()
                } else {
                    0
                };
                if handle != INVALID_HANDLE_VALUE {
                    assert_ne!(FindClose(handle), 0);
                }
                println!("LONG_PATH_PROBE extended={extended} long_name_length={n} long_name_error={error} stream_error={stream_error}");
            }
        }
    }
    assert_eq!(
        validate_release_v2(&f.root, &f.bytes()).unwrap().file_count,
        7
    );
}
#[test]
fn capacity_exceeds_v1_without_relaxing_v1() {
    let mut f = Fixture::new();
    f.put("app/large.bin", &vec![0; 65537], "resource");
    for i in 0..260 {
        f.put(&format!("app/src/m{i}.js"), b"x", "gateway-js");
    }
    f.sort();
    assert_eq!(
        validate_release_v2(&f.root, &f.bytes()).unwrap().file_count,
        267
    );
    assert!(validate_release(&f.root, &f.bytes()).is_err());
}

#[test]
fn original_v1_schema_still_enforces_original_capacity_before_tree_reads() {
    let f = Fixture::new();
    let mut v1 = json!({"format_version":1,"platform":"windows","architecture":"x86_64","scope":"synthetic-fixture","validation_scope":"static-tree","production_eligible":false,"entry":"gateway/server.ts","node":"runtime/node.exe","loader":"loader/tsx.mjs","config":"config/gateway.json","node_version":"synthetic","loader_version":"synthetic","loading_policy":"closed-synthetic-v1","files":[]});
    let item = json!({"path":"modules/x.mjs","sha256":"0".repeat(64),"size":1,"role":"module","file_type":"regular","loadable":true,"dependencies":[]});
    v1["files"] = json!(vec![item.clone(); 257]);
    assert_eq!(
        validate_release(&f.root, &serde_json::to_vec(&v1).unwrap())
            .unwrap_err()
            .code(),
        "resource_limit"
    );
    v1["files"] = json!(vec![item; 4]);
    v1["files"][0]["size"] = json!(65537);
    assert_eq!(
        validate_release(&f.root, &serde_json::to_vec(&v1).unwrap())
            .unwrap_err()
            .code(),
        "resource_limit"
    );
}
#[test]
fn content_native_resource_and_report_tamper_rejected() {
    for p in [
        "app/src/gateway/server.js",
        "app/node_modules/@scope/pkg/native.node",
        "app/node_modules/@scope/pkg/dict.txt",
        "closure-report.json",
    ] {
        let f = Fixture::new();
        fs::write(f.root.join(p), b"tampered").unwrap();
        f.reject("file_identity_mismatch");
    }
}
#[test]
fn undeclared_files_rejected() {
    let f = Fixture::new();
    fs::write(f.root.join("rogue.js"), b"x").unwrap();
    f.reject("tree_mismatch");
}
#[test]
fn undeclared_empty_directory_rejected() {
    let f = Fixture::new();
    fs::create_dir(f.root.join("extra")).unwrap();
    f.reject("tree_mismatch");
}
#[test]
fn missing_file_rejected() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("app/src/gateway/server.js")).unwrap();
    f.reject("tree_mismatch");
}
#[test]
fn windows_member_aliases_and_escape_rejected() {
    for p in [
        "../x",
        "/x",
        "C:/x",
        "//host/x",
        "\\\\?\\C:\\x",
        "x:y",
        "x.",
        "x ",
        "nul.txt",
        "COM1.js",
        "lpt9",
        "a~1/x",
        "é.txt",
        "a\\b",
        "a//b",
        "a/./b",
    ] {
        let mut f = Fixture::new();
        f.manifest["files"][0]["path"] = json!(p);
        f.reject("path_invalid");
    }
}
#[test]
fn case_alias_and_duplicate_members_rejected() {
    let mut f = Fixture::new();
    let mut x = f.manifest["files"][0].clone();
    x["path"] = json!(x["path"].as_str().unwrap().to_ascii_uppercase());
    f.manifest["files"].as_array_mut().unwrap().push(x);
    f.manifest["files"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    f.reject("path_alias_rejected");
}
#[test]
fn root_aliases_device_unc_and_traversal_rejected() {
    let f = Fixture::new();
    for root in [
        PathBuf::from(format!("{}.", f.root.display())),
        PathBuf::from(format!("{} ", f.root.display())),
        f.root.join("x/.."),
        PathBuf::from("\\\\?\\C:\\x"),
        PathBuf::from("\\\\server\\share"),
    ] {
        assert_eq!(
            validate_release_v2(&root, &f.bytes()).unwrap_err().code(),
            "path_invalid"
        );
    }
}
#[test]
fn junction_root_ancestor_and_child_rejected() {
    let f = Fixture::new();
    let link = f.root.with_extension("link");
    let o = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&f.root)
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(
        validate_release_v2(&link, &f.bytes()).unwrap_err().code(),
        "reparse_rejected"
    );
    fs::remove_dir(&link).unwrap();
    let child = f.root.join("escape");
    let o = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&child)
        .arg(f.root.parent().unwrap())
        .output()
        .unwrap();
    assert!(o.status.success());
    f.reject("reparse_rejected");
    fs::remove_dir(child).unwrap();
}
#[test]
fn ads_rejected() {
    let f = Fixture::new();
    fs::write(f.root.join("app/src/gateway/server.js:extra"), b"INERT").unwrap();
    f.reject("alternate_stream_rejected");
}
#[test]
fn unknown_duplicate_fields_and_wrong_scalar_types_rejected() {
    for (key, v) in [
        ("unknown", json!(true)),
        ("production_eligible", json!("false")),
        ("format_version", json!(1)),
    ] {
        let mut f = Fixture::new();
        f.manifest[key] = v;
        f.reject("manifest_invalid");
    }
    let f = Fixture::new();
    let raw = String::from_utf8(f.bytes())
        .unwrap()
        .replacen('{', "{\"format_version\":2,", 1);
    assert_eq!(
        validate_release_v2(&f.root, raw.as_bytes())
            .unwrap_err()
            .code(),
        "manifest_invalid"
    );
}
#[test]
fn runtime_and_production_claims_fail_closed() {
    for key in [
        "dependency_closure_proven",
        "native_load_verified",
        "config_isolation",
        "protected_service",
        "trusted_issuer",
    ] {
        let mut f = Fixture::new();
        f.manifest["runtime"][key] = json!(true);
        f.reject("manifest_invalid");
    }
    let mut f = Fixture::new();
    f.manifest["production_eligible"] = json!(true);
    f.reject("manifest_invalid");
}
#[test]
fn manifest_bytes_and_file_size_caps() {
    let mut f = Fixture::new();
    assert_eq!(
        validate_release_v2(&f.root, &vec![b' '; 8 * 1024 * 1024 + 1])
            .unwrap_err()
            .code(),
        "resource_limit"
    );
    f.manifest["files"][0]["size"] = json!(256_u64 * 1024 * 1024 + 1);
    f.reject("resource_limit");
}
#[test]
fn file_count_and_total_size_caps() {
    let mut f = Fixture::new();
    f.manifest["files"] = json!(vec![f.manifest["files"][0].clone(); 16385]);
    f.reject("resource_limit");
    let mut f = Fixture::new();
    for x in f.manifest["files"].as_array_mut().unwrap() {
        x["size"] = json!(256_u64 * 1024 * 1024);
    }
    f.reject("resource_limit");
}
#[test]
fn depth_cap_and_invalid_digest() {
    let mut f = Fixture::new();
    f.manifest["files"][0]["path"] = json!(format!("{}x", "a/".repeat(32)));
    f.reject("path_invalid");
    let mut f = Fixture::new();
    f.manifest["files"][0]["sha256"] = json!("A".repeat(64));
    f.reject("manifest_invalid");
}
#[test]
fn file_directory_prefix_conflict() {
    let mut f = Fixture::new();
    let p = f.manifest["files"][0]["path"].clone();
    f.manifest["directories"].as_array_mut().unwrap().push(p);
    f.manifest["directories"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    f.reject("manifest_invalid");
}
#[test]
fn closure_derived_facts_and_report_identity_must_match() {
    for field in ["sha256", "graph_sha256"] {
        let mut f = Fixture::new();
        f.manifest["closure"][field] = json!("0".repeat(64));
        f.reject("report_invalid");
    }
    let mut f = Fixture::new();
    f.manifest["closure"]["unresolved_edges"] = json!(0);
    f.reject("report_invalid");
}
#[test]
fn node_and_build_metadata_cannot_diverge_from_report() {
    let mut f = Fixture::new();
    f.manifest["node"]["moduleABI"] = json!("1");
    f.reject("report_invalid");
    let mut f = Fixture::new();
    f.manifest["build_tool"]["version"] = json!("0.0.0");
    f.reject("report_invalid");
}
#[test]
fn file_kind_must_match_path_not_caller_claim() {
    let mut f = Fixture::new();
    f.manifest["files"][0]["kind"] = json!("native");
    f.reject("manifest_invalid");
}

#[test]
fn uppercase_native_and_code_extensions_have_consistent_kinds() {
    let mut f = Fixture::new();
    for (p, kind) in [
        ("app/x.NODE", "native"),
        ("app/x.DLL", "native"),
        ("app/src/X.JS", "gateway-js"),
        ("app/x.JSON", "metadata"),
    ] {
        f.put(p, b"INERT", kind);
    }
    f.sort();
    assert_eq!(
        validate_release_v2(&f.root, &f.bytes()).unwrap().file_count,
        10
    );
}
#[test]
fn cross_language_candidate() {
    let Ok(root) = std::env::var("V2_CROSS_ROOT") else {
        let f = Fixture::new();
        assert_eq!(
            validate_release_v2(&f.root, &f.bytes()).unwrap().file_count,
            6
        );
        return;
    };
    let p = std::env::var("V2_CROSS_MANIFEST").unwrap();
    assert!(fs::metadata(&p).unwrap().len() <= 8 * 1024 * 1024);
    let bytes = fs::read(p).unwrap();
    let expected = std::env::var("V2_CROSS_EXPECT").unwrap();
    let result = validate_release_v2(Path::new(&root), &bytes);
    if expected == "ok" {
        let r = result.unwrap();
        println!("V2_CANDIDATE_CONTENT_INTEGRITY=PASS_NONPRODUCTION FILES={} BYTES={} RELEASE_ELIGIBLE=false",r.file_count,r.total_bytes);
    } else {
        assert_eq!(result.unwrap_err().code(), expected);
        println!("TAMPER_REJECTION={expected}");
    }
}

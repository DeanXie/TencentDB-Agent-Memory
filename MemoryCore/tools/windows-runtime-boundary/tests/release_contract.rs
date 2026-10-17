use std::path::Path;
use windows_runtime_boundary::validate_release;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    manifest: Value,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "r1-rust-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let files = [
            ("config/gateway.json", "config", "{\"synthetic\":true}\n"),
            ("gateway/server.ts", "entry", "export const syntheticGateway = true;\n"),
            ("loader/tsx.mjs", "loader", "export {};\n"),
            ("runtime/node.exe", "runtime", "R1_SYNTHETIC_NODE_NOT_EXECUTABLE\n"),
        ].into_iter().map(|(path, role, body)| {
            let file = root.join(path); fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, body).unwrap();
            json!({"path":path,"role":role,"sha256":format!("{:x}",Sha256::digest(body)),"size":body.len(),"file_type":"regular","loadable":role!="config","dependencies":[]})
        }).collect::<Vec<_>>();
        Self {
            root,
            manifest: json!({
                "format_version":1,"platform":"windows","architecture":"x86_64",
                "scope":"synthetic-fixture","validation_scope":"static-tree",
                "production_eligible":false,"entry":"gateway/server.ts","node":"runtime/node.exe",
                "loader":"loader/tsx.mjs","config":"config/gateway.json",
                "node_version":"synthetic","loader_version":"synthetic",
                "loading_policy":"closed-synthetic-v1","files":files
            }),
        }
    }
    fn result(
        &self,
    ) -> Result<windows_runtime_boundary::ReleaseReport, windows_runtime_boundary::ReleaseError>
    {
        validate_release(&self.root, &serde_json::to_vec(&self.manifest).unwrap())
    }
    fn reject(&self, code: &str) {
        assert_eq!(self.result().unwrap_err().code(), code);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn valid_synthetic_tree_binds_all_four_roles() {
    let f = Fixture::new();
    assert_eq!(f.result().unwrap().file_count, 4);
}
#[test]
fn tampered_file_is_rejected() {
    let f = Fixture::new();
    fs::write(f.root.join("gateway/server.ts"), "tampered").unwrap();
    f.reject("file_identity_mismatch");
}
#[test]
fn missing_required_file_is_rejected() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("loader/tsx.mjs")).unwrap();
    f.reject("tree_mismatch");
}
#[test]
fn undeclared_modules_native_extensions_and_data_are_rejected() {
    for name in ["rogue.mjs", "rogue.node", "rogue.dll", "secret.txt"] {
        let f = Fixture::new();
        fs::write(f.root.join(name), b"x").unwrap();
        f.reject("tree_mismatch");
    }
}
#[test]
fn traversal_absolute_unc_devices_ads_and_windows_aliases_are_rejected() {
    for path in [
        "../x",
        "/x",
        "C:/x",
        "c:x",
        "//host/share/x",
        "\\\\?\\C:\\x",
        "a\\b",
        "a//b",
        "./a",
        "a/../b",
        "a:b",
        "a.",
        "a ",
        "CON",
        "con.txt",
        "aux",
        "nul",
        "com1.js",
        "lpt9.txt",
        "x/COM1",
        "Gateway/server.ts",
        "a~1/x",
        "é.txt",
        "a\u{0000}b",
    ] {
        let mut f = Fixture::new();
        f.manifest["files"][0]["path"] = json!(path);
        f.reject("path_invalid");
    }
}
#[test]
fn duplicate_case_alias_and_prefix_conflicts_are_rejected() {
    let mut f = Fixture::new();
    let item = f.manifest["files"][0].clone();
    f.manifest["files"].as_array_mut().unwrap().insert(1, item);
    f.reject("manifest_invalid");
    let mut f = Fixture::new();
    f.manifest["files"][1]["path"] = json!("config/gateway.json/child.ts");
    f.reject("manifest_invalid");
}
#[test]
fn entry_loader_runtime_and_config_must_match_roles_and_fixed_paths() {
    for field in ["entry", "loader", "node", "config"] {
        let mut f = Fixture::new();
        f.manifest[field] = json!("elsewhere/x.js");
        f.reject("manifest_invalid");
    }
    let mut f = Fixture::new();
    f.manifest["files"][1]["role"] = json!("loader");
    f.reject("manifest_invalid");
}
#[test]
fn dependencies_must_be_declared_sorted_and_acyclic() {
    let mut f = Fixture::new();
    f.manifest["files"][1]["dependencies"] = json!(["modules/missing.mjs"]);
    f.reject("dependency_invalid");
    let mut f = Fixture::new();
    f.manifest["files"][1]["dependencies"] = json!(["gateway/server.ts"]);
    f.reject("dependency_invalid");
    let mut f = Fixture::new();
    f.manifest["files"][1]["dependencies"] = json!(["loader/tsx.mjs"]);
    f.manifest["files"][2]["dependencies"] = json!(["gateway/server.ts"]);
    f.reject("dependency_invalid");
}
#[test]
fn unknown_fields_types_versions_and_formal_release_claims_are_rejected() {
    for (key, value) in [
        ("extra", json!(true)),
        ("format_version", json!(2)),
        ("platform", json!("linux")),
        ("production_eligible", json!(true)),
        ("scope", json!("gateway")),
        ("loading_policy", json!("inherit-env")),
        ("architecture", json!("arm64")),
    ] {
        let mut f = Fixture::new();
        f.manifest[key] = value;
        f.reject("manifest_invalid");
    }
    let mut f = Fixture::new();
    f.manifest["files"][0]["extra"] = json!(1);
    f.reject("manifest_invalid");
    let mut f = Fixture::new();
    f.manifest["files"][0]["loadable"] = json!("false");
    f.reject("manifest_invalid");
}
#[test]
fn unsafe_development_and_secret_paths_fail_closed() {
    for p in [
        "src/x.ts",
        "node_modules/x.mjs",
        ".env",
        "config/secret.json",
        "data/memory.db",
        "artifacts/x.json",
    ] {
        let mut f = Fixture::new();
        f.manifest["files"][0]["path"] = json!(p);
        assert!(f.result().is_err());
    }
}
#[test]
fn correct_hash_does_not_approve_arbitrary_secret_or_import_content() {
    for body in [
        "export const token = 'PRIVATE_SYNTHETIC_CANARY';\n",
        "import 'undeclared';\n",
        "import('C:/dev/evil.js');\n",
    ] {
        let mut f = Fixture::new();
        fs::write(f.root.join("gateway/server.ts"), body).unwrap();
        f.manifest["files"][1]["sha256"] = json!(format!("{:x}", Sha256::digest(body)));
        f.manifest["files"][1]["size"] = json!(body.len());
        f.reject("synthetic_content_invalid");
    }
}
#[test]
fn unknown_type_size_digest_and_resource_limits_are_rejected() {
    for (key, value) in [
        ("role", json!("other")),
        ("file_type", json!("link")),
        ("sha256", json!("ABC")),
        ("size", json!(90000000)),
    ] {
        let mut f = Fixture::new();
        f.manifest["files"][0][key] = value;
        assert!(f.result().is_err());
    }
    let f = Fixture::new();
    assert_eq!(
        validate_release(&f.root, &vec![b' '; 1_048_577])
            .unwrap_err()
            .code(),
        "resource_limit"
    );
    assert_eq!(
        validate_release(&f.root, br#"{"format_version":1,"format_version":1}"#)
            .unwrap_err()
            .code(),
        "manifest_invalid"
    );
}
#[test]
fn root_and_parent_directory_reparse_points_are_rejected() {
    let f = Fixture::new();
    let alias = f.root.with_extension("junction");
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&alias)
            .arg(&f.root)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "isolated junction fixture creation must succeed"
        );
        assert_eq!(
            validate_release(&alias, &serde_json::to_vec(&f.manifest).unwrap())
                .unwrap_err()
                .code(),
            "reparse_rejected"
        );
        fs::remove_dir(&alias).unwrap();
        let path = f.root.join("escape");
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&path)
            .arg(f.root.parent().unwrap())
            .output()
            .unwrap();
        assert!(status.status.success());
        f.reject("reparse_rejected");
        fs::remove_dir(path).unwrap();
    }
}

// Cross-language harness: Node sets both explicit paths for a generated synthetic tree.
// No environment paths are consumed in the normal Rust-only run.
#[test]
fn cross_language_package() {
    let Ok(root) = std::env::var("R1_CROSS_ROOT") else {
        assert_eq!(Fixture::new().result().unwrap().file_count, 4);
        return;
    };
    let bytes = fs::read(std::env::var("R1_CROSS_MANIFEST").unwrap()).unwrap();
    let expected = std::env::var("R1_CROSS_EXPECT").unwrap();
    let result = validate_release(Path::new(&root), &bytes);
    if expected == "ok" {
        assert_eq!(result.unwrap().file_count, 4);
    } else {
        assert_eq!(result.unwrap_err().code(), expected);
    }
}

#[test]
fn excessively_deep_paths_are_rejected_before_filesystem_lookup() {
    let mut f = Fixture::new();
    let p = "modules/a/b/c/d/e/f/g/h/x.mjs";
    f.manifest["files"].as_array_mut().unwrap().insert(3,json!({"path":p,"role":"module","size":39,"sha256":"0".repeat(64),"file_type":"regular","loadable":true,"dependencies":[]}));
    f.reject("path_invalid");
}

#[test]
fn declared_tree_size_is_bounded_before_filesystem_lookup() {
    let mut f = Fixture::new();
    for i in 0..180 {
        f.manifest["files"].as_array_mut().unwrap().push(json!({"path":format!("modules/m{i:03}/a/b/x.mjs"),"role":"module","size":39,"sha256":"0".repeat(64),"file_type":"regular","loadable":true,"dependencies":[]}));
    }
    f.manifest["files"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    f.reject("resource_limit");
}

#[cfg(windows)]
#[test]
fn alternate_data_streams_are_not_hidden_from_tree_validation() {
    let f = Fixture::new();
    fs::write(
        f.root.join("gateway/server.ts:extra"),
        b"NONSECRET_SYNTHETIC_ADS",
    )
    .unwrap();
    f.reject("alternate_stream_rejected");
}

#[test]
fn release_root_rejects_parent_components_and_device_or_unc_prefixes() {
    let f = Fixture::new();
    let bytes = serde_json::to_vec(&f.manifest).unwrap();
    for root in [
        f.root.join("config/.."),
        PathBuf::from("\\\\?\\C:\\r1"),
        PathBuf::from("\\\\server\\share\\r1"),
    ] {
        assert_eq!(
            validate_release(&root, &bytes).unwrap_err().code(),
            "path_invalid"
        );
    }
}

#[test]
fn declared_inert_native_and_module_files_are_bound_not_executed() {
    let mut f = Fixture::new();
    for (p, role, body) in [
        (
            "modules/test.mjs",
            "module",
            "export const syntheticDependency = true;\n",
        ),
        (
            "native/test.node",
            "native",
            "R1_SYNTHETIC_NATIVE_NOT_LOADABLE\n",
        ),
    ] {
        fs::create_dir_all(f.root.join(p).parent().unwrap()).unwrap();
        fs::write(f.root.join(p), body).unwrap();
        f.manifest["files"].as_array_mut().unwrap().push(json!({"path":p,"role":role,"size":body.len(),"sha256":format!("{:x}",Sha256::digest(body)),"file_type":"regular","loadable":true,"dependencies":[]}));
    }
    f.manifest["files"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    assert_eq!(f.result().unwrap().file_count, 6);
}

#[test]
fn invalid_manifest_fails_closed_without_echoing_input() {
    let error = validate_release(Path::new("."), b"PRIVATE_SYNTHETIC_CANARY").unwrap_err();
    assert_eq!(error.code(), "manifest_invalid");
    assert!(!error.to_string().contains("PRIVATE_SYNTHETIC_CANARY"));
}

#[cfg(windows)]
mod root_alias_tests {
    use super::*;
    use std::{
        io,
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, GetFinalPathNameByHandleW, GetLongPathNameW, GetShortPathNameW,
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
    };

    #[derive(Debug, PartialEq, Eq)]
    struct ObjectId {
        volume: u32,
        index: u64,
    }
    struct Fact {
        id: ObjectId,
        resolved: String,
    }

    fn fact(path: &Path) -> io::Result<Fact> {
        // Deliberately follows isolated fixture junctions to establish the alias relationship.
        let file = fs::OpenOptions::new()
            .read(true)
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let mut final_path = vec![0u16; 32768];
        unsafe {
            if GetFileInformationByHandle(file.as_raw_handle(), &mut info) == 0 {
                return Err(io::Error::last_os_error());
            }
            let n = GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                final_path.as_mut_ptr(),
                final_path.len() as u32,
                0,
            );
            if n == 0 || n as usize >= final_path.len() {
                return Err(io::Error::last_os_error());
            }
            final_path.truncate(n as usize);
        }
        Ok(Fact {
            id: ObjectId {
                volume: info.dwVolumeSerialNumber,
                index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            },
            resolved: String::from_utf16(&final_path).unwrap(),
        })
    }
    fn same_object(case: &str, root: &Path, alias: &Path) {
        let normal = fact(root).unwrap();
        let other = fact(alias).unwrap();
        println!(
            "PATH_FACT case={case} input={alias:?} resolved={:?} object={:?} same={}",
            other.resolved,
            other.id,
            normal.id == other.id
        );
        assert_eq!(
            normal.id, other.id,
            "fixture must prove actual object identity"
        );
    }
    fn check_root(f: &Fixture, path: &Path, code: &str) {
        let bytes = serde_json::to_vec(&f.manifest).unwrap();
        assert_eq!(validate_release(path, &bytes).unwrap_err().code(), code);
    }
    fn suffixed(path: &Path, suffix: &str) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    }
    fn intermediate(root: &Path, suffix: &str) -> PathBuf {
        suffixed(root.parent().unwrap(), suffix).join(root.file_name().unwrap())
    }
    fn windows_name(path: &Path, short: bool) -> io::Result<PathBuf> {
        let raw: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut out = vec![0u16; 32768];
        let n = unsafe {
            if short {
                GetShortPathNameW(raw.as_ptr(), out.as_mut_ptr(), out.len() as u32)
            } else {
                GetLongPathNameW(raw.as_ptr(), out.as_mut_ptr(), out.len() as u32)
            }
        };
        if n == 0 || n as usize >= out.len() {
            return Err(io::Error::last_os_error());
        }
        out.truncate(n as usize);
        Ok(PathBuf::from(String::from_utf16(&out).unwrap()))
    }
    struct Junction(PathBuf);
    impl Junction {
        fn new(path: PathBuf, target: &Path) -> Self {
            assert!(path.starts_with(std::env::temp_dir()));
            assert!(target.starts_with(std::env::temp_dir()));
            assert!(!path.exists());
            let output = std::process::Command::new("cmd.exe")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&path)
                .arg(target)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated junction fixture must be constructible"
            );
            Self(path)
        }
    }
    impl Drop for Junction {
        fn drop(&mut self) {
            fs::remove_dir(&self.0).unwrap();
        }
    }

    #[test]
    fn root_alias_normal_root_and_ascii_case_equivalence_remain_valid() {
        let f = Fixture::new();
        let case = f.root.with_file_name(
            f.root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_ascii_uppercase(),
        );
        same_object("normal_ascii_case", &f.root, &case);
        assert_eq!(f.result().unwrap().file_count, 4);
        assert_eq!(
            validate_release(&case, &serde_json::to_vec(&f.manifest).unwrap())
                .unwrap()
                .file_count,
            4
        );
    }
    #[test]
    fn root_alias_trailing_dot_same_object_is_rejected() {
        let f = Fixture::new();
        let alias = suffixed(&f.root, ".");
        same_object("trailing_dot", &f.root, &alias);
        check_root(&f, &alias, "path_invalid");
    }
    #[test]
    fn root_alias_trailing_space_same_object_is_rejected_by_policy() {
        let f = Fixture::new();
        let alias = suffixed(&f.root, " ");
        same_object("trailing_space", &f.root, &alias);
        check_root(&f, &alias, "path_invalid");
    }
    #[test]
    fn root_alias_intermediate_dot_same_object_is_rejected() {
        let f = Fixture::new();
        let alias = intermediate(&f.root, ".");
        same_object("intermediate_dot", &f.root, &alias);
        check_root(&f, &alias, "path_invalid");
    }
    #[test]
    fn root_alias_intermediate_space_has_explicit_policy_even_if_unresolvable() {
        let f = Fixture::new();
        let alias = intermediate(&f.root, " ");
        match fact(&alias) {
            Ok(other) => {
                assert_eq!(other.id, fact(&f.root).unwrap().id);
                println!("INTERMEDIATE_SPACE_RELATION=SAME_OBJECT");
            }
            Err(error) => println!(
                "INTERMEDIATE_SPACE_RELATION=NOT_RESOLVED native_error={:?}",
                error.raw_os_error()
            ),
        }
        check_root(&f, &alias, "path_invalid");
    }
    #[test]
    #[ignore = "run explicitly only after this task proves a distinct real filesystem short-name alias"]
    fn root_alias_real_short_name_same_object_is_rejected() {
        let f = Fixture::new();
        let short = windows_name(&f.root, true).unwrap();
        if short
            .to_str()
            .unwrap()
            .eq_ignore_ascii_case(f.root.to_str().unwrap())
        {
            println!("SHORT_NAME_8_3=NOT_TESTABLE");
            panic!("no distinct real short-name alias; do not report this scenario as PASS");
        }
        let long = windows_name(&short, false).unwrap();
        assert!(long
            .to_str()
            .unwrap()
            .eq_ignore_ascii_case(f.root.to_str().unwrap()));
        same_object("short_8_3", &f.root, &short);
        check_root(&f, &short, "root_alias_rejected");
    }
    #[test]
    fn root_alias_ancestor_junction_same_object_is_rejected() {
        let f = Fixture::new();
        let link = Junction::new(
            f.root.with_extension("ancestor-link"),
            f.root.parent().unwrap(),
        );
        let alias = link.0.join(f.root.file_name().unwrap());
        same_object("ancestor_junction", &f.root, &alias);
        check_root(&f, &alias, "reparse_rejected");
    }
    #[test]
    fn root_alias_root_junction_same_object_is_rejected() {
        let f = Fixture::new();
        let link = Junction::new(f.root.with_extension("root-link"), &f.root);
        same_object("root_junction", &f.root, &link.0);
        check_root(&f, &link.0, "reparse_rejected");
    }
    #[test]
    fn root_alias_unsafe_components_fail_before_missing_path_lookup() {
        let f = Fixture::new();
        for suffix in [
            "missing.",
            "missing ",
            ".. ",
            "nul.txt",
            "conin$",
            "x:y",
            "x?y",
            "x\u{0001}y",
        ] {
            check_root(&f, &f.root.join(suffix), "path_invalid");
        }
        let extended = PathBuf::from(format!("\\\\?\\{}", f.root.display()));
        same_object("extended_path", &f.root, &extended);
        check_root(&f, &extended, "path_invalid");
        let device = PathBuf::from(format!("\\\\.\\{}", f.root.display()));
        same_object("device_path", &f.root, &device);
        check_root(&f, &device, "path_invalid");
        check_root(
            &f,
            Path::new("\\\\localhost\\r1-unapproved-share\\payload"),
            "path_invalid",
        );
    }
}

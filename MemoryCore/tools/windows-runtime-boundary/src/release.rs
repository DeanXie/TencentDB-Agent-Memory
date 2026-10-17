//! R1 static, synthetic release-tree contract. Not a launcher or trust anchor.
//! Metadata checks precede opens: hostile concurrent replacement remains a TOCTOU limitation.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::Path,
};

const MAX_MANIFEST: usize = 1_048_576;
const MAX_FILES: usize = 256;
const MAX_FILE: u64 = 65_536;
const MAX_TREE: u64 = 1_048_576;

#[derive(Debug)]
pub struct ReleaseReport {
    pub file_count: usize,
}
#[derive(Debug)]
pub struct ReleaseError(pub(crate) &'static str);
impl ReleaseError {
    pub fn code(&self) -> &'static str {
        self.0
    }
}
impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ReleaseError {}
type Result<T> = std::result::Result<T, ReleaseError>;
fn require(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(ReleaseError(code))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u32,
    platform: String,
    architecture: String,
    scope: String,
    validation_scope: String,
    production_eligible: bool,
    entry: String,
    node: String,
    loader: String,
    config: String,
    node_version: String,
    loader_version: String,
    loading_policy: String,
    files: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    sha256: String,
    size: u64,
    role: String,
    file_type: String,
    loadable: bool,
    dependencies: Vec<String>,
}

// Lowercase ASCII excludes case, Unicode and supplied 8.3 alias ambiguity.
fn path_valid(p: &str) -> bool {
    if p.is_empty() || p.len() > 200 || p.split('/').count() > 8 {
        return false;
    }
    p.split('/').all(|s| {
        let stem = s.split('.').next().unwrap_or("");
        let reserved = matches!(stem, "con" | "prn" | "aux" | "nul" | "clock$")
            || (stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        !s.is_empty()
            && s.len() <= 100
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && !s.ends_with('.')
            && !reserved
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    })
}

// Inert, nonsecret fixture vocabulary only. Arbitrary executable/JS/native/config bytes
// require a future independently established closure contract; hashes alone cannot grant it.
fn fixture(path: &str, role: &str) -> Option<&'static [u8]> {
    match (path, role) {
        ("config/gateway.json", "config") => Some(b"{\"synthetic\":true}\n"),
        ("gateway/server.ts", "entry") => Some(b"export const syntheticGateway = true;\n"),
        ("loader/tsx.mjs", "loader") => Some(b"export {};\n"),
        ("runtime/node.exe", "runtime") => Some(b"R1_SYNTHETIC_NODE_NOT_EXECUTABLE\n"),
        (p, "module") if p.starts_with("modules/") && p.ends_with(".mjs") => {
            Some(b"export const syntheticDependency = true;\n")
        }
        (p, "native") if p.starts_with("native/") && p.ends_with(".node") => {
            Some(b"R1_SYNTHETIC_NATIVE_NOT_LOADABLE\n")
        }
        _ => None,
    }
}

pub(crate) fn no_reparse(path: &Path) -> Result<fs::Metadata> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ReleaseError("filesystem_unavailable"))?;
    require(!metadata.file_type().is_symlink(), "reparse_rejected")?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        require(metadata.file_attributes() & 0x400 == 0, "reparse_rejected")?;
    }
    Ok(metadata)
}

#[cfg(windows)]
fn root_spelling(root: &Path) -> Result<String> {
    // Inspect the original spelling, not Path::components/canonicalize: those can hide '.'.
    let raw = root.to_str().ok_or(ReleaseError("path_invalid"))?;
    require(raw.encode_utf16().count() <= 32760, "resource_limit")?;
    let prefix = raw.as_bytes();
    require(
        prefix.len() >= 3
            && prefix[0].is_ascii_alphabetic()
            && prefix[1] == b':'
            && matches!(prefix[2], b'\\' | b'/'),
        "path_invalid",
    )?;
    let mut parts: Vec<_> = raw[3..].split(['\\', '/']).collect();
    // One trailing directory separator is harmless; repeated/internal empty parts are not.
    if parts.last() == Some(&"") {
        parts.pop();
    }
    require(!parts.is_empty(), "path_invalid")?;
    for part in parts {
        require(
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with('.')
                && !part.ends_with(' ')
                && !part
                    .chars()
                    .any(|c| c.is_control() || "<>:\"|?*".contains(c)),
            "path_invalid",
        )?;
        let stem = part
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches(' ')
            .to_ascii_lowercase();
        let numbered = stem
            .strip_prefix("com")
            .or_else(|| stem.strip_prefix("lpt"));
        require(
            !matches!(
                stem.as_str(),
                "con" | "prn" | "aux" | "nul" | "clock$" | "conin$" | "conout$"
            ) && !matches!(
                numbered,
                Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
            ),
            "path_invalid",
        )?;
    }
    Ok(raw.replace('/', "\\").trim_end_matches('\\').to_owned())
}

#[cfg(windows)]
pub(crate) fn validate_root(root: &Path) -> Result<()> {
    validate_root_impl(root, false)
}

#[cfg(windows)]
pub(crate) fn validate_root_v2(root: &Path) -> Result<()> {
    validate_root_impl(root, true)
}

#[cfg(windows)]
fn validate_root_impl(root: &Path, long_paths: bool) -> Result<()> {
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, GetFinalPathNameByHandleW, GetLongPathNameW,
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let spelling = root_spelling(root)?;
    // Inspect from the drive down: do not first query a child through an unchecked ancestor.
    for ancestor in root.ancestors().collect::<Vec<_>>().into_iter().rev() {
        require(no_reparse(ancestor)?.is_dir(), "file_type_invalid")?;
    }
    // V2 needs long-path Win32 calls for actual nested npm trees. This prefix is created
    // only AFTER checking the original DOS spelling; caller-supplied prefixes still fail.
    // V1 continues to use its original API spelling and resource limits.
    let api_spelling = if long_paths {
        format!("\\\\?\\{spelling}")
    } else {
        spelling.clone()
    };
    let input: Vec<_> = std::ffi::OsStr::new(&api_spelling)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut buffer = vec![0u16; 32768];
    // SAFETY: input is terminated and buffer has the declared writable capacity.
    let n = unsafe { GetLongPathNameW(input.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    require(
        n > 0 && (n as usize) < buffer.len(),
        "filesystem_unavailable",
    )?;
    let long = String::from_utf16(&buffer[..n as usize])
        .map_err(|_| ReleaseError("root_identity_unavailable"))?;
    let long = if long_paths {
        long.strip_prefix("\\\\?\\")
            .ok_or(ReleaseError("root_identity_unavailable"))?
            .to_owned()
    } else {
        long
    };
    // ASCII case equivalence is allowed, not name substitution. Non-ASCII case variants
    // conservatively fail closed. This detects real short names, including ones without '~'.
    require(spelling.eq_ignore_ascii_case(&long), "root_alias_rejected")?;

    let open = |p: &Path| -> Result<fs::File> {
        fs::OpenOptions::new()
            .read(true)
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(p)
            .map_err(|_| ReleaseError("filesystem_unavailable"))
    };
    let identity = |file: &fs::File| -> Result<(u32, u64)> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the file owns a live handle; info is a correctly sized writable buffer.
        require(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "root_identity_unavailable",
        )?;
        require(info.dwFileAttributes & 0x400 == 0, "reparse_rejected")?;
        require(info.dwFileAttributes & 0x10 != 0, "file_type_invalid")?;
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        require(index != 0, "root_identity_unavailable")?;
        Ok((info.dwVolumeSerialNumber, index))
    };
    let file = open(Path::new(&spelling))?;
    let id = identity(&file)?;
    // Bind the accepted spelling, long name and normalized handle path to the same object.
    let long_file = open(Path::new(&long))?;
    require(id == identity(&long_file)?, "root_identity_mismatch")?;
    // SAFETY: file is live, buffer remains allocated with the specified capacity.
    let n = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    require(
        n > 0 && (n as usize) < buffer.len(),
        "root_identity_unavailable",
    )?;
    let final_path = String::from_utf16(&buffer[..n as usize])
        .map_err(|_| ReleaseError("root_identity_unavailable"))?;
    let dos = final_path
        .strip_prefix("\\\\?\\")
        .ok_or(ReleaseError("root_identity_unavailable"))?;
    require(spelling.eq_ignore_ascii_case(dos), "root_identity_mismatch")?;
    // These handle checks are a point-in-time consistency check. The later tree reads are
    // path-based; this does not remove ancestor/root replacement or other TOCTOU windows.
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn validate_root(_root: &Path) -> Result<()> {
    Err(ReleaseError("platform_unavailable"))
}

#[cfg(not(windows))]
pub(crate) fn validate_root_v2(root: &Path) -> Result<()> {
    validate_root(root)
}

#[cfg(windows)]
pub(crate) fn no_extra_streams(path: &Path) -> Result<()> {
    no_extra_streams_impl(path, false)
}

#[cfg(windows)]
pub(crate) fn no_extra_streams_v2(path: &Path) -> Result<()> {
    no_extra_streams_impl(path, true)
}

#[cfg(windows)]
fn no_extra_streams_impl(path: &Path, long_paths: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
            WIN32_FIND_STREAM_DATA,
        },
    };
    let api_path;
    let path = if long_paths {
        // Called only for validated root/relative paths. Do not normalize untrusted raw input.
        api_path = format!(
            "\\\\?\\{}",
            path.to_str()
                .ok_or(ReleaseError("path_invalid"))?
                .replace('/', "\\")
        );
        Path::new(&api_path)
    } else {
        path
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut data = WIN32_FIND_STREAM_DATA::default();
    // SAFETY: the terminated path and writable stream-data buffer live throughout each call.
    let handle = unsafe {
        FindFirstStreamW(
            name.as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // Empty directories may have no data stream. All other enumeration failures close.
        return require(
            unsafe { GetLastError() } == ERROR_HANDLE_EOF,
            "filesystem_unavailable",
        );
    }
    let outcome = loop {
        let end = data
            .cStreamName
            .iter()
            .position(|v| *v == 0)
            .unwrap_or(data.cStreamName.len());
        if data.cStreamName[..end] != "::$DATA".encode_utf16().collect::<Vec<_>>() {
            break Err(ReleaseError("alternate_stream_rejected"));
        }
        // SAFETY: handle is an active stream enumeration handle; data remains writable.
        if unsafe { FindNextStreamW(handle, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) }
            == 0
        {
            break require(
                unsafe { GetLastError() } == ERROR_HANDLE_EOF,
                "filesystem_unavailable",
            );
        }
    };
    // SAFETY: close the enumeration handle exactly once, on both success and rejection.
    require(unsafe { FindClose(handle) } != 0, "filesystem_unavailable")?;
    outcome
}

#[cfg(not(windows))]
pub(crate) fn no_extra_streams(_path: &Path) -> Result<()> {
    Err(ReleaseError("platform_unavailable"))
}

#[cfg(not(windows))]
pub(crate) fn no_extra_streams_v2(path: &Path) -> Result<()> {
    no_extra_streams(path)
}

fn visit(
    root: &Path,
    relative: &str,
    files: &mut BTreeSet<String>,
    dirs: &mut BTreeSet<String>,
    count: &mut usize,
    bytes: &mut u64,
) -> Result<()> {
    require(relative.split('/').count() <= 8, "resource_limit")?;
    let path = if relative.is_empty() {
        root.to_owned()
    } else {
        root.join(relative)
    };
    for child in fs::read_dir(path).map_err(|_| ReleaseError("filesystem_unavailable"))? {
        let child = child.map_err(|_| ReleaseError("filesystem_unavailable"))?;
        *count += 1;
        require(*count <= 512, "resource_limit")?;
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| ReleaseError("path_invalid"))?;
        let rel = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        require(path_valid(&rel), "path_invalid")?;
        let metadata = no_reparse(&child.path())?;
        no_extra_streams(&child.path())?;
        if metadata.is_dir() {
            dirs.insert(rel.clone());
            visit(root, &rel, files, dirs, count, bytes)?;
        } else {
            require(metadata.is_file(), "file_type_invalid")?;
            require(metadata.len() <= MAX_FILE, "resource_limit")?;
            *bytes = bytes
                .checked_add(metadata.len())
                .ok_or(ReleaseError("resource_limit"))?;
            require(*bytes <= MAX_TREE, "resource_limit")?;
            files.insert(rel);
        }
    }
    Ok(())
}

fn dependency_visit<'a>(
    key: &'a str,
    entries: &BTreeMap<&'a str, &'a Entry>,
    active: &mut BTreeSet<&'a str>,
    done: &mut BTreeSet<&'a str>,
) -> Result<()> {
    if done.contains(key) {
        return Ok(());
    }
    require(active.insert(key), "dependency_invalid")?;
    let item = entries.get(key).ok_or(ReleaseError("dependency_invalid"))?;
    let mut previous = "";
    for dep in &item.dependencies {
        require(
            path_valid(dep) && dep.as_str() > previous,
            "dependency_invalid",
        )?;
        previous = dep;
        dependency_visit(dep, entries, active, done)?;
    }
    active.remove(key);
    done.insert(key);
    Ok(())
}

pub fn validate_release(root: &Path, manifest: &[u8]) -> Result<ReleaseReport> {
    require(manifest.len() <= MAX_MANIFEST, "resource_limit")?;
    // Direct struct deserialization rejects duplicate as well as unknown fields.
    let m: Manifest =
        serde_json::from_slice(manifest).map_err(|_| ReleaseError("manifest_invalid"))?;
    require(
        m.format_version == 1
            && m.platform == "windows"
            && m.architecture == "x86_64"
            && m.scope == "synthetic-fixture"
            && m.validation_scope == "static-tree"
            && !m.production_eligible
            && m.entry == "gateway/server.ts"
            && m.node == "runtime/node.exe"
            && m.loader == "loader/tsx.mjs"
            && m.config == "config/gateway.json"
            && m.node_version == "synthetic"
            && m.loader_version == "synthetic"
            && m.loading_policy == "closed-synthetic-v1",
        "manifest_invalid",
    )?;
    require(
        m.files.len() >= 4 && m.files.len() <= MAX_FILES,
        "resource_limit",
    )?;
    let mut entries = BTreeMap::new();
    let mut declared_dirs = BTreeSet::new();
    let mut previous = "";
    for item in &m.files {
        require(path_valid(&item.path), "path_invalid")?;
        require(item.path.as_str() > previous, "manifest_invalid")?;
        previous = &item.path;
        require(
            item.file_type == "regular"
                && item.sha256.len() == 64
                && item
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && item.loadable == (item.role != "config")
                && item.dependencies.len() <= MAX_FILES,
            "manifest_invalid",
        )?;
        require(item.size <= MAX_FILE, "resource_limit")?;
        let mut ancestor = item.path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            require(!entries.contains_key(parent), "manifest_invalid")?;
            declared_dirs.insert(parent.to_owned());
            ancestor = parent;
        }
        entries.insert(item.path.as_str(), item);
    }
    require(declared_dirs.len() + m.files.len() <= 512, "resource_limit")?;
    for (path, role) in [
        (m.entry.as_str(), "entry"),
        (m.node.as_str(), "runtime"),
        (m.loader.as_str(), "loader"),
        (m.config.as_str(), "config"),
    ] {
        require(
            entries.get(path).is_some_and(|entry| entry.role == role),
            "manifest_invalid",
        )?;
    }
    for item in &m.files {
        require(
            fixture(&item.path, &item.role).is_some(),
            "manifest_invalid",
        )?;
    }
    let mut active = BTreeSet::new();
    let mut done = BTreeSet::new();
    for key in entries.keys() {
        dependency_visit(key, &entries, &mut active, &mut done)?;
    }
    validate_root(root)?;
    no_extra_streams(root)?;
    let mut actual_files = BTreeSet::new();
    let mut actual_dirs = BTreeSet::new();
    visit(
        root,
        "",
        &mut actual_files,
        &mut actual_dirs,
        &mut 0,
        &mut 0,
    )?;
    require(
        actual_files == entries.keys().map(|s| s.to_string()).collect()
            && actual_dirs == declared_dirs,
        "tree_mismatch",
    )?;
    for item in &m.files {
        let path = root.join(&item.path);
        no_reparse(&path)?;
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|_| ReleaseError("filesystem_unavailable"))?
            .take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReleaseError("filesystem_unavailable"))?;
        require(
            bytes.len() as u64 == item.size
                && format!("{:x}", Sha256::digest(&bytes)) == item.sha256,
            "file_identity_mismatch",
        )?;
        require(
            Some(bytes.as_slice()) == fixture(&item.path, &item.role),
            "synthetic_content_invalid",
        )?;
    }
    Ok(ReleaseReport {
        file_count: m.files.len(),
    })
}

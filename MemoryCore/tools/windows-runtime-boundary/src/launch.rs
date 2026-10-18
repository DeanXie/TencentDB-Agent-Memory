//! R2 closed synthetic-process policy. This is NOT Gateway release authorization or an issuer.
//! V2 is a point-in-time content check; loaded-code identity and TOCTOU remain unproven.
//! The installed Node executable is a local test tool, not a trusted deployed runtime.
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
pub const NODE_TEST_TOOL: &str = "C:\\Program Files\\nodejs\\node.exe";
pub const SYNTHETIC_ENTRY: &str = "app/src/gateway/server.js";
pub const SYNTHETIC_PACKAGE: &str = "{\"type\":\"module\",\"private\":true}\n";
pub const SYNTHETIC_ENTRY_SOURCE: &str = r#"import fs from 'node:fs';
let gate = '';
let accepted = false;
const timer = setTimeout(() => process.exit(91), 5000);
process.stdin.on('end', () => { if (!accepted) process.exit(92); });
process.stdin.on('data', chunk => {
  gate += chunk.toString('utf8');
  if (gate.length > 6 || !'R2_GO\n'.startsWith(gate)) process.exit(93);
  if (gate !== 'R2_GO\n' || accepted) return;
  accepted = true; clearTimeout(timer); process.stdin.destroy();
  const scenario = process.env.R2_SCENARIO;
  fs.writeSync(1, JSON.stringify({scenario, cwd:process.cwd(), execArgv:process.execArgv, environment:process.env})+'\n');
  if (scenario === 'normal') process.exit(0);
  if (scenario === 'nonzero') { fs.writeSync(2, 'R2_SYNTHETIC_NONZERO\n'); process.exit(17); }
  if (scenario === 'wait') { setInterval(() => {}, 1000); return; }
  process.exit(94);
});
"#;
#[derive(Clone, Default, Debug)]
pub struct CancelToken(Arc<AtomicBool>);
impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
#[derive(Clone, Copy, Debug)]
pub enum SyntheticCase {
    Normal,
    Nonzero,
    Wait,
}
#[derive(Clone, Copy, Debug)]
pub enum LaunchTarget {
    Synthetic(SyntheticCase),
    /// Offline integration-test executable, never a Gateway or arbitrary command.
    SyntheticIpc,
    /// Fixed ordinary Cargo bin, still offline and nonauthoritative.
    StandaloneIpc,
    Gateway,
    ProtectedGateway,
}
pub struct LaunchRequest {
    pub target: LaunchTarget,
    pub release_root: PathBuf,
    pub manifest: Vec<u8>,
    pub executable: PathBuf,
    pub entry: String,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub environment_overrides: Vec<(String, String)>,
    pub timeout: Duration,
    pub cancel: CancelToken,
}
#[derive(Debug, PartialEq, Eq)]
pub enum LaunchOutcome {
    Exited(i32),
    TimedOut,
    Aborted,
}
#[derive(Debug, PartialEq, Eq)]
pub enum LaunchEvent {
    Created,
    JobAssigned,
    HandshakeSent,
    Exited,
    NonzeroExited,
    TimedOut,
    Aborted,
}
#[derive(Debug)]
pub struct LaunchReport {
    /// Exact application and serialized command line passed to CreateProcessW.
    /// These are launch observations, not loaded-code attestation.
    pub executable_path: PathBuf,
    pub command_line: String,
    pub startup_confirmed: bool,
    pub output_readers_joined: bool,
    pub job_binding_at_creation: bool,
    pub job_membership_verified: bool,
    pub pre_execution_limits_verified: bool,
    pub job_handle_not_inherited: bool,
    pub kill_on_job_close_verified: bool,
    pub outcome: LaunchOutcome,
    pub events: Vec<LaunchEvent>,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
    pub process_reaped: bool,
    pub job_closed: bool,
    pub test_tool_sha256: String,
    pub synthetic_entry_sha256: String,
}
/// Test supervision only. A process object is not a trusted loaded-code identity.
pub struct LaunchObservation {
    pub stage: &'static str,
    pub process_id: u32,
    pub creation_time: u64,
    pub job_binding_at_creation: bool,
    pub job_membership_verified: bool,
    pub pre_execution_limits_verified: bool,
    pub job_handle_not_inherited: bool,
}
impl LaunchRequest {
    /// Locate this package's fixed ordinary development bin beside the current
    /// Cargo integration-test output. No caller path/hash or environment override
    /// selects the source. This local build layout is NOT a production trust anchor.
    pub fn standalone_ipc_build_artifact_for_test() -> Result<PathBuf, LaunchError> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            windows::standalone_build_artifact()
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            Err(error("platform_unavailable"))
        }
    }
    pub fn launch_observed_for_test(
        self,
        mut observer: impl FnMut(&LaunchObservation),
    ) -> Result<LaunchReport, LaunchError> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            windows::launch_inner(self, Some(&mut observer))
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            let _ = observer;
            Err(error("platform_unavailable"))
        }
    }
}
#[derive(Debug)]
pub struct LaunchError {
    code: &'static str,
    pub os_error: Option<i32>,
}
impl LaunchError {
    pub fn code(&self) -> &'static str {
        self.code
    }
}
impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for LaunchError {}
pub(crate) fn error(code: &'static str) -> LaunchError {
    LaunchError {
        code,
        os_error: None,
    }
}
/// A duplicate of the original child process object, never a PID lookup.
/// Liveness is a point-in-time observation, not a loaded-code trust claim.
#[derive(Debug)]
pub(crate) struct StartedChild {
    #[cfg(all(windows, target_arch = "x86_64"))]
    process: std::os::windows::io::OwnedHandle,
}
impl StartedChild {
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub(crate) fn process_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        use std::os::windows::io::AsHandle;
        self.process.as_handle()
    }
    pub(crate) fn is_alive(&self) -> Result<bool, LaunchError> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{Foundation::*, System::Threading::*};
            match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => Ok(true),
                WAIT_OBJECT_0 => Ok(false),
                _ => Err(LaunchError {
                    code: "startup_probe_failed",
                    os_error: std::io::Error::last_os_error().raw_os_error(),
                }),
            }
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        Err(error("platform_unavailable"))
    }
}
pub(crate) const IPC_FIXTURE_ENTRY: &str = "app/r3-ipc-test.exe";
pub(crate) const IPC_FIXTURE_TEST: &str = "controlled_ipc_fixture";
pub(crate) const STANDALONE_IPC_ENTRY: &str = "app/cmg-runtime-boundary-ipc-child.exe";
const STANDALONE_IPC_BIN: &str = "cmg-runtime-boundary-ipc-child.exe";

/// Only the R4 offline worker can supply this bounded, internally generated GO
/// message. It contains no caller-selected command, arguments or environment.
pub(crate) fn launch_with_ipc(
    request: LaunchRequest,
    gate: &[u8],
    on_ready: &mut dyn FnMut(StartedChild) -> Result<bool, LaunchError>,
) -> Result<LaunchReport, LaunchError> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        windows::launch_ipc(request, gate, on_ready)
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (request, gate, on_ready);
        Err(error("platform_unavailable"))
    }
}
pub(crate) fn launch_with_startup(
    request: LaunchRequest,
    on_ready: &mut dyn FnMut(StartedChild) -> Result<(), LaunchError>,
) -> Result<LaunchReport, LaunchError> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        windows::launch_controlled(request, on_ready)
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (request, on_ready);
        Err(error("platform_unavailable"))
    }
}
#[cfg(all(test, windows, target_arch = "x86_64"))]
pub(crate) fn launch_with_startup_observed(
    request: LaunchRequest,
    on_ready: &mut dyn FnMut(StartedChild) -> Result<(), LaunchError>,
    observer: &mut dyn FnMut(&LaunchObservation),
) -> Result<LaunchReport, LaunchError> {
    windows::launch_core(request, Some(observer), Some(on_ready))
}
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows {
    use super::*;
    use crate::{
        release::{no_extra_streams_v2, no_reparse, validate_root_v2},
        validate_release_v2,
    };
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::OsStr,
        fs,
        io::{Read, Write},
        os::windows::{
            ffi::OsStrExt,
            io::{AsHandle, AsRawHandle, FromRawHandle},
            process::{CommandExt, ExitStatusExt},
        },
        path::Path,
        process::{Command, ExitStatus, Stdio},
        sync::mpsc::{self, Receiver, RecvTimeoutError},
        thread,
        time::Instant,
    };
    use windows_sys::Win32::{
        Foundation::*,
        System::{JobObjects::*, Threading::*},
    };
    const MAX_OUTPUT: u64 = 8192;
    const FIXTURE_FILES: [&str; 4] = [
        "app/package.json",
        SYNTHETIC_ENTRY,
        "closure-report.json",
        "js-dependency-graph.json",
    ];
    const FIXTURE_DIRS: [&str; 5] = ["app", "app/src", "app/src/gateway", "temp", "work"];

    fn native(code: &'static str) -> LaunchError {
        LaunchError {
            code,
            os_error: std::io::Error::last_os_error().raw_os_error(),
        }
    }
    struct Job(HANDLE);
    impl Job {
        fn new() -> Result<Self, LaunchError> {
            let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if raw.is_null() {
                return Err(native("job_create_failed"));
            }
            let job = Self(raw);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            if unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
            {
                return Err(native("job_configure_failed"));
            }
            job.verify_limits()?;
            Ok(job)
        }
        fn verify_limits(&self) -> Result<(), LaunchError> {
            // NULL has special Win32 query semantics (the caller's current Job).
            // A closed owned Job must never silently select that different object.
            if self.0.is_null() || self.0 == INVALID_HANDLE_VALUE {
                return Err(error("job_closed"));
            }
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            let mut returned = 0;
            if unsafe {
                QueryInformationJobObject(
                    self.0,
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(native("job_limits_not_proven"));
            }
            if returned as usize != std::mem::size_of_val(&limits)
                || limits.BasicLimitInformation.LimitFlags
                    != (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
                || limits.BasicLimitInformation.ActiveProcessLimit != 1
            {
                return Err(error("job_limits_not_proven"));
            }
            let mut flags = 0;
            if unsafe { GetHandleInformation(self.0, &mut flags) } == 0 {
                return Err(native("job_handle_not_proven"));
            }
            if flags & HANDLE_FLAG_INHERIT != 0 {
                return Err(error("job_handle_inheritable"));
            }
            Ok(())
        }
        fn verify_member(&self, child: &NativeChild) -> Result<(), LaunchError> {
            if self.0.is_null() || self.0 == INVALID_HANDLE_VALUE {
                return Err(error("job_closed"));
            }
            let mut member = 0;
            if unsafe { IsProcessInJob(child.as_raw_handle(), self.0, &mut member) } == 0 {
                return Err(native("job_assignment_not_proven"));
            }
            if member == 0 {
                return Err(error("job_assignment_not_proven"));
            }
            Ok(())
        }
        fn terminate(&self) -> Result<(), LaunchError> {
            if unsafe { TerminateJobObject(self.0, 95) } == 0 {
                return Err(native("job_terminate_failed"));
            }
            Ok(())
        }
        fn close(&mut self) -> Result<(), LaunchError> {
            if !self.0.is_null() {
                if unsafe { CloseHandle(self.0) } == 0 {
                    return Err(native("job_close_failed"));
                }
                self.0 = std::ptr::null_mut();
            }
            Ok(())
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }
    struct StartupAttributes {
        buffer: Vec<usize>,
        initialized: bool,
    }
    impl StartupAttributes {
        fn new(flags: u32) -> Result<Self, LaunchError> {
            let mut bytes = 0;
            let first = unsafe {
                InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, flags, &mut bytes)
            };
            if first != 0
                || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
                || bytes == 0
                || bytes > 65536
            {
                return Err(native("attribute_init_failed"));
            }
            let mut value = Self {
                buffer: vec![0; bytes.div_ceil(std::mem::size_of::<usize>())],
                initialized: false,
            };
            if unsafe {
                InitializeProcThreadAttributeList(value.as_mut_ptr(), 2, flags, &mut bytes)
            } == 0
            {
                return Err(native("attribute_init_failed"));
            }
            value.initialized = true;
            Ok(value)
        }
        fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.buffer.as_mut_ptr().cast()
        }
        fn set_handles(&mut self, kind: u32, handles: &[HANDLE]) -> Result<(), LaunchError> {
            if unsafe {
                UpdateProcThreadAttribute(
                    self.as_mut_ptr(),
                    0,
                    kind as usize,
                    handles.as_ptr().cast(),
                    std::mem::size_of_val(handles),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(native("attribute_update_failed"));
            }
            Ok(())
        }
    }
    impl Drop for StartupAttributes {
        fn drop(&mut self) {
            if self.initialized {
                unsafe {
                    DeleteProcThreadAttributeList(self.as_mut_ptr());
                }
            }
        }
    }
    fn owned(raw: HANDLE) -> std::os::windows::io::OwnedHandle {
        // Callers have just received an owned non-null native handle.
        unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) }
    }
    fn pipe_pair(
        child_reads: bool,
    ) -> Result<(fs::File, std::os::windows::io::OwnedHandle), LaunchError> {
        let (mut read, mut write) = (std::ptr::null_mut(), std::ptr::null_mut());
        if unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(
                &mut read,
                &mut write,
                std::ptr::null(),
                0,
            )
        } == 0
        {
            return Err(native("pipe_create_failed"));
        }
        let read = owned(read);
        let write = owned(write);
        let (parent, child) = if child_reads {
            (write, read)
        } else {
            (read, write)
        };
        if unsafe {
            SetHandleInformation(
                child.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        } == 0
        {
            return Err(native("pipe_inheritance_failed"));
        }
        Ok((fs::File::from(parent), child))
    }
    fn wide(value: &OsStr) -> Result<Vec<u16>, LaunchError> {
        let v = value.encode_wide().collect::<Vec<_>>();
        if v.contains(&0) {
            return Err(error("launch_policy_rejected"));
        }
        Ok(v.into_iter().chain(Some(0)).collect())
    }
    fn quote_arg(value: &OsStr) -> Result<Vec<u16>, LaunchError> {
        let mut q = vec![34];
        let mut slashes = 0;
        for unit in value.encode_wide() {
            if unit == 0 {
                return Err(error("launch_policy_rejected"));
            }
            if unit == 92 {
                slashes += 1;
                continue;
            }
            if unit == 34 {
                q.extend(std::iter::repeat_n(92, slashes * 2 + 1));
                q.push(34);
            } else {
                q.extend(std::iter::repeat_n(92, slashes));
                q.push(unit);
            }
            slashes = 0;
        }
        q.extend(std::iter::repeat_n(92, slashes * 2));
        q.push(34);
        Ok(q)
    }
    struct NativeChild {
        command_line: String,
        process: std::os::windows::io::OwnedHandle,
        thread: Option<std::os::windows::io::OwnedHandle>,
        stdin: Option<fs::File>,
        stdout: Option<fs::File>,
        stderr: Option<fs::File>,
    }
    impl AsRawHandle for NativeChild {
        fn as_raw_handle(&self) -> HANDLE {
            self.process.as_raw_handle()
        }
    }
    impl std::os::windows::io::AsHandle for NativeChild {
        fn as_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
            self.process.as_handle()
        }
    }
    impl NativeChild {
        fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
            match unsafe { WaitForSingleObject(self.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(self.as_raw_handle(), &mut code) } == 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(Some(ExitStatus::from_raw(code)))
                }
                _ => Err(std::io::Error::last_os_error()),
            }
        }
        fn wait(&mut self) -> std::io::Result<ExitStatus> {
            if unsafe { WaitForSingleObject(self.as_raw_handle(), u32::MAX) } != WAIT_OBJECT_0 {
                return Err(std::io::Error::last_os_error());
            }
            self.try_wait()?.ok_or_else(std::io::Error::last_os_error)
        }
        fn kill(&mut self) -> std::io::Result<()> {
            if unsafe { TerminateProcess(self.as_raw_handle(), 98) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        fn verify_job_not_inherited(&self, job: &Job) -> Result<(), LaunchError> {
            let mut raw = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    self.as_raw_handle(),
                    job.0,
                    GetCurrentProcess(),
                    &mut raw,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 {
                if unsafe { GetLastError() } == ERROR_INVALID_HANDLE {
                    return Ok(());
                }
                return Err(native("child_handle_inheritance_not_proven"));
            }
            let duplicate = owned(raw);
            // Equal handle values in different processes can name different objects.
            if unsafe { CompareObjectHandles(job.0, duplicate.as_raw_handle()) } != 0 {
                return Err(error("job_handle_inherited"));
            }
            Ok(())
        }
        fn observation(&self) -> Result<LaunchObservation, LaunchError> {
            let (mut c, mut e, mut k, mut u) = unsafe {
                (
                    std::mem::zeroed(),
                    std::mem::zeroed(),
                    std::mem::zeroed(),
                    std::mem::zeroed(),
                )
            };
            if unsafe { GetProcessTimes(self.as_raw_handle(), &mut c, &mut e, &mut k, &mut u) } == 0
            {
                return Err(native("process_identity_failed"));
            }
            Ok(LaunchObservation {
                stage: "before_resume",
                process_id: unsafe { GetProcessId(self.as_raw_handle()) },
                creation_time: (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime),
                job_binding_at_creation: true,
                job_membership_verified: true,
                pre_execution_limits_verified: true,
                job_handle_not_inherited: true,
            })
        }
    }
    struct Running {
        child: NativeChild,
        job: Job,
        reaped: bool,
    }
    impl Running {
        #[cfg(test)]
        fn start(command: Command) -> Result<Self, LaunchError> {
            let mut r = Self::start_suspended(command)?;
            r.resume()?;
            Ok(r)
        }
        fn start_suspended(command: Command) -> Result<Self, LaunchError> {
            let job = Job::new()?;
            let handle = job.0;
            Self::create(command, job, handle)
        }
        fn create(command: Command, job: Job, attribute_job: HANDLE) -> Result<Self, LaunchError> {
            job.verify_limits()?;
            let (stdin, child_in) = pipe_pair(true)?;
            let (stdout, child_out) = pipe_pair(false)?;
            let (stderr, child_err) = pipe_pair(false)?;
            let jobs = [attribute_job];
            let handles = [
                child_in.as_raw_handle(),
                child_out.as_raw_handle(),
                child_err.as_raw_handle(),
            ];
            let mut attrs = StartupAttributes::new(0)?;
            attrs.set_handles(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
            attrs.set_handles(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles)?;
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = handles[0];
            startup.StartupInfo.hStdOutput = handles[1];
            startup.StartupInfo.hStdError = handles[2];
            startup.lpAttributeList = attrs.as_mut_ptr();
            let app = wide(command.get_program())?;
            let mut args = quote_arg(command.get_program())?;
            for argument in command.get_args() {
                args.push(32);
                args.extend(quote_arg(argument)?);
            }
            args.push(0);
            let command_line = String::from_utf16_lossy(&args[..args.len() - 1]);
            let cwd = wide(
                command
                    .get_current_dir()
                    .ok_or_else(|| error("launch_policy_rejected"))?
                    .as_os_str(),
            )?;
            let mut entries = command
                .get_envs()
                .map(|(k, v)| {
                    v.map(|v| (k.to_owned(), v.to_owned()))
                        .ok_or_else(|| error("launch_policy_rejected"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
            if entries.len() != 6 {
                return Err(error("launch_policy_rejected"));
            }
            let mut env = Vec::<u16>::new();
            for (k, v) in entries {
                let mut entry = wide(&k)?;
                entry.pop();
                entry.push(61);
                let value = wide(&v)?;
                entry.extend(value);
                env.extend(entry);
            }
            env.push(0);
            let mut info = PROCESS_INFORMATION::default();
            // JOB_LIST is mandatory. No breakaway or post-create assignment fallback.
            let ok = unsafe {
                CreateProcessW(
                    app.as_ptr(),
                    args.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                    CREATE_SUSPENDED
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_NO_WINDOW,
                    env.as_ptr().cast(),
                    cwd.as_ptr(),
                    &startup.StartupInfo,
                    &mut info,
                )
            };
            if ok == 0 {
                return Err(native("spawn_failed"));
            }
            let child = NativeChild {
                command_line,
                process: owned(info.hProcess),
                thread: Some(owned(info.hThread)),
                stdin: Some(stdin),
                stdout: Some(stdout),
                stderr: Some(stderr),
            };
            let running = Self {
                child,
                job,
                reaped: false,
            };
            // Failures here drop Running and terminate/reap its suspended child.
            running.job.verify_limits()?;
            running.job.verify_member(&running.child)?;
            running.child.verify_job_not_inherited(&running.job)?;
            Ok(running)
        }
        fn resume(&mut self) -> Result<(), LaunchError> {
            let thread = self
                .child
                .thread
                .take()
                .ok_or_else(|| error("thread_already_resumed"))?;
            if unsafe { ResumeThread(thread.as_raw_handle()) } != 1 {
                return Err(native("resume_failed"));
            }
            Ok(())
        }
        fn stop(&mut self) -> Result<ExitStatus, LaunchError> {
            self.job.terminate()?;
            let status = self.child.wait().map_err(|e| LaunchError {
                code: "wait_failed",
                os_error: e.raw_os_error(),
            })?;
            self.reaped = true;
            Ok(status)
        }
    }
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.job.close();
            if !self.reaped {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
    fn exact_file(path: &Path, expected: &[u8]) -> Result<(), LaunchError> {
        no_reparse(path).map_err(|e| error(e.code()))?;
        no_extra_streams_v2(path).map_err(|e| error(e.code()))?;
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|_| error("synthetic_fixture_invalid"))?
            .take(expected.len() as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("synthetic_fixture_invalid"))?;
        if bytes != expected {
            return Err(error("synthetic_fixture_invalid"));
        }
        Ok(())
    }
    pub(super) fn standalone_build_artifact() -> Result<PathBuf, LaunchError> {
        let current = std::env::current_exe().map_err(|_| error("ipc_build_source_invalid"))?;
        let stem = current.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let suffix = stem
            .strip_prefix("service_contract-")
            .or_else(|| stem.strip_prefix("launch_contract-"));
        let deps = current
            .parent()
            .ok_or_else(|| error("ipc_build_source_invalid"))?;
        let profile = deps
            .parent()
            .ok_or_else(|| error("ipc_build_source_invalid"))?;
        if !suffix.is_some_and(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            || deps.file_name() != Some(OsStr::new("deps"))
            || !matches!(
                profile.file_name().and_then(|s| s.to_str()),
                Some("debug" | "release")
            )
        {
            return Err(error("ipc_build_source_invalid"));
        }
        validate_root_v2(profile).map_err(|e| error(e.code()))?;
        let artifact = profile.join(STANDALONE_IPC_BIN);
        let info = no_reparse(&artifact).map_err(|e| error(e.code()))?;
        no_extra_streams_v2(&artifact).map_err(|e| error(e.code()))?;
        if !info.is_file() || info.len() == 0 || info.len() > 256 * 1024 * 1024 {
            return Err(error("ipc_build_source_invalid"));
        }
        Ok(artifact)
    }
    fn validate(request: &LaunchRequest) -> Result<SyntheticCase, LaunchError> {
        let standalone = matches!(request.target, LaunchTarget::StandaloneIpc);
        let ipc = matches!(
            request.target,
            LaunchTarget::SyntheticIpc | LaunchTarget::StandaloneIpc
        );
        let case = match request.target {
            LaunchTarget::Synthetic(c) => c,
            LaunchTarget::SyntheticIpc | LaunchTarget::StandaloneIpc => SyntheticCase::Wait,
            _ => return Err(error("gateway_release_not_qualified")),
        };
        let executable = if ipc {
            request.release_root.join(if standalone {
                STANDALONE_IPC_ENTRY
            } else {
                IPC_FIXTURE_ENTRY
            })
        } else {
            PathBuf::from(NODE_TEST_TOOL)
        };
        if request.executable != executable
            || (ipc && request.timeout != Duration::from_secs(5))
            || request.entry != SYNTHETIC_ENTRY
            || !request.arguments.is_empty()
            || !request.environment_overrides.is_empty()
            || request.working_directory.as_os_str()
                != request.release_root.join("work").as_os_str()
            || request.timeout < Duration::from_millis(10)
            || request.timeout > Duration::from_secs(5)
            || request.release_root.parent() != Some(std::env::temp_dir().as_path())
        {
            return Err(error("launch_policy_rejected"));
        }
        // TEMP controls placement only, never identity or authorization. A repository is forbidden
        // even if a caller points TEMP into it; the working directory is always this fixture's work/.
        if request
            .release_root
            .ancestors()
            .any(|p| fs::symlink_metadata(p.join(".git")).is_ok())
        {
            return Err(error("launch_policy_rejected"));
        }
        validate_release_v2(&request.release_root, &request.manifest)
            .map_err(|e| error(e.code()))?;
        let m: Value =
            serde_json::from_slice(&request.manifest).map_err(|_| error("manifest_invalid"))?;
        let files = m["files"]
            .as_array()
            .ok_or_else(|| error("synthetic_fixture_invalid"))?;
        let mut expected = FIXTURE_FILES.to_vec();
        if ipc {
            expected.push(if standalone {
                STANDALONE_IPC_ENTRY
            } else {
                IPC_FIXTURE_ENTRY
            });
            expected.sort_unstable();
        }
        if files.len() != expected.len()
            || files.iter().zip(expected).any(|(x, p)| x["path"] != p)
            || m["directories"] != serde_json::json!(FIXTURE_DIRS)
        {
            return Err(error("synthetic_fixture_invalid"));
        }
        exact_file(
            &request.release_root.join(SYNTHETIC_ENTRY),
            SYNTHETIC_ENTRY_SOURCE.as_bytes(),
        )?;
        if standalone {
            // V2 covers the actual copy; compare its bounded raw bytes with the
            // independently located fixed Cargo bin, never a caller-supplied hash.
            let source = standalone_build_artifact()?;
            if hash_tool(&source)? != hash_tool(&executable)? {
                return Err(error("standalone_ipc_identity_mismatch"));
            }
        } else if ipc {
            // This is a closed test-harness entry, not an executable supplied by
            // the caller. The only accepted copy is the current integration-test
            // image, byte-for-byte, in the V2-validated candidate tree. These
            // unprotected test bytes do not constitute runtime code attestation.
            let current = std::env::current_exe().map_err(|_| error("ipc_fixture_invalid"))?;
            let stem = current.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let suffix = stem
                .strip_prefix("service_contract-")
                .or_else(|| stem.strip_prefix("launch_contract-"));
            if !suffix.is_some_and(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(error("ipc_fixture_invalid"));
            }
            validate_root_v2(
                current
                    .parent()
                    .ok_or_else(|| error("ipc_fixture_invalid"))?,
            )
            .map_err(|e| error(e.code()))?;
            no_reparse(&current).map_err(|e| error(e.code()))?;
            no_extra_streams_v2(&current).map_err(|e| error(e.code()))?;
            if hash_tool(&current)? != hash_tool(&executable)? {
                return Err(error("ipc_fixture_identity_mismatch"));
            }
        }
        exact_file(
            &request.release_root.join("app/package.json"),
            SYNTHETIC_PACKAGE.as_bytes(),
        )?;
        if !standalone {
            validate_root_v2(Path::new(NODE_TEST_TOOL).parent().unwrap())
                .map_err(|e| error(e.code()))?;
            no_reparse(Path::new(NODE_TEST_TOOL)).map_err(|e| error(e.code()))?;
            no_extra_streams_v2(Path::new(NODE_TEST_TOOL)).map_err(|e| error(e.code()))?;
        }
        if request.cancel.0.load(Ordering::SeqCst) {
            return Err(error("cancelled_before_spawn"));
        }
        Ok(case)
    }
    fn command(root: &Path, case: SyntheticCase) -> Command {
        let scenario = match case {
            SyntheticCase::Normal => "normal",
            SyntheticCase::Nonzero => "nonzero",
            SyntheticCase::Wait => "wait",
        };
        let mut c = Command::new(NODE_TEST_TOOL);
        c.args(["--no-addons", "--no-global-search-paths", "--"])
            .arg(root.join(SYNTHETIC_ENTRY))
            .current_dir(root.join("work"))
            .env_clear()
            .env("SystemRoot", "C:\\Windows")
            .env("WINDIR", "C:\\Windows")
            .env("SYSTEMDRIVE", "C:")
            .env("TEMP", root.join("temp"))
            .env("TMP", root.join("temp"))
            .env("R2_SCENARIO", scenario)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x08000000); // CREATE_NO_WINDOW
        c
    }
    fn ipc_command(root: &Path, standalone: bool) -> Command {
        let c = command(root, SyntheticCase::Wait);
        // Rebuild instead of appending to the Node argument list.
        let mut fixed = Command::new(root.join(if standalone {
            STANDALONE_IPC_ENTRY
        } else {
            IPC_FIXTURE_ENTRY
        }));
        if !standalone {
            fixed.args(["--exact", IPC_FIXTURE_TEST, "--ignored", "--nocapture"]);
        }
        fixed.current_dir(root.join("work")).env_clear();
        for (key, value) in c.get_envs() {
            if let Some(value) = value {
                fixed.env(key, value);
            }
        }
        fixed
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x08000000);
        fixed
    }
    fn output(reader: Option<impl Read>) -> Result<String, LaunchError> {
        let mut bytes = Vec::new();
        reader
            .ok_or_else(|| error("output_unavailable"))?
            .take(MAX_OUTPUT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("output_read_failed"))?;
        if bytes.len() as u64 > MAX_OUTPUT {
            return Err(error("output_resource_limit"));
        }
        String::from_utf8(bytes).map_err(|_| error("output_invalid"))
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StartupAck {
        scenario: String,
        cwd: String,
        #[serde(rename = "execArgv")]
        exec_argv: Vec<String>,
        #[serde(deserialize_with = "startup_environment")]
        environment: std::collections::BTreeMap<String, String>,
    }
    fn startup_environment<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<std::collections::BTreeMap<String, String>, D::Error> {
        struct Environment;
        impl<'de> serde::de::Visitor<'de> for Environment {
            type Value = std::collections::BTreeMap<String, String>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a unique environment object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut result = Self::Value::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if result.insert(key.to_ascii_uppercase(), value).is_some() {
                        return Err(serde::de::Error::custom("duplicate environment key"));
                    }
                }
                Ok(result)
            }
        }
        deserializer.deserialize_map(Environment)
    }
    fn validate_startup(line: &[u8], root: &Path, case: SyntheticCase) -> Result<(), LaunchError> {
        if line.len() as u64 > MAX_OUTPUT || line.last() != Some(&b'\n') {
            return Err(error("startup_invalid"));
        }
        let ack: StartupAck = serde_json::from_slice(line).map_err(|_| error("startup_invalid"))?;
        let scenario = match case {
            SyntheticCase::Normal => "normal",
            SyntheticCase::Nonzero => "nonzero",
            SyntheticCase::Wait => "wait",
        };
        let expected = [
            ("SYSTEMROOT", "C:\\Windows".to_owned()),
            ("WINDIR", "C:\\Windows".to_owned()),
            ("SYSTEMDRIVE", "C:".to_owned()),
            ("TEMP", root.join("temp").to_string_lossy().into_owned()),
            ("TMP", root.join("temp").to_string_lossy().into_owned()),
            ("R2_SCENARIO", scenario.to_owned()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect::<std::collections::BTreeMap<_, _>>();
        if ack.scenario != scenario
            || ack.cwd != root.join("work").to_string_lossy()
            || ack.exec_argv != ["--no-addons", "--no-global-search-paths"]
            || ack.environment != expected
        {
            return Err(error("startup_invalid"));
        }
        Ok(())
    }
    type Reader = thread::JoinHandle<Result<String, LaunchError>>;
    /// Owns every reader together with the only process that can keep its pipe open.
    /// Drop always kills/reaps/closes the Job before joining, including unwinding.
    struct Supervised {
        running: Running,
        stdout: Option<Reader>,
        stderr: Option<Reader>,
        startup: Receiver<Result<Vec<u8>, LaunchError>>,
    }
    impl Supervised {
        fn new(running: Running) -> Result<Self, LaunchError> {
            let (sender, startup) = mpsc::channel();
            let mut value = Self {
                running,
                stdout: None,
                stderr: None,
                startup,
            };
            let mut stdout = value
                .running
                .child
                .stdout
                .take()
                .ok_or_else(|| error("output_unavailable"))?;
            value.stdout = Some(
                thread::Builder::new()
                    .name("r2-stdout".into())
                    .spawn(move || {
                        let mut bytes = Vec::new();
                        let first = loop {
                            let mut byte = [0u8];
                            match stdout.read(&mut byte) {
                                Ok(0) => break Err(error("startup_eof")),
                                Ok(_) => {
                                    bytes.push(byte[0]);
                                    if bytes.len() as u64 > MAX_OUTPUT {
                                        break Err(error("output_resource_limit"));
                                    }
                                    if byte[0] == b'\n' {
                                        break Ok(bytes.clone());
                                    }
                                }
                                Err(_) => break Err(error("output_read_failed")),
                            }
                        };
                        let valid_line = first.is_ok();
                        let _ = sender.send(first);
                        if !valid_line {
                            return String::from_utf8(bytes).map_err(|_| error("output_invalid"));
                        }
                        stdout
                            .take(MAX_OUTPUT + 1 - bytes.len() as u64)
                            .read_to_end(&mut bytes)
                            .map_err(|_| error("output_read_failed"))?;
                        if bytes.len() as u64 > MAX_OUTPUT {
                            return Err(error("output_resource_limit"));
                        }
                        String::from_utf8(bytes).map_err(|_| error("output_invalid"))
                    })
                    .map_err(|_| error("output_reader_start_failed"))?,
            );
            let stderr = value
                .running
                .child
                .stderr
                .take()
                .ok_or_else(|| error("output_unavailable"))?;
            value.stderr = Some(
                thread::Builder::new()
                    .name("r2-stderr".into())
                    .spawn(move || output(Some(stderr)))
                    .map_err(|_| error("output_reader_start_failed"))?,
            );
            Ok(value)
        }
        fn cleanup(&mut self) {
            let _ = self.running.job.close();
            if !self.running.reaped {
                let _ = self.running.child.kill();
                if self.running.child.wait().is_ok() {
                    self.running.reaped = true;
                }
            }
            self.running.child.stdin.take();
        }
        fn join(&mut self) -> Result<(String, String), LaunchError> {
            // Join both even if the first one failed. Never drop a live JoinHandle.
            let stdout = self.stdout.take().map(|reader| reader.join());
            let stderr = self.stderr.take().map(|reader| reader.join());
            let extract = |joined: Option<std::thread::Result<Result<String, LaunchError>>>| {
                joined
                    .ok_or_else(|| error("output_unavailable"))?
                    .map_err(|_| error("output_reader_panicked"))?
            };
            Ok((extract(stdout)?, extract(stderr)?))
        }
    }
    impl Drop for Supervised {
        fn drop(&mut self) {
            self.cleanup();
            if let Some(reader) = self.stdout.take() {
                let _ = reader.join();
            }
            if let Some(reader) = self.stderr.take() {
                let _ = reader.join();
            }
        }
    }
    fn await_startup(
        supervised: &mut Supervised,
        request: &LaunchRequest,
        case: SyntheticCase,
        start: Instant,
        controlled: bool,
    ) -> Result<Option<LaunchOutcome>, LaunchError> {
        loop {
            let cancelled = request.cancel.0.load(Ordering::SeqCst);
            let expired = start.elapsed() >= request.timeout;
            if cancelled || expired {
                if controlled {
                    return Err(error(if cancelled {
                        "startup_cancelled"
                    } else {
                        "startup_timeout"
                    }));
                }
                supervised.running.stop()?;
                return Ok(Some(if cancelled {
                    LaunchOutcome::Aborted
                } else {
                    LaunchOutcome::TimedOut
                }));
            }
            match supervised.startup.recv_timeout(Duration::from_millis(5)) {
                Ok(line) => {
                    if request.cancel.0.load(Ordering::SeqCst) || start.elapsed() >= request.timeout
                    {
                        continue;
                    }
                    validate_startup(&line?, &request.release_root, case)?;
                    return Ok(None);
                }
                Err(RecvTimeoutError::Disconnected) => return Err(error("startup_eof")),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if controlled
                && supervised
                    .running
                    .child
                    .try_wait()
                    .map_err(|_| error("wait_failed"))?
                    .is_some()
            {
                return Err(error("startup_child_exited"));
            }
        }
    }
    fn tool_hash() -> Result<String, LaunchError> {
        hash_tool(Path::new(NODE_TEST_TOOL))
    }
    fn hash_tool(path: &Path) -> Result<String, LaunchError> {
        let file = fs::File::open(path).map_err(|_| error("test_tool_unavailable"))?;
        let mut reader = file.take(256 * 1024 * 1024 + 1);
        let mut hash = Sha256::new();
        let mut bytes = [0u8; 65536];
        let mut total = 0;
        loop {
            let n = reader
                .read(&mut bytes)
                .map_err(|_| error("test_tool_unavailable"))?;
            if n == 0 {
                break;
            }
            total += n;
            if total > 256 * 1024 * 1024 {
                return Err(error("test_tool_resource_limit"));
            }
            hash.update(&bytes[..n]);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
    fn stop_before_go(
        running: &mut Running,
        cancel: &CancelToken,
        timeout: Duration,
        start: Instant,
    ) -> Result<Option<LaunchOutcome>, LaunchError> {
        let outcome = if cancel.0.load(Ordering::SeqCst) {
            Some(LaunchOutcome::Aborted)
        } else if start.elapsed() >= timeout {
            Some(LaunchOutcome::TimedOut)
        } else {
            None
        };
        if outcome.is_some() {
            running.stop()?;
        }
        Ok(outcome)
    }
    fn wait_outcome(
        running: &mut Running,
        cancel: &CancelToken,
        timeout: Duration,
        start: Instant,
        events: &mut Vec<LaunchEvent>,
    ) -> Result<LaunchOutcome, LaunchError> {
        loop {
            if let Some(status) = running.child.try_wait().map_err(|e| LaunchError {
                code: "wait_failed",
                os_error: e.raw_os_error(),
            })? {
                running.child.wait().map_err(|e| LaunchError {
                    code: "wait_failed",
                    os_error: e.raw_os_error(),
                })?;
                running.reaped = true;
                let code = status.code().unwrap_or(-1);
                events.push(if code == 0 {
                    LaunchEvent::Exited
                } else {
                    LaunchEvent::NonzeroExited
                });
                return Ok(LaunchOutcome::Exited(code));
            }
            if cancel.0.load(Ordering::SeqCst) {
                running.stop()?;
                events.push(LaunchEvent::Aborted);
                return Ok(LaunchOutcome::Aborted);
            }
            if start.elapsed() >= timeout {
                running.stop()?;
                events.push(LaunchEvent::TimedOut);
                return Ok(LaunchOutcome::TimedOut);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    pub(super) fn launch(request: LaunchRequest) -> Result<LaunchReport, LaunchError> {
        launch_inner(request, None)
    }
    pub(super) fn launch_inner(
        request: LaunchRequest,
        observer: Option<&mut dyn FnMut(&LaunchObservation)>,
    ) -> Result<LaunchReport, LaunchError> {
        launch_core(request, observer, None)
    }
    pub(super) fn launch_controlled(
        request: LaunchRequest,
        on_ready: &mut dyn FnMut(StartedChild) -> Result<(), LaunchError>,
    ) -> Result<LaunchReport, LaunchError> {
        launch_core(request, None, Some(on_ready))
    }
    pub(super) fn launch_core(
        request: LaunchRequest,
        mut observer: Option<&mut dyn FnMut(&LaunchObservation)>,
        mut on_ready: Option<&mut dyn FnMut(StartedChild) -> Result<(), LaunchError>>,
    ) -> Result<LaunchReport, LaunchError> {
        if matches!(
            request.target,
            LaunchTarget::SyntheticIpc | LaunchTarget::StandaloneIpc
        ) {
            return Err(error("ipc_worker_required"));
        }
        launch_core_inner(request, observer.take(), on_ready.take(), None)
    }
    pub(super) fn launch_ipc(
        request: LaunchRequest,
        gate: &[u8],
        on_ready: &mut dyn FnMut(StartedChild) -> Result<bool, LaunchError>,
    ) -> Result<LaunchReport, LaunchError> {
        if !matches!(
            request.target,
            LaunchTarget::SyntheticIpc | LaunchTarget::StandaloneIpc
        ) || gate.len() > 2048
            || gate.is_empty()
        {
            return Err(error("ipc_fixture_invalid"));
        }
        let mut authenticated = false;
        let mut callback = |child| {
            authenticated = on_ready(child)?;
            Ok(())
        };
        let mut report = launch_core_inner(request, None, Some(&mut callback), Some(gate))?;
        // A cleanup report after pre-auth cancellation is not a startup receipt.
        // The boolean is internal and derived by R4 only from the real R3 receipt.
        report.startup_confirmed = authenticated;
        Ok(report)
    }
    fn launch_core_inner(
        request: LaunchRequest,
        mut observer: Option<&mut dyn FnMut(&LaunchObservation)>,
        mut on_ready: Option<&mut dyn FnMut(StartedChild) -> Result<(), LaunchError>>,
        ipc_gate: Option<&[u8]>,
    ) -> Result<LaunchReport, LaunchError> {
        let case = validate(&request)?;
        let test_tool_sha256 = if ipc_gate.is_some() {
            hash_tool(&request.executable)?
        } else {
            tool_hash()?
        };
        let start = Instant::now();
        let cmd = if ipc_gate.is_some() {
            ipc_command(
                &request.release_root,
                matches!(request.target, LaunchTarget::StandaloneIpc),
            )
        } else {
            command(&request.release_root, case)
        };
        let mut running = Running::start_suspended(cmd)?;
        if let Some(callback) = observer.as_mut() {
            callback(&running.child.observation()?);
        }
        running.resume()?;
        let mut supervised = Supervised::new(running)?;
        let mut events = vec![LaunchEvent::Created, LaunchEvent::JobAssigned];
        let mut startup_confirmed = false;
        // Expired/cancelled setup never grants the payload its GO handshake. This is a
        // deadline decision, not an atomic scheduling guarantee against OS preemption.
        let outcome = if let Some(outcome) = stop_before_go(
            &mut supervised.running,
            &request.cancel,
            request.timeout,
            start,
        )? {
            if on_ready.is_some() {
                return Err(error(if outcome == LaunchOutcome::Aborted {
                    "startup_cancelled"
                } else {
                    "startup_timeout"
                }));
            }
            events.push(if outcome == LaunchOutcome::Aborted {
                LaunchEvent::Aborted
            } else {
                LaunchEvent::TimedOut
            });
            outcome
        } else {
            let mut stdin = supervised
                .running
                .child
                .stdin
                .take()
                .ok_or_else(|| error("stdin_unavailable"))?;
            stdin
                .write_all(b"R2_GO\n")
                .map_err(|_| error("handshake_failed"))?;
            if let Some(gate) = ipc_gate {
                stdin
                    .write_all(gate)
                    .map_err(|_| error("handshake_failed"))?;
            }
            drop(stdin);
            events.push(LaunchEvent::HandshakeSent);
            let startup = if ipc_gate.is_some() {
                // R3 authentication, not libtest/stdout text, gates readiness.
                None
            } else {
                await_startup(&mut supervised, &request, case, start, on_ready.is_some())?
            };
            if let Some(outcome) = startup {
                events.push(if outcome == LaunchOutcome::Aborted {
                    LaunchEvent::Aborted
                } else {
                    LaunchEvent::TimedOut
                });
                outcome
            } else {
                startup_confirmed = true;
                if let Some(callback) = on_ready.as_mut() {
                    let proof = StartedChild {
                        process: supervised
                            .running
                            .child
                            .as_handle()
                            .try_clone_to_owned()
                            .map_err(|_| native("startup_probe_failed"))?,
                    };
                    if !proof.is_alive()? {
                        return Err(error("startup_child_exited"));
                    }
                    if request.cancel.0.load(Ordering::SeqCst) {
                        return Err(error("startup_cancelled"));
                    }
                    if start.elapsed() >= request.timeout {
                        return Err(error("startup_timeout"));
                    }
                    callback(proof)?;
                    // ACK has been accepted. A subsequent cancellation belongs to
                    // the running lifecycle and must retain its cleanup report.
                    // Cancellation before ACK still fails in await_startup above.
                    if supervised
                        .running
                        .child
                        .try_wait()
                        .map_err(|_| native("wait_failed"))?
                        .is_some()
                    {
                        return Err(error("startup_child_exited"));
                    }
                }
                wait_outcome(
                    &mut supervised.running,
                    &request.cancel,
                    request.timeout,
                    start,
                    &mut events,
                )?
            }
        };
        supervised.running.job.close()?;
        supervised.cleanup();
        let (stdout, stderr) = supervised.join()?;
        Ok(LaunchReport {
            executable_path: request.executable.clone(),
            command_line: supervised.running.child.command_line.clone(),
            startup_confirmed,
            output_readers_joined: true,
            job_binding_at_creation: true,
            job_membership_verified: true,
            pre_execution_limits_verified: true,
            job_handle_not_inherited: true,
            kill_on_job_close_verified: true,
            outcome,
            events,
            stdout,
            stderr,
            elapsed: start.elapsed(),
            process_reaped: supervised.running.reaped,
            job_closed: supervised.running.job.0.is_null(),
            test_tool_sha256,
            synthetic_entry_sha256: format!("{:x}", Sha256::digest(SYNTHETIC_ENTRY_SOURCE)),
        })
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::io::AsHandle;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            #[link_name = "GetProcessHandleCount"]
            fn get_process_handle_count(process: HANDLE, count: *mut u32) -> i32;
            #[link_name = "WaitForSingleObject"]
            fn wait_for_single_object(handle: HANDLE, millis: u32) -> u32;
        }
        fn handles() -> u32 {
            let mut n = 0;
            assert_ne!(
                unsafe { get_process_handle_count(-1isize as HANDLE, &mut n) },
                0
            );
            n
        }
        struct CoreFixture(PathBuf);
        impl CoreFixture {
            fn new() -> Self {
                use std::sync::atomic::AtomicU64;
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let root = std::env::temp_dir().join(format!(
                    "r2-resource-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                fs::create_dir(&root).unwrap();
                for p in ["app/src/gateway", "temp", "work"] {
                    fs::create_dir_all(root.join(p)).unwrap();
                }
                fs::write(root.join(SYNTHETIC_ENTRY), SYNTHETIC_ENTRY_SOURCE).unwrap();
                fs::write(root.join("app/package.json"), SYNTHETIC_PACKAGE).unwrap();
                Self(root)
            }
        }
        impl Drop for CoreFixture {
            fn drop(&mut self) {
                assert!(self.0.is_absolute() && self.0.starts_with(std::env::temp_dir()));
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
        fn startup_request(f: &CoreFixture) -> LaunchRequest {
            LaunchRequest {
                target: LaunchTarget::Synthetic(SyntheticCase::Wait),
                release_root: f.0.clone(),
                manifest: vec![],
                executable: PathBuf::from(NODE_TEST_TOOL),
                entry: SYNTHETIC_ENTRY.into(),
                arguments: vec![],
                working_directory: f.0.join("work"),
                environment_overrides: vec![],
                timeout: Duration::from_millis(100),
                cancel: CancelToken::new(),
            }
        }
        #[test]
        fn startup_ack_rejects_missing_or_changed_process_facts() {
            let f = CoreFixture::new();
            let valid = serde_json::json!({
                "scenario":"wait", "cwd":f.0.join("work"),
                "execArgv":["--no-addons", "--no-global-search-paths"],
                "environment":{"SystemRoot":"C:\\Windows", "WINDIR":"C:\\Windows", "SYSTEMDRIVE":"C:",
                    "TEMP":f.0.join("temp"), "TMP":f.0.join("temp"), "R2_SCENARIO":"wait"}
            });
            let encode = |value: &Value| {
                let mut b = serde_json::to_vec(value).unwrap();
                b.push(b'\n');
                b
            };
            validate_startup(&encode(&valid), &f.0, SyntheticCase::Wait).unwrap();
            let mut invalid = vec![serde_json::json!({})];
            for key in ["scenario", "cwd", "execArgv", "environment"] {
                let mut changed = valid.clone();
                changed.as_object_mut().unwrap().remove(key);
                invalid.push(changed);
            }
            for (key, value) in [
                ("scenario", serde_json::json!("normal")),
                ("cwd", serde_json::json!("C:\\wrong")),
                ("execArgv", serde_json::json!(["--inspect"])),
            ] {
                let mut changed = valid.clone();
                changed[key] = value;
                invalid.push(changed);
            }
            let mut extra = valid.clone();
            extra["environment"]["NODE_OPTIONS"] = serde_json::json!("--inspect");
            invalid.push(extra);
            let mut changed = valid.clone();
            changed["environment"]["TEMP"] = serde_json::json!("C:\\wrong");
            invalid.push(changed);
            let mut extra = valid.clone();
            extra["unexpected"] = serde_json::json!(true);
            invalid.push(extra);
            for value in invalid {
                assert_eq!(
                    validate_startup(&encode(&value), &f.0, SyntheticCase::Wait)
                        .unwrap_err()
                        .code(),
                    "startup_invalid"
                );
            }
            for invalid in [b"\n".as_slice(), b"not json\n", b"{}", b"{}\n{}\n"] {
                assert_eq!(
                    validate_startup(invalid, &f.0, SyntheticCase::Wait)
                        .unwrap_err()
                        .code(),
                    "startup_invalid"
                );
            }
            let duplicated = String::from_utf8(encode(&valid)).unwrap().replace(
                "\"SystemRoot\":",
                "\"SYSTEMROOT\":\"C:\\\\Windows\",\"SystemRoot\":",
            );
            assert_eq!(
                validate_startup(duplicated.as_bytes(), &f.0, SyntheticCase::Wait)
                    .unwrap_err()
                    .code(),
                "startup_invalid"
            );
        }
        #[test]
        fn startup_without_go_times_out_and_eof_is_rejected_with_joined_readers() {
            let f = CoreFixture::new();
            for close_stdin in [false, true] {
                let mut request = startup_request(&f);
                if close_stdin {
                    request.timeout = Duration::from_secs(2);
                }
                let running = Running::start(command(&f.0, SyntheticCase::Wait)).unwrap();
                let mut supervised = Supervised::new(running).unwrap();
                if close_stdin {
                    supervised.running.child.stdin.take();
                }
                let result = await_startup(
                    &mut supervised,
                    &request,
                    SyntheticCase::Wait,
                    Instant::now(),
                    true,
                )
                .unwrap_err();
                assert!(if close_stdin {
                    ["startup_eof", "startup_child_exited"].contains(&result.code())
                } else {
                    result.code() == "startup_timeout"
                });
                supervised.cleanup();
                assert!(supervised.running.reaped && supervised.running.job.0.is_null());
                let (stdout, stderr) = supervised.join().unwrap();
                assert!(stdout.is_empty() && stderr.is_empty());
                assert!(supervised.stdout.is_none() && supervised.stderr.is_none());
            }
        }
        #[test]
        fn startup_cancellation_and_unwind_join_readers_after_original_process_cleanup() {
            let f = CoreFixture::new();
            let request = startup_request(&f);
            request.cancel.cancel();
            let mut supervised =
                Supervised::new(Running::start(command(&f.0, SyntheticCase::Wait)).unwrap())
                    .unwrap();
            assert_eq!(
                await_startup(
                    &mut supervised,
                    &request,
                    SyntheticCase::Wait,
                    Instant::now(),
                    true
                )
                .unwrap_err()
                .code(),
                "startup_cancelled"
            );
            supervised.cleanup();
            supervised.join().unwrap();
            drop(supervised);
            let before = handles();
            let running = Running::start(command(&f.0, SyntheticCase::Wait)).unwrap();
            let probe = StartedChild {
                process: running.child.as_handle().try_clone_to_owned().unwrap(),
            };
            assert!(probe.is_alive().unwrap());
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _supervised = Supervised::new(running).unwrap();
                panic!("controlled callback unwind cleanup");
            }));
            assert!(unwound.is_err());
            assert!(!probe.is_alive().unwrap());
            drop(probe);
            assert_eq!(handles(), before);
        }
        #[test]
        fn expired_deadline_stops_real_child_before_go() {
            let f = CoreFixture::new();
            let mut running = Running::start(command(&f.0, SyntheticCase::Wait)).unwrap();
            let result = stop_before_go(
                &mut running,
                &CancelToken::new(),
                Duration::from_millis(10),
                Instant::now() - Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(result, Some(LaunchOutcome::TimedOut));
            assert!(running.reaped);
            running.job.close().unwrap();
            assert!(output(running.child.stdout.take()).unwrap().is_empty());
            println!("EXPIRED_DEADLINE_NO_GO=PASS");
        }
        #[test]
        fn spawn_failure_releases_job_and_pipe_handles() {
            let root = std::env::temp_dir().join("r2-missing-work-directory");
            assert!(!root.exists());
            let before = handles();
            for _ in 0..16 {
                let e = Running::start(command(&root, SyntheticCase::Normal))
                    .err()
                    .expect("OS must reject nonexistent cwd");
                assert_eq!(e.code(), "spawn_failed");
                assert!(e.os_error.is_some());
                println!("SPAWN_FAILURE code={} native={:?}", e.code(), e.os_error);
            }
            let after = handles();
            assert_eq!(before, after);
            println!("SPAWN_FAILURE_HANDLE_CLEANUP=PASS");
        }
        #[test]
        fn closing_job_terminates_owned_child_without_pid_lookup() {
            let f = CoreFixture::new();
            let mut running = Running::start(command(&f.0, SyntheticCase::Wait)).unwrap();
            let owned = running.child.as_handle().try_clone_to_owned().unwrap();
            // SAFETY: this owned duplicate references our child; zero timeout only observes liveness.
            assert_eq!(
                unsafe { wait_for_single_object(owned.as_raw_handle(), 0) },
                258
            );
            running.job.close().unwrap();
            assert_eq!(
                unsafe { wait_for_single_object(owned.as_raw_handle(), 2000) },
                0
            );
            running.child.wait().unwrap();
            running.reaped = true;
            drop(running);
            drop(owned);
            println!("JOB_CLOSE_TERMINATION_HANDLE_VERIFIED=PASS");
        }
        #[test]
        fn invalid_job_is_rejected_before_child_creation() {
            let f = CoreFixture::new();
            let before = handles();
            let mut job = Job::new().unwrap();
            job.close().unwrap();
            let e = Running::create(
                command(&f.0, SyntheticCase::Wait),
                job,
                std::ptr::null_mut(),
            )
            .err()
            .expect("closed Job must fail before creation");
            assert_eq!(e.code(), "job_closed");
            assert!(e.os_error.is_none());
            assert_eq!(handles(), before);
            println!(
                "CLOSED_JOB_DOMAIN_REJECTION=true NO_IMPLICIT_CURRENT_JOB=true NO_FALLBACK=true"
            );
        }
        #[test]
        fn active_synthetic_payload_is_aborted_and_reaped() {
            use std::io::{BufRead, BufReader};
            let f = CoreFixture::new();
            let mut running = Running::start(command(&f.0, SyntheticCase::Wait)).unwrap();
            running
                .child
                .stdin
                .take()
                .unwrap()
                .write_all(b"R2_GO\n")
                .unwrap();
            let stdout = running.child.stdout.take().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let reader = thread::spawn(move || {
                let mut line = String::new();
                let result = BufReader::new(stdout.take(MAX_OUTPUT + 1))
                    .read_line(&mut line)
                    .map(|_| line);
                let _ = tx.send(result);
            });
            let line = rx.recv_timeout(Duration::from_secs(2));
            if line.is_err() {
                running.stop().unwrap();
                reader.join().unwrap();
                panic!("fixed payload did not acknowledge GO");
            }
            let line = line.unwrap().unwrap();
            reader.join().unwrap();
            let observed: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(observed["scenario"], "wait");
            let token = CancelToken::new();
            token.cancel();
            let mut events = vec![
                LaunchEvent::Created,
                LaunchEvent::JobAssigned,
                LaunchEvent::HandshakeSent,
            ];
            assert_eq!(
                wait_outcome(
                    &mut running,
                    &token,
                    Duration::from_secs(2),
                    Instant::now(),
                    &mut events
                )
                .unwrap(),
                LaunchOutcome::Aborted
            );
            running.job.close().unwrap();
            assert!(running.reaped && events.contains(&LaunchEvent::Aborted));
            println!("ACTIVE_PAYLOAD_ACKNOWLEDGED=true ABORTED=true REAPED=true JOB_CLOSED=true");
        }
        #[test]
        fn attribute_initialization_failure_rejects_without_resource_growth() {
            let before = handles();
            for _ in 0..16 {
                let e = StartupAttributes::new(1)
                    .err()
                    .expect("reserved attribute flags must fail");
                assert_eq!(e.code(), "attribute_init_failed");
                assert_eq!(e.os_error, Some(87));
            }
            assert_eq!(handles(), before);
            println!(
                "ATTRIBUTE_INITIALIZATION_FAILURE_NATIVE=87 NO_SPAWN=true HANDLE_CLEANUP=true"
            );
        }
        #[test]
        fn invalid_creation_job_attribute_does_not_fall_back_to_assignment() {
            let f = CoreFixture::new();
            let before = handles();
            let e = Running::create(
                command(&f.0, SyntheticCase::Wait),
                Job::new().unwrap(),
                std::ptr::null_mut(),
            )
            .err()
            .expect("invalid creation Job must reject");
            assert_eq!(e.code(), "spawn_failed");
            assert_eq!(e.os_error, Some(6));
            assert_eq!(handles(), before);
            println!(
                "CREATION_JOB_FAILURE code={} native={:?} NO_FALLBACK=true HANDLE_CLEANUP=true",
                e.code(),
                e.os_error
            );
        }
        #[test]
        fn a_different_job_cannot_claim_the_current_child() {
            let f = CoreFixture::new();
            let mut first = Running::start_suspended(command(&f.0, SyntheticCase::Wait)).unwrap();
            let mut second = Running::start_suspended(command(&f.0, SyntheticCase::Wait)).unwrap();
            assert_eq!(
                first.job.verify_member(&second.child).unwrap_err().code(),
                "job_assignment_not_proven"
            );
            assert_eq!(
                second.job.verify_member(&first.child).unwrap_err().code(),
                "job_assignment_not_proven"
            );
            first.stop().unwrap();
            first.job.close().unwrap();
            assert_eq!(
                unsafe { WaitForSingleObject(second.child.as_raw_handle(), 0) },
                WAIT_TIMEOUT
            );
            second.stop().unwrap();
            second.job.close().unwrap();
            println!("DISTINCT_JOB_OBJECTS=true CROSS_MEMBERSHIP_REJECTED=true OLD_JOB_CLOSE_DID_NOT_KILL_CURRENT_CHILD=true");
        }
        #[test]
        fn unsupported_attribute_update_is_rejected() {
            let mut attrs = StartupAttributes::new(0).unwrap();
            let e = attrs
                .set_handles(u32::MAX, &[unsafe { GetCurrentProcess() }])
                .unwrap_err();
            assert_eq!(e.code(), "attribute_update_failed");
            assert_eq!(e.os_error, Some(50));
            println!(
                "UNSUPPORTED_ATTRIBUTE code={} native={:?} NO_FALLBACK=true",
                e.code(),
                e.os_error
            );
        }
        #[test]
        fn explicit_handle_list_excludes_an_unrelated_inheritable_handle() {
            let f = CoreFixture::new();
            let attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 1,
            };
            let event = unsafe { CreateEventW(&attrs, 1, 0, std::ptr::null()) };
            assert!(!event.is_null());
            let event = owned(event);
            let mut flags = 0;
            assert_ne!(
                unsafe { GetHandleInformation(event.as_raw_handle(), &mut flags) },
                0
            );
            assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
            let mut running = Running::start_suspended(command(&f.0, SyntheticCase::Wait)).unwrap();
            let mut raw = std::ptr::null_mut();
            let copied = unsafe {
                DuplicateHandle(
                    running.child.as_raw_handle(),
                    event.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut raw,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if copied == 0 {
                assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_HANDLE);
            } else {
                let duplicate = owned(raw);
                assert_eq!(
                    unsafe {
                        CompareObjectHandles(event.as_raw_handle(), duplicate.as_raw_handle())
                    },
                    0
                );
            }
            running.stop().unwrap();
            running.job.close().unwrap();
            println!(
                "UNRELATED_INHERITABLE_OBJECT_EXCLUDED=true CHILD_SUSPENDED_DURING_INSPECTION=true"
            );
        }
    }
}
#[cfg(all(windows, target_arch = "x86_64"))]
pub fn launch_synthetic(request: LaunchRequest) -> Result<LaunchReport, LaunchError> {
    windows::launch(request)
}
#[cfg(not(all(windows, target_arch = "x86_64")))]
pub fn launch_synthetic(_request: LaunchRequest) -> Result<LaunchReport, LaunchError> {
    Err(error("platform_unavailable"))
}

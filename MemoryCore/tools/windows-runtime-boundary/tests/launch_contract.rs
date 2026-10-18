use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};
use windows_runtime_boundary::{
    launch_synthetic, CancelToken, LaunchEvent, LaunchOutcome, LaunchRequest, LaunchTarget,
    SyntheticCase, NODE_TEST_TOOL, SYNTHETIC_ENTRY, SYNTHETIC_ENTRY_SOURCE, SYNTHETIC_PACKAGE,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
struct Fixture {
    root: PathBuf,
    manifest: Value,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "r2-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let graph=serde_json::to_vec(&json!({"format":"gateway-js-dependency-staging/v1","edges":[{"status":"UNRESOLVED"}],"TRANSITIVE_CLOSURE_PROVEN":false,"NATIVE_LOAD_VERIFIED":false,"DEVELOPMENT_PATH_ESCAPE":false})).unwrap();
        let node = json!({"version":"v24.16.0","platform":"win32","architecture":"x64","moduleABI":"137","napi":"10","runtimeCompatibility":"NOT_LOAD_VERIFIED"});
        let build = json!({"name":"esbuild","version":"0.28.2","typescriptVersion":"6.0.3","lockVersionMatched":true,"lockSha256":"1".repeat(64),"jsEntrypoints":[{"path":"node_modules/esbuild/lib/main.js","bytes":1,"sha256":"2".repeat(64)}],"executableIdentity":{"bytes":1,"sha256":"3".repeat(64)},"transformCalls":1});
        let report=serde_json::to_vec(&json!({"format":"gateway-js-candidate-closure/v1","entryOutput":SYNTHETIC_ENTRY,"CANDIDATE_BUILD_SUCCESS":true,"buildExitCode":0,"buildTool":build,"node":node,"jsDependencyStaging":{"graphPath":"js-dependency-graph.json","graphSha256":hash(&graph),"unresolvedEdges":1,"TRANSITIVE_CLOSURE_PROVEN":false,"NATIVE_LOAD_VERIFIED":false,"DEVELOPMENT_PATH_ESCAPE":false},"closureGateExitCode":2,"RELEASE_ELIGIBLE":false,"RELEASE_DEPENDENCY_CLOSURE_COMPLETE":false})).unwrap();
        let files = [
            ("app/package.json", SYNTHETIC_PACKAGE.as_bytes(), "metadata"),
            (
                SYNTHETIC_ENTRY,
                SYNTHETIC_ENTRY_SOURCE.as_bytes(),
                "gateway-js",
            ),
            ("closure-report.json", report.as_slice(), "report"),
            ("js-dependency-graph.json", graph.as_slice(), "report"),
        ]
        .into_iter()
        .map(|(p, b, k)| {
            let f = root.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, b).unwrap();
            json!({"path":p,"size":b.len(),"sha256":hash(b),"kind":k})
        })
        .collect::<Vec<_>>();
        for name in ["temp", "work"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        let manifest = json!({"format_version":2,"platform":"windows","architecture":"x86_64","validation_scope":"candidate-static-tree","production_eligible":false,"entry":SYNTHETIC_ENTRY,"node":node,"node_identity_scope":"reported-target-not-packaged","build_tool":build,"closure":{"path":"closure-report.json","sha256":hash(&report),"graph_path":"js-dependency-graph.json","graph_sha256":hash(&graph),"unresolved_edges":1},"runtime":{"dependency_closure_proven":false,"native_load_verified":false,"config_isolation":false,"protected_service":false,"trusted_issuer":false},"directories":["app","app/src","app/src/gateway","temp","work"],"files":files});
        Self { root, manifest }
    }
    fn request(&self, case: SyntheticCase) -> LaunchRequest {
        LaunchRequest {
            target: LaunchTarget::Synthetic(case),
            release_root: self.root.clone(),
            manifest: serde_json::to_vec(&self.manifest).unwrap(),
            executable: PathBuf::from(NODE_TEST_TOOL),
            entry: SYNTHETIC_ENTRY.into(),
            arguments: vec![],
            working_directory: self.root.join("work"),
            environment_overrides: vec![],
            timeout: Duration::from_secs(2),
            cancel: CancelToken::new(),
        }
    }
    fn replace_entry(&mut self, body: &[u8]) {
        fs::write(self.root.join(SYNTHETIC_ENTRY), body).unwrap();
        let item = self.manifest["files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|x| x["path"] == SYNTHETIC_ENTRY)
            .unwrap();
        item["size"] = json!(body.len());
        item["sha256"] = json!(hash(body));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn reject(r: LaunchRequest, code: &str) {
    assert_eq!(launch_synthetic(r).unwrap_err().code(), code);
}

#[test]
fn ipc_fixture_cannot_be_launched_without_the_r4_ipc_worker() {
    let f = Fixture::new();
    let mut r = f.request(SyntheticCase::Wait);
    r.target = LaunchTarget::SyntheticIpc;
    reject(r, "ipc_worker_required");
}
#[test]
fn ipc_fixture_observation_callback_cannot_bypass_worker_entry_policy() {
    let f = Fixture::new();
    let mut r = f.request(SyntheticCase::Wait);
    r.target = LaunchTarget::SyntheticIpc;
    let mut invoked = false;
    let e = r.launch_observed_for_test(|_| invoked = true).unwrap_err();
    assert_eq!(e.code(), "ipc_worker_required");
    assert!(!invoked);
}
fn receipt(name: &str, r: &windows_runtime_boundary::LaunchReport) {
    println!(
        "R2_PROCESS_RECEIPT={}",
        json!({
            "case":name,"outcome":format!("{:?}",r.outcome),
            "events":r.events.iter().map(|x|format!("{x:?}")).collect::<Vec<_>>(),
            "process_reaped":r.process_reaped,"job_closed":r.job_closed,
            "elapsed_ms":r.elapsed.as_millis(),"local_test_tool_sha256":r.test_tool_sha256,
            "fixed_synthetic_entry_sha256":r.synthetic_entry_sha256,
            "runtime_trust":"NOT_PROVEN"
        })
    );
}
#[test]
fn fixed_entry_actually_runs_and_reports_normal_exit() {
    let f = Fixture::new();
    let r = launch_synthetic(f.request(SyntheticCase::Normal)).unwrap();
    assert_eq!(r.outcome, LaunchOutcome::Exited(0));
    assert_eq!(
        r.events,
        vec![
            LaunchEvent::Created,
            LaunchEvent::JobAssigned,
            LaunchEvent::HandshakeSent,
            LaunchEvent::Exited
        ]
    );
    assert!(r.process_reaped && r.job_closed);
    let child: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(child["scenario"], "normal");
    assert_eq!(child["cwd"], f.root.join("work").to_str().unwrap());
    assert_eq!(
        child["execArgv"],
        json!(["--no-addons", "--no-global-search-paths"])
    );
    assert!(r.stderr.is_empty());
    receipt("normal", &r);
    println!("SYNTHETIC_NORMAL={}", r.stdout.trim());
}
#[test]
fn child_nonzero_is_observed_not_misreported_as_success() {
    let f = Fixture::new();
    let r = launch_synthetic(f.request(SyntheticCase::Nonzero)).unwrap();
    assert_eq!(r.outcome, LaunchOutcome::Exited(17));
    assert!(r.events.contains(&LaunchEvent::NonzeroExited));
    assert!(r.process_reaped && r.job_closed);
    assert_eq!(r.stderr, "R2_SYNTHETIC_NONZERO\n");
    receipt("nonzero", &r);
    println!("SYNTHETIC_NONZERO=17 CLEANUP=true");
}
#[test]
fn timeout_terminates_and_reaps_real_child() {
    let f = Fixture::new();
    let mut q = f.request(SyntheticCase::Wait);
    q.timeout = Duration::from_millis(250);
    let r = launch_synthetic(q).unwrap();
    assert_eq!(r.outcome, LaunchOutcome::TimedOut);
    assert!(r.events.contains(&LaunchEvent::TimedOut));
    assert!(r.process_reaped && r.job_closed);
    assert!(r.elapsed < Duration::from_secs(3));
    receipt("timeout", &r);
    println!("SYNTHETIC_TIMEOUT_TERMINATED_AND_REAPED=true");
}
#[test]
fn waiting_payload_confirms_startup_and_joins_both_output_readers() {
    let f = Fixture::new();
    let mut request = f.request(SyntheticCase::Wait);
    request.timeout = Duration::from_millis(400);
    let report = launch_synthetic(request).unwrap();
    let observed: Value = serde_json::from_str(report.stdout.trim()).unwrap();
    assert_eq!(observed["scenario"], "wait");
    assert_eq!(report.outcome, LaunchOutcome::TimedOut);
    assert!(report.process_reaped && report.job_closed);
    let facts = format!("{report:?}");
    assert!(
        facts.contains("startup_confirmed: true"),
        "a running fixed payload must have its startup acknowledgement validated: {facts}"
    );
    assert!(
        facts.contains("output_readers_joined: true"),
        "both bounded output readers must be joined after process cleanup: {facts}"
    );
    assert!(report.startup_confirmed && report.output_readers_joined);
}
#[test]
fn cooperative_abort_terminates_and_reaps_real_child() {
    let f = Fixture::new();
    let q = f.request(SyntheticCase::Wait);
    let token = q.cancel.clone();
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(250));
        token.cancel();
    });
    let r = launch_synthetic(q).unwrap();
    worker.join().unwrap();
    assert_eq!(r.outcome, LaunchOutcome::Aborted);
    assert!(r.events.contains(&LaunchEvent::Aborted));
    assert!(r.process_reaped && r.job_closed);
    println!("SYNTHETIC_ABORT_REAPED=true");
    receipt("abort", &r);
}
#[test]
fn cancelled_before_creation_does_not_spawn() {
    let f = Fixture::new();
    let q = f.request(SyntheticCase::Normal);
    q.cancel.cancel();
    reject(q, "cancelled_before_spawn");
}
#[test]
fn arbitrary_programs_and_relative_path_search_are_rejected() {
    for p in [
        "cmd.exe",
        "node",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\dev\\node.exe",
    ] {
        let f = Fixture::new();
        let mut q = f.request(SyntheticCase::Normal);
        q.executable = PathBuf::from(p);
        reject(q, "launch_policy_rejected");
    }
}
#[test]
fn entry_and_shell_string_injection_rejected() {
    for p in [
        "app/other.js",
        "app/src/gateway/server.js;whoami",
        "--eval",
        "../entry.js",
    ] {
        let f = Fixture::new();
        let mut q = f.request(SyntheticCase::Normal);
        q.entry = p.into();
        reject(q, "launch_policy_rejected");
    }
}
#[test]
fn all_caller_arguments_rejected() {
    for args in [
        vec!["-e", "process.exit(0)"],
        vec!["--require", "injected.js"],
        vec!["--inspect=0"],
        vec![";whoami"],
    ] {
        let f = Fixture::new();
        let mut q = f.request(SyntheticCase::Normal);
        q.arguments = args.into_iter().map(str::to_owned).collect();
        reject(q, "launch_policy_rejected");
    }
}
#[test]
fn working_directory_escape_or_alias_rejected() {
    let f = Fixture::new();
    for p in [
        f.root.clone(),
        f.root.parent().unwrap().to_path_buf(),
        std::env::current_dir().unwrap(),
        f.root.join("work/../work"),
    ] {
        let mut q = f.request(SyntheticCase::Normal);
        q.working_directory = p;
        reject(q, "launch_policy_rejected");
    }
}
#[test]
fn environment_overrides_cannot_inject_or_replace_whitelisted_values() {
    let f = Fixture::new();
    for key in [
        "NODE_OPTIONS",
        "NODE_PATH",
        "NAPI_RS_NATIVE_LIBRARY_PATH",
        "TSX_TSCONFIG_PATH",
        "NODE_COMPILE_CACHE",
        "NODE_V8_COVERAGE",
        "PATH",
        "SystemRoot",
        "TEMP",
    ] {
        let mut q = f.request(SyntheticCase::Normal);
        q.environment_overrides = vec![(key.into(), "UNTRUSTED".into())];
        reject(q, "launch_policy_rejected");
    }
}
#[test]
fn gateway_and_protected_gateway_are_unconditionally_closed() {
    let f = Fixture::new();
    for target in [LaunchTarget::Gateway, LaunchTarget::ProtectedGateway] {
        let mut q = f.request(SyntheticCase::Normal);
        q.target = target;
        reject(q, "gateway_release_not_qualified");
    }
}
#[test]
fn correct_v2_digest_cannot_authorize_arbitrary_js() {
    let mut f = Fixture::new();
    f.replace_entry(b"throw new Error('NEVER_EXECUTE_GATEWAY_OR_CALLER_CODE');\n");
    reject(
        f.request(SyntheticCase::Normal),
        "synthetic_fixture_invalid",
    );
}
#[test]
fn manifest_is_revalidated_instead_of_accepting_verified_claim() {
    let mut f = Fixture::new();
    f.manifest["verified"] = json!(true);
    reject(f.request(SyntheticCase::Normal), "manifest_invalid");
}
#[test]
fn v2_file_identity_tamper_prevents_process_creation() {
    let f = Fixture::new();
    fs::write(f.root.join(SYNTHETIC_ENTRY), b"TAMPER").unwrap();
    reject(f.request(SyntheticCase::Normal), "file_identity_mismatch");
}
#[test]
fn production_eligible_true_never_unlocks_gateway() {
    let mut f = Fixture::new();
    f.manifest["production_eligible"] = json!(true);
    let mut q = f.request(SyntheticCase::Normal);
    q.target = LaunchTarget::Gateway;
    reject(q, "gateway_release_not_qualified");
}
#[test]
fn timeout_is_bounded_and_not_an_unlimited_execution_switch() {
    let f = Fixture::new();
    for timeout in [Duration::ZERO, Duration::from_secs(6)] {
        let mut q = f.request(SyntheticCase::Normal);
        q.timeout = timeout;
        reject(q, "launch_policy_rejected");
    }
}
#[test]
fn simultaneous_instances_have_independent_job_lifetimes() {
    let slow = Fixture::new();
    let fast = Fixture::new();
    let mut q = slow.request(SyntheticCase::Wait);
    q.timeout = Duration::from_millis(350);
    let worker = thread::spawn(move || launch_synthetic(q).unwrap());
    let good = launch_synthetic(fast.request(SyntheticCase::Normal)).unwrap();
    let timed = worker.join().unwrap();
    assert_eq!(good.outcome, LaunchOutcome::Exited(0));
    assert_eq!(timed.outcome, LaunchOutcome::TimedOut);
    assert!(good.job_closed && timed.job_closed && good.process_reaped && timed.process_reaped);
    receipt("parallel_normal", &good);
    receipt("parallel_timeout", &timed);
}
#[test]
fn hostile_parent_environment_is_not_inherited() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "environment_observation_child", "--nocapture"])
        .env("NODE_OPTIONS", "--require C:\\NEVER_LOAD_R2_INJECTION.js")
        .env("NODE_PATH", "C:\\NEVER_LOAD_R2_MODULES")
        .env(
            "NAPI_RS_NATIVE_LIBRARY_PATH",
            "C:\\NEVER_LOAD_R2_NATIVE.dll",
        )
        .env("TSX_TSCONFIG_PATH", "C:\\NEVER_LOAD_R2_TSCONFIG.json")
        .env("NODE_COMPILE_CACHE", "C:\\NEVER_WRITE_R2_CACHE")
        .env("NODE_V8_COVERAGE", "C:\\NEVER_WRITE_R2_COVERAGE")
        .env("R2_PARENT_CANARY", "UNTRUSTED_PARENT")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("HOSTILE_PARENT_ENV_ISOLATION=PASS"));
}
#[test]
fn environment_observation_child() {
    let f = Fixture::new();
    let r = launch_synthetic(f.request(SyntheticCase::Normal)).unwrap();
    assert_eq!(r.outcome, LaunchOutcome::Exited(0));
    let child: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    let env = child["environment"].as_object().unwrap();
    assert_eq!(env.len(), 6);
    for key in env.keys() {
        assert!([
            "SYSTEMROOT",
            "WINDIR",
            "SYSTEMDRIVE",
            "TEMP",
            "TMP",
            "R2_SCENARIO"
        ]
        .contains(&key.to_ascii_uppercase().as_str()));
    }
    assert_eq!(env["TEMP"], f.root.join("temp").to_str().unwrap());
    assert_eq!(env["TMP"], f.root.join("temp").to_str().unwrap());
    println!("HOSTILE_PARENT_ENV_ISOLATION=PASS");
}
#[test]
fn working_directory_junction_rejected_before_spawn() {
    let f = Fixture::new();
    fs::remove_dir(f.root.join("work")).unwrap();
    let o = Command::new("C:\\Windows\\System32\\cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(f.root.join("work"))
        .arg(f.root.parent().unwrap())
        .output()
        .unwrap();
    assert!(o.status.success());
    reject(f.request(SyntheticCase::Normal), "reparse_rejected");
    fs::remove_dir(f.root.join("work")).unwrap();
}
#[test]
fn extra_declared_native_content_cannot_expand_synthetic_launch_policy() {
    let mut f = Fixture::new();
    fs::write(f.root.join("extra.node"), b"INERT").unwrap();
    f.manifest["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path":"extra.node","size":5,"sha256":hash(b"INERT"),"kind":"native"}));
    f.manifest["files"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    reject(
        f.request(SyntheticCase::Normal),
        "synthetic_fixture_invalid",
    );
}
#[test]
fn atomic_job_contract_is_proven_by_actual_launch() {
    let f = Fixture::new();
    let r = launch_synthetic(f.request(SyntheticCase::Normal)).unwrap();
    assert!(
        r.job_binding_at_creation,
        "R2 must bind Job during CreateProcess"
    );
    assert!(r.job_membership_verified && r.pre_execution_limits_verified);
    assert!(r.job_handle_not_inherited && r.kill_on_job_close_verified);
}
#[test]
fn observer_sees_suspended_child_already_in_its_job() {
    let f = Fixture::new();
    let mut observed = false;
    let r = f
        .request(SyntheticCase::Normal)
        .launch_observed_for_test(|o| {
            assert_eq!(o.stage, "before_resume");
            assert!(
                o.job_binding_at_creation
                    && o.job_membership_verified
                    && o.pre_execution_limits_verified
                    && o.job_handle_not_inherited
            );
            assert!(o.process_id > 0 && o.creation_time > 0);
            observed = true;
        })
        .unwrap();
    assert!(observed && r.outcome == LaunchOutcome::Exited(0));
}
struct AtomicSupervisor(std::process::Child);
impl Drop for AtomicSupervisor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct ObservedChild(std::os::windows::io::OwnedHandle);
impl Drop for ObservedChild {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.0.as_raw_handle(), 98);
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.0.as_raw_handle(),
                2000,
            );
        }
    }
}
#[test]
#[ignore = "independent synthetic supervisor entry, invoked explicitly"]
fn atomic_supervisor_entry() {
    let f = Fixture::new();
    let dir = PathBuf::from(std::env::var_os("R2_ATOMIC_DIR").unwrap());
    let mode = std::env::var("R2_ATOMIC_MODE").unwrap();
    let _=f.request(SyntheticCase::Wait).launch_observed_for_test(|o|{
        let data=json!({"stage":o.stage,"child":o.process_id,"created":o.creation_time,
            "create_time_job":o.job_binding_at_creation,"member":o.job_membership_verified,
            "limits":o.pre_execution_limits_verified,"job_not_inherited":o.job_handle_not_inherited});
        fs::write(dir.join("observation.partial"),serde_json::to_vec(&data).unwrap()).unwrap();
        fs::rename(dir.join("observation.partial"),dir.join("observation.json")).unwrap();
        let end=std::time::Instant::now()+Duration::from_secs(8);
        while !dir.join("release").exists(){assert!(std::time::Instant::now()<end);thread::sleep(Duration::from_millis(2));}
        if mode=="normal_exit" {std::process::exit(0);}
        panic!("crash supervisor should be terminated by its retained process handle");
    });
}
fn parent_exit_e2e(crash: bool) {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    let dir = std::env::temp_dir().join(format!(
        "r2-atomic-parent-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let mode = if crash { "crash" } else { "normal_exit" };
    let mut supervisor = AtomicSupervisor(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "atomic_supervisor_entry",
                "--ignored",
                "--nocapture",
            ])
            .env("R2_ATOMIC_DIR", &dir)
            .env("R2_ATOMIC_MODE", mode)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let end = std::time::Instant::now() + Duration::from_secs(4);
    while !dir.join("observation.json").exists() {
        assert!(
            std::time::Instant::now() < end,
            "supervisor failed to create fixture child"
        );
        assert!(supervisor.0.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(2));
    }
    let data: Value =
        serde_json::from_slice(&fs::read(dir.join("observation.json")).unwrap()).unwrap();
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZATION_SYNCHRONIZE | PROCESS_TERMINATE,
            0,
            data["child"].as_u64().unwrap() as u32,
        )
    };
    assert!(!raw.is_null());
    // Until creation identity is checked this handle may only be closed, never
    // used by a terminate-on-drop cleanup guard.
    let child_handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let (mut c, mut e, mut k, mut u) = unsafe {
        (
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
        )
    };
    assert_ne!(
        unsafe { GetProcessTimes(child_handle.as_raw_handle(), &mut c, &mut e, &mut k, &mut u) },
        0
    );
    assert_eq!(
        (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime),
        data["created"].as_u64().unwrap()
    );
    let observed = ObservedChild(child_handle);
    assert_eq!(
        unsafe { WaitForSingleObject(observed.0.as_raw_handle(), 0) },
        WAIT_TIMEOUT
    );
    assert_eq!(data["stage"], "before_resume");
    assert!(
        data["create_time_job"] == true
            && data["member"] == true
            && data["limits"] == true
            && data["job_not_inherited"] == true
    );
    if crash {
        assert_ne!(
            unsafe { TerminateProcess(supervisor.0.as_raw_handle(), 0xe2aa) },
            0
        );
    } else {
        fs::write(dir.join("release"), b"release normal supervisor").unwrap();
    }
    assert_eq!(
        unsafe { WaitForSingleObject(supervisor.0.as_raw_handle(), 2000) },
        WAIT_OBJECT_0
    );
    let parent_status = supervisor.0.wait().unwrap();
    assert_eq!(parent_status.code(), Some(if crash { 0xe2aa } else { 0 }));
    // This handle references only the observed synthetic child. No Job handle is
    // kept in the outer test process, so OS parent teardown closes the last one.
    assert_eq!(
        unsafe { WaitForSingleObject(observed.0.as_raw_handle(), 2000) },
        WAIT_OBJECT_0,
        "Job did not kill the suspended child after parent exit"
    );
    let mut child_code = 0;
    assert_ne!(
        unsafe { GetExitCodeProcess(observed.0.as_raw_handle(), &mut child_code) },
        0
    );
    println!(
        "ATOMIC_PARENT_EXIT_RECEIPT={}",
        json!({"mode":mode,"parent_exit":parent_status.code(),"child_exit":child_code,"original_creation_identity_matched":true,"child_alive_before_parent_exit":true,"child_terminated_after_parent_exit":true,"suspended_before_resume":true,"outer_process_holds_no_job_handle":true})
    );
    drop(observed);
    drop(supervisor);
    assert!(dir.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn normal_supervisor_exit_kills_suspended_job_child() {
    parent_exit_e2e(false);
}
#[test]
fn crashed_supervisor_kills_suspended_job_child() {
    parent_exit_e2e(true);
}
#[test]
#[ignore = "isolated restrictive host Job supervisor entry"]
fn restrictive_job_supervisor_entry() {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::{JobObjects::*, Threading::*};
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    assert!(!raw.is_null());
    let _owned = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    assert_ne!(
        unsafe {
            SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        },
        0
    );
    // Test setup only: constrain this independent supervisor, never the root
    // test runner. The production launcher does not use post-create assignment.
    assert_ne!(
        unsafe { AssignProcessToJobObject(raw, GetCurrentProcess()) },
        0
    );
    let f = Fixture::new();
    let mut child_observed = false;
    let result = f
        .request(SyntheticCase::Normal)
        .launch_observed_for_test(|_| child_observed = true);
    assert!(!child_observed);
    let error = result.unwrap_err();
    assert_eq!(error.code(), "spawn_failed");
    assert_eq!(error.os_error, Some(1816));
    println!(
        "RESTRICTED_PARENT_JOB_RECEIPT={}",
        json!({"error":error.code(),"native":error.os_error,"no_child_observed":true,"breakaway":false,"fallback":false})
    );
}
#[test]
fn restrictive_parent_job_fails_closed_without_breakaway() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "restrictive_job_supervisor_entry",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("RESTRICTED_PARENT_JOB_RECEIPT="));
    for line in text
        .lines()
        .filter(|l| l.contains("RESTRICTED_PARENT_JOB_RECEIPT="))
    {
        println!("{line}");
    }
}

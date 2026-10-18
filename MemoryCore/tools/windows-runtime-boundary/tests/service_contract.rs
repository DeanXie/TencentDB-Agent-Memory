use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use windows_runtime_boundary::service::*;
use windows_sys::Win32::{
    Foundation::*,
    System::{Services::*, Threading::*},
};

#[test]
fn stopped_status_failure_is_never_retried() {
    let (mut machine, mut sink) = normal_machine();
    machine.begin_stop(&mut sink).unwrap();
    sink.fail = Some(ServicePhase::Stopped);
    assert_eq!(
        machine.finish_stop(&mut sink, false).unwrap_err().code(),
        "synthetic_status_failure"
    );
    let calls = sink.calls;
    assert_eq!(
        machine.finish_stop(&mut sink, false).unwrap_err().code(),
        "terminal_status_already_attempted"
    );
    assert_eq!(sink.calls, calls);
    assert_ne!(machine.phase(), ServicePhase::Stopped);
}

#[test]
fn failed_instance_cannot_poison_next_lifecycle() {
    let mut failed = RecordingSink::default();
    assert!(run_synthetic_lifecycle(&mut failed, SyntheticServiceCase::StartupFailure).is_err());
    let mut next = RecordingSink::default();
    let report = run_synthetic_lifecycle(&mut next, SyntheticServiceCase::NormalStop).unwrap();
    assert!(report.worker_joined && report.resources_released && report.prepared_before_running);
    assert_eq!(next.states.last().unwrap().win32_exit_code, 0);
    assert_eq!(next.states.last().unwrap().service_exit_code, 0);
    assert_eq!(
        phases(&next),
        vec![
            ServicePhase::StartPending,
            ServicePhase::Running,
            ServicePhase::StopPending,
            ServicePhase::Stopped
        ]
    );
}
#[derive(Default)]
struct RecordingSink {
    states: Vec<ServiceSnapshot>,
    fail: Option<ServicePhase>,
    calls: usize,
}
impl StatusSink for RecordingSink {
    fn report(&mut self, s: ServiceSnapshot) -> Result<(), ServiceError> {
        self.calls += 1;
        if self.fail == Some(s.phase) {
            return Err(ServiceError::test_status_fault());
        }
        self.states.push(s);
        Ok(())
    }
}
fn phases(s: &RecordingSink) -> Vec<ServicePhase> {
    s.states.iter().map(|s| s.phase).collect()
}
fn normal_machine() -> (ServiceMachine, RecordingSink) {
    let mut m = ServiceMachine::new();
    let mut s = RecordingSink::default();
    m.start(&mut s).unwrap();
    (m, s)
}
#[test]
fn legal_state_transitions_and_status_fields() {
    let (mut m, mut s) = normal_machine();
    m.ready(&mut s).unwrap();
    m.begin_stop(&mut s).unwrap();
    m.finish_stop(&mut s, false).unwrap();
    assert_eq!(
        phases(&s),
        vec![
            ServicePhase::StartPending,
            ServicePhase::Running,
            ServicePhase::StopPending,
            ServicePhase::Stopped
        ]
    );
    for state in &s.states {
        if matches!(
            state.phase,
            ServicePhase::StartPending | ServicePhase::StopPending
        ) {
            assert_eq!(state.accepted_controls, 0);
            assert!(state.checkpoint > 0 && state.wait_hint_ms > 0);
        } else {
            assert_eq!(state.checkpoint, 0);
            assert_eq!(state.wait_hint_ms, 0);
        }
    }
    assert_eq!(
        s.states[1].accepted_controls,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    );
    assert_eq!(m.phase(), ServicePhase::Stopped);
}
#[test]
fn ready_before_start_is_rejected() {
    let mut m = ServiceMachine::new();
    let mut s = RecordingSink::default();
    assert_eq!(m.ready(&mut s).unwrap_err().code(), "invalid_service_state");
    assert!(m.failed());
    assert!(s.states.is_empty());
}
#[test]
fn duplicate_start_fails_closed() {
    let (mut m, mut s) = normal_machine();
    assert_eq!(m.start(&mut s).unwrap_err().code(), "invalid_service_state");
    assert!(m.failed());
    assert!(m.ready(&mut s).is_err());
}
#[test]
fn repeated_stop_is_idempotent() {
    let (mut m, mut s) = normal_machine();
    m.ready(&mut s).unwrap();
    assert!(m.begin_stop(&mut s).unwrap());
    assert!(!m.begin_stop(&mut s).unwrap());
    assert!(m.finish_stop(&mut s, false).unwrap());
    let calls = s.calls;
    assert!(!m.begin_stop(&mut s).unwrap());
    assert!(!m.finish_stop(&mut s, false).unwrap());
    assert_eq!(s.calls, calls);
}
#[test]
fn restart_after_stopped_is_rejected() {
    let (mut m, mut s) = normal_machine();
    m.begin_stop(&mut s).unwrap();
    m.finish_stop(&mut s, false).unwrap();
    assert!(m.start(&mut s).is_err());
}
#[test]
fn stopped_cannot_be_reported_before_stop() {
    let (mut m, mut s) = normal_machine();
    assert!(m.finish_stop(&mut s, false).is_err());
    assert!(!phases(&s).contains(&ServicePhase::Stopped));
}
#[test]
fn real_synthetic_worker_ready_then_stop() {
    let mut s = RecordingSink::default();
    let r = run_synthetic_lifecycle(&mut s, SyntheticServiceCase::NormalStop).unwrap();
    assert!(r.worker_joined && r.resources_released && r.prepared_before_running);
    assert_eq!(
        phases(&s),
        vec![
            ServicePhase::StartPending,
            ServicePhase::Running,
            ServicePhase::StopPending,
            ServicePhase::Stopped
        ]
    );
    println!(
        "R4A_OFFLINE_WORKER_RECEIPT=real_events:true;real_thread:true;ready_before_running:true;joined:true;released:true;SCM:false"
    );
}
#[test]
fn synthetic_repeated_stop_does_not_duplicate_terminal_report() {
    let mut s = RecordingSink::default();
    run_synthetic_lifecycle(&mut s, SyntheticServiceCase::DuplicateStop).unwrap();
    assert_eq!(
        phases(&s)
            .iter()
            .filter(|p| **p == ServicePhase::Stopped)
            .count(),
        1
    );
}
#[test]
fn stop_during_startup_never_reports_running() {
    let mut s = RecordingSink::default();
    run_synthetic_lifecycle(&mut s, SyntheticServiceCase::StopDuringStartup).unwrap();
    assert_eq!(
        phases(&s),
        vec![
            ServicePhase::StartPending,
            ServicePhase::StopPending,
            ServicePhase::Stopped
        ]
    );
}
#[test]
fn startup_failure_cleans_up_without_running() {
    let mut s = RecordingSink::default();
    assert_eq!(
        run_synthetic_lifecycle(&mut s, SyntheticServiceCase::StartupFailure)
            .unwrap_err()
            .code(),
        "synthetic_start_failure"
    );
    assert!(!phases(&s).contains(&ServicePhase::Running));
    assert_eq!(s.states.last().unwrap().phase, ServicePhase::Stopped);
    assert_eq!(
        s.states.last().unwrap().win32_exit_code,
        ERROR_SERVICE_SPECIFIC_ERROR
    );
}
#[test]
fn stop_failure_is_terminal_failure_after_join() {
    let mut s = RecordingSink::default();
    assert_eq!(
        run_synthetic_lifecycle(&mut s, SyntheticServiceCase::StopFailure)
            .unwrap_err()
            .code(),
        "synthetic_stop_failure"
    );
    assert_eq!(s.states.last().unwrap().phase, ServicePhase::Stopped);
    assert_ne!(s.states.last().unwrap().service_exit_code, 0);
}
#[test]
fn unexpected_worker_exit_fails_closed() {
    let mut s = RecordingSink::default();
    assert_eq!(
        run_synthetic_lifecycle(&mut s, SyntheticServiceCase::WorkerExit)
            .unwrap_err()
            .code(),
        "synthetic_worker_exit"
    );
    assert_eq!(s.states.last().unwrap().phase, ServicePhase::Stopped);
}
#[test]
fn status_report_failures_never_commit_success() {
    for p in [
        ServicePhase::StartPending,
        ServicePhase::Running,
        ServicePhase::StopPending,
        ServicePhase::Stopped,
    ] {
        let mut s = RecordingSink {
            fail: Some(p),
            ..Default::default()
        };
        assert!(run_synthetic_lifecycle(&mut s, SyntheticServiceCase::NormalStop).is_err());
        assert!(!phases(&s).contains(&p));
    }
}
#[test]
fn native_invalid_status_handle_is_rejected() {
    let e = invalid_status_handle_probe().unwrap_err();
    assert_eq!(e.code(), "service_status_failed");
    assert_eq!(e.native_code, Some(ERROR_INVALID_HANDLE));
    println!("R4A_NATIVE_STATUS_FAILURE=6;SCM:false");
}
#[test]
fn failure_and_stop_paths_release_real_handles() {
    unsafe {
        let mut before = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut before), 0);
        for _ in 0..3 {
            for case in [
                SyntheticServiceCase::NormalStop,
                SyntheticServiceCase::StartupFailure,
                SyntheticServiceCase::StopFailure,
                SyntheticServiceCase::WorkerExit,
            ] {
                let _ = run_synthetic_lifecycle(&mut RecordingSink::default(), case);
            }
        }
        let mut after = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut after), 0);
        assert!(after <= before + 2);
        println!("R4A_HANDLE_RECEIPT=before:{before};after:{after};SCM:false");
    }
}
fn run_binary(args: &[&str], forged: bool) -> (i32, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cmg-runtime-boundary-test-service"));
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if forged {
        command
            .env("CMG_SERVICE_VERIFIED", "true")
            .env("GATEWAY_MODE", "production")
            .env("R4A_SCM_CONNECTED", "true")
            .env("SERVICE_NAME", "TencentDBMemoryGateway");
    }
    let mut child = command.spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("service binary did not fail closed");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let mut output = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .take(4096)
        .read_to_string(&mut output)
        .unwrap();
    (status.code().unwrap(), output)
}
#[test]
fn direct_binary_execution_cannot_connect_to_scm() {
    let (code, text) = run_binary(&[], false);
    assert_eq!(code, 2);
    assert!(text.contains("code=scm_dispatcher_unavailable"));
    assert!(text.contains("1063"));
    println!("R4A_DIRECT_EXECUTION=exit:2;native:1063;SCM:false");
}
#[test]
fn forged_environment_cannot_enable_gateway_or_service_mode() {
    let (code, text) = run_binary(&[], true);
    assert_eq!(code, 2);
    assert!(text.contains("1063"));
}
#[test]
fn command_line_cannot_select_arbitrary_service_or_gateway() {
    for args in [
        vec!["--gateway"],
        vec!["--install"],
        vec!["--service-name", "TencentDBMemoryGateway"],
        vec!["--command", "cmd.exe"],
    ] {
        let (code, text) = run_binary(&args, false);
        assert_eq!(code, 2);
        assert!(text.contains("command_line_rejected"));
    }
}
#[test]
fn service_identity_and_protocol_are_fixed_test_only() {
    assert_eq!(TEST_SERVICE_NAME, "CmgRuntimeBoundaryR4ATest");
    assert_eq!(SERVICE_PROTOCOL, "cmg-service-host-test/v1");
}

#[test]
fn r4b_late_ready_after_stopped_has_no_external_effect() {
    let (mut machine, mut sink) = normal_machine();
    machine.begin_stop(&mut sink).unwrap();
    machine.finish_stop(&mut sink, false).unwrap();
    let calls = sink.calls;
    assert!(machine.ready(&mut sink).is_err());
    assert_eq!(machine.phase(), ServicePhase::Stopped);
    assert_eq!(sink.calls, calls);
}

#[test]
fn r4b_failed_running_report_cannot_be_retried_as_success() {
    let (mut machine, mut sink) = normal_machine();
    sink.fail = Some(ServicePhase::Running);
    assert!(machine.ready(&mut sink).is_err());
    sink.fail = None;
    let calls = sink.calls;
    assert!(machine.ready(&mut sink).is_err());
    assert_eq!(sink.calls, calls);
    machine.begin_stop(&mut sink).unwrap();
    machine.finish_stop(&mut sink, true).unwrap();
    assert_ne!(sink.states.last().unwrap().service_exit_code, 0);
}

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use windows_runtime_boundary::{
    CancelToken, LaunchRequest, LaunchTarget, SyntheticCase, NODE_TEST_TOOL, SYNTHETIC_ENTRY,
    SYNTHETIC_ENTRY_SOURCE, SYNTHETIC_PACKAGE,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
struct ProcessFixture {
    root: PathBuf,
    manifest: Value,
}
impl ProcessFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "service-process-fixture-{}-{}",
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
}
impl Drop for ProcessFixture {
    fn drop(&mut self) {
        assert!(self.root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[derive(Default)]
struct ProcessSink {
    states: Vec<ServiceSnapshot>,
    control: Option<SyntheticProcessControl>,
    stop_at: Option<ServicePhase>,
    fail_at: Option<ServicePhase>,
    duplicate_stop: bool,
    stopped_calls: usize,
    stoppers: Vec<thread::JoinHandle<()>>,
}
impl StatusSink for ProcessSink {
    fn report(&mut self, snapshot: ServiceSnapshot) -> Result<(), ServiceError> {
        if snapshot.phase == ServicePhase::Stopped {
            self.stopped_calls += 1;
        }
        if self.fail_at == Some(snapshot.phase) {
            return Err(ServiceError::test_status_fault());
        }
        self.states.push(snapshot);
        if self.stop_at == Some(snapshot.phase) {
            let control = self.control.as_ref().unwrap().clone();
            // RUNNING publication owns the transition lock; emulate asynchronous
            // control delivery rather than recursively requesting STOP in the sink.
            if snapshot.phase == ServicePhase::Running {
                let twice = self.duplicate_stop;
                self.stoppers.push(thread::spawn(move || {
                    control.stop().unwrap();
                    if twice {
                        control.stop().unwrap();
                    }
                }));
            } else {
                control.stop().unwrap();
            }
        }
        Ok(())
    }
}
impl Drop for ProcessSink {
    fn drop(&mut self) {
        for thread in self.stoppers.drain(..) {
            thread.join().unwrap();
        }
    }
}
fn process_sink(control: &SyntheticProcessControl) -> ProcessSink {
    let mut sink = ProcessSink::default();
    sink.control = Some(control.clone());
    sink.stop_at = Some(ServicePhase::Running);
    sink
}
#[test]
fn process_worker_valid_ack_then_stop_reaps_and_joins_readers() {
    let f = ProcessFixture::new();
    let control = SyntheticProcessControl::new();
    let mut sink = process_sink(&control);
    let result = run_synthetic_process_lifecycle(
        &mut sink,
        f.request(windows_runtime_boundary::SyntheticCase::Wait),
        control,
    )
    .unwrap();
    let launch = result.launch.unwrap();
    assert!(launch.startup_confirmed && launch.output_readers_joined);
    assert!(launch.process_reaped && launch.job_closed);
    assert_eq!(
        launch.outcome,
        windows_runtime_boundary::LaunchOutcome::Aborted
    );
    assert!(result.lifecycle.worker_joined && result.lifecycle.resources_released);
    assert!(result.lifecycle.prepared_before_running);
    assert_eq!(
        sink.states.iter().map(|s| s.phase).collect::<Vec<_>>(),
        vec![
            ServicePhase::StartPending,
            ServicePhase::Running,
            ServicePhase::StopPending,
            ServicePhase::Stopped
        ]
    );
    assert_eq!(sink.stopped_calls, 1);
}
#[test]
fn process_worker_stop_before_spawn_suppresses_running() {
    let f = ProcessFixture::new();
    let control = SyntheticProcessControl::new();
    control.stop().unwrap();
    let mut sink = process_sink(&control);
    let result = run_synthetic_process_lifecycle(
        &mut sink,
        f.request(windows_runtime_boundary::SyntheticCase::Wait),
        control,
    )
    .unwrap();
    assert!(result.launch.is_none());
    assert!(!sink.states.iter().any(|s| s.phase == ServicePhase::Running));
    assert!(result.lifecycle.worker_joined && result.lifecycle.resources_released);
    assert_eq!(sink.stopped_calls, 1);
}
#[test]
fn process_worker_stop_at_start_pending_is_not_lost() {
    let f = ProcessFixture::new();
    let control = SyntheticProcessControl::new();
    let mut sink = process_sink(&control);
    sink.stop_at = Some(ServicePhase::StartPending);
    let result = run_synthetic_process_lifecycle(
        &mut sink,
        f.request(windows_runtime_boundary::SyntheticCase::Wait),
        control,
    )
    .unwrap();
    assert!(!sink.states.iter().any(|s| s.phase == ServicePhase::Running));
    assert!(result.lifecycle.worker_joined && result.lifecycle.resources_released);
    assert_eq!(sink.stopped_calls, 1);
}
#[test]
fn process_worker_repeated_stop_reports_terminal_once() {
    let f = ProcessFixture::new();
    let control = SyntheticProcessControl::new();
    let mut sink = process_sink(&control);
    sink.duplicate_stop = true;
    let result = run_synthetic_process_lifecycle(
        &mut sink,
        f.request(windows_runtime_boundary::SyntheticCase::Wait),
        control,
    )
    .unwrap();
    assert!(result.lifecycle.worker_joined && result.lifecycle.resources_released);
    assert_eq!(sink.stopped_calls, 1);
    assert_eq!(
        sink.states
            .iter()
            .filter(|s| s.phase == ServicePhase::Running)
            .count(),
        1
    );
}
#[test]
fn process_worker_rejects_bad_manifest_without_running() {
    let f = ProcessFixture::new();
    let mut request = f.request(windows_runtime_boundary::SyntheticCase::Wait);
    request.manifest = b"{}".to_vec();
    let control = SyntheticProcessControl::new();
    let mut sink = process_sink(&control);
    assert!(run_synthetic_process_lifecycle(&mut sink, request, control).is_err());
    assert!(!sink.states.iter().any(|s| s.phase == ServicePhase::Running));
    assert_eq!(sink.stopped_calls, 1);
}
#[test]
fn process_worker_timeout_is_a_failure_with_terminal_cleanup() {
    let f = ProcessFixture::new();
    let mut request = f.request(windows_runtime_boundary::SyntheticCase::Wait);
    request.timeout = Duration::from_millis(700);
    let control = SyntheticProcessControl::new();
    let mut sink = process_sink(&control);
    sink.stop_at = None;
    let error = run_synthetic_process_lifecycle(&mut sink, request, control).unwrap_err();
    assert_eq!(error.code(), "synthetic_process_timeout");
    assert_eq!(sink.stopped_calls, 1);
    assert_eq!(sink.states.last().unwrap().phase, ServicePhase::Stopped);
    assert_ne!(sink.states.last().unwrap().service_exit_code, 0);
}
#[test]
fn process_worker_status_failures_preserve_original_error_and_stop_once() {
    for phase in [
        ServicePhase::StartPending,
        ServicePhase::Running,
        ServicePhase::StopPending,
        ServicePhase::Stopped,
    ] {
        let f = ProcessFixture::new();
        let control = SyntheticProcessControl::new();
        let mut sink = process_sink(&control);
        sink.fail_at = Some(phase);
        let error = run_synthetic_process_lifecycle(
            &mut sink,
            f.request(windows_runtime_boundary::SyntheticCase::Wait),
            control,
        )
        .unwrap_err();
        assert_eq!(error.code(), "synthetic_status_failure");
        assert!(!sink.states.iter().any(|s| s.phase == phase));
        assert!(sink.stopped_calls <= 1);
    }
}
#[test]
fn process_worker_early_exit_cannot_report_success() {
    for case in [
        windows_runtime_boundary::SyntheticCase::Normal,
        windows_runtime_boundary::SyntheticCase::Nonzero,
    ] {
        let f = ProcessFixture::new();
        let control = SyntheticProcessControl::new();
        let mut sink = process_sink(&control);
        sink.stop_at = None;
        assert!(run_synthetic_process_lifecycle(&mut sink, f.request(case), control).is_err());
        assert_eq!(sink.stopped_calls, 1);
        assert_ne!(sink.states.last().unwrap().service_exit_code, 0);
    }
}
#[test]
fn process_worker_failed_instance_does_not_poison_next_request() {
    let f = ProcessFixture::new();
    let mut bad = f.request(windows_runtime_boundary::SyntheticCase::Wait);
    bad.manifest.clear();
    assert!(run_synthetic_process_lifecycle(
        &mut ProcessSink::default(),
        bad,
        SyntheticProcessControl::new()
    )
    .is_err());
    let control = SyntheticProcessControl::new();
    let mut sink = process_sink(&control);
    let good = run_synthetic_process_lifecycle(
        &mut sink,
        f.request(windows_runtime_boundary::SyntheticCase::Wait),
        control,
    )
    .unwrap();
    assert!(good.lifecycle.worker_joined && good.launch.unwrap().output_readers_joined);
}

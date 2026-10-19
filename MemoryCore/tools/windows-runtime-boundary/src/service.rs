//! R4A test-only SCM host. No service installation, Gateway, issuer or verifier.
//! Offline sinks exercise lifecycle logic; they do not prove actual SCM behavior.
use crate::launch::{self, CancelToken, LaunchOutcome, LaunchReport, LaunchRequest, StartedChild};
use crate::peer::{PeerError, PinnedProcess, ScmPeerPolicy, TestPeerPolicy, TestPipeServer};
use std::{
    cell::Cell,
    ffi::OsString,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{Services::*, Threading::*},
};
pub const TEST_SERVICE_NAME: &str = "CmgRuntimeBoundaryR4ATest";
pub const SERVICE_PROTOCOL: &str = "cmg-service-host-test/v1";
#[derive(Debug, Clone)]
pub struct ServiceError {
    code: &'static str,
    pub native_code: Option<u32>,
}
impl ServiceError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            native_code: None,
        }
    }
    fn native(code: &'static str) -> Self {
        Self {
            code,
            native_code: Some(unsafe { GetLastError() }),
        }
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn test_status_fault() -> Self {
        Self::new("synthetic_status_failure")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePhase {
    Dormant,
    StartPending,
    Running,
    StopPending,
    Stopped,
}
#[derive(Debug, Clone, Copy)]
pub struct ServiceSnapshot {
    pub phase: ServicePhase,
    pub accepted_controls: u32,
    pub checkpoint: u32,
    pub wait_hint_ms: u32,
    pub win32_exit_code: u32,
    pub service_exit_code: u32,
}
/// A synchronous status reporter. RUNNING reports are serialized with STOP.
/// A reporter must not wait for a concurrent STOP or synchronously reenter STOP
/// on the same lifecycle; same-thread reentry is rejected instead of deadlocking.
pub trait StatusSink {
    fn report(&mut self, snapshot: ServiceSnapshot) -> Result<(), ServiceError>;
}
pub struct ServiceMachine {
    phase: ServicePhase,
    failed: bool,
    stop_requested: bool,
    terminal_attempted: bool,
}
impl Default for ServiceMachine {
    fn default() -> Self {
        Self::new()
    }
}
impl ServiceMachine {
    pub fn new() -> Self {
        Self {
            phase: ServicePhase::Dormant,
            failed: false,
            stop_requested: false,
            terminal_attempted: false,
        }
    }
    pub fn phase(&self) -> ServicePhase {
        self.phase
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    fn invalid<T>(&mut self) -> Result<T, ServiceError> {
        self.failed = true;
        Err(ServiceError::new("invalid_service_state"))
    }
    fn snapshot(&self, phase: ServicePhase) -> ServiceSnapshot {
        let pending = matches!(
            phase,
            ServicePhase::StartPending | ServicePhase::StopPending
        );
        let error = phase == ServicePhase::Stopped && self.failed;
        ServiceSnapshot {
            phase,
            accepted_controls: if phase == ServicePhase::Running {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            checkpoint: if pending { 1 } else { 0 },
            wait_hint_ms: if pending { 3000 } else { 0 },
            win32_exit_code: if error {
                ERROR_SERVICE_SPECIFIC_ERROR
            } else {
                0
            },
            service_exit_code: if error { 1 } else { 0 },
        }
    }
    fn publish(
        &mut self,
        sink: &mut impl StatusSink,
        next: ServicePhase,
    ) -> Result<bool, ServiceError> {
        if let Err(e) = sink.report(self.snapshot(next)) {
            self.failed = true;
            self.stop_requested = true;
            return Err(e);
        }
        self.phase = next;
        Ok(true)
    }
    pub fn start(&mut self, sink: &mut impl StatusSink) -> Result<bool, ServiceError> {
        if self.phase != ServicePhase::Dormant || self.failed {
            return self.invalid();
        }
        self.publish(sink, ServicePhase::StartPending)
    }
    pub fn ready(&mut self, sink: &mut impl StatusSink) -> Result<bool, ServiceError> {
        if self.phase != ServicePhase::StartPending || self.failed || self.stop_requested {
            return self.invalid();
        }
        self.publish(sink, ServicePhase::Running)
    }
    pub fn begin_stop(&mut self, sink: &mut impl StatusSink) -> Result<bool, ServiceError> {
        if matches!(
            self.phase,
            ServicePhase::StopPending | ServicePhase::Stopped
        ) {
            return Ok(false);
        }
        if self.phase == ServicePhase::Dormant && !self.failed {
            return self.invalid();
        }
        self.stop_requested = true;
        self.publish(sink, ServicePhase::StopPending)
    }
    pub fn finish_stop(
        &mut self,
        sink: &mut impl StatusSink,
        failure: bool,
    ) -> Result<bool, ServiceError> {
        if self.phase == ServicePhase::Stopped {
            return Ok(false);
        }
        if self.terminal_attempted {
            return Err(ServiceError::new("terminal_status_already_attempted"));
        }
        if !self.stop_requested || (self.phase != ServicePhase::StopPending && !self.failed) {
            return self.invalid();
        }
        self.failed |= failure;
        // SCM's STOPPED status closes its RPC context. Never retry it.
        self.terminal_attempted = true;
        self.publish(sink, ServicePhase::Stopped)
    }
    fn refresh(&mut self, sink: &mut impl StatusSink) -> Result<(), ServiceError> {
        if self.phase == ServicePhase::Dormant || self.terminal_attempted {
            return Err(ServiceError::new("service_not_active"));
        }
        if let Err(e) = sink.report(self.snapshot(self.phase)) {
            self.failed = true;
            self.stop_requested = true;
            return Err(e);
        }
        Ok(())
    }
}

struct Event(OwnedHandle);
impl Event {
    fn new() -> Result<Self, ServiceError> {
        let raw = unsafe { CreateEventW(null(), 1, 0, null()) };
        if raw.is_null() {
            return Err(ServiceError::native("event_create_failed"));
        }
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(raw) }))
    }
    fn set(&self) -> Result<(), ServiceError> {
        if unsafe { SetEvent(self.0.as_raw_handle()) } == 0 {
            return Err(ServiceError::native("event_set_failed"));
        }
        Ok(())
    }
    fn wait(&self, ms: u32) -> Result<bool, ServiceError> {
        match unsafe { WaitForSingleObject(self.0.as_raw_handle(), ms) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(ServiceError::native("event_wait_failed")),
        }
    }
}
thread_local! {
    // Pointer identity only, never dereferenced or used as an authorization fact.
    static REPORTING_CONTROL: Cell<*const Control> = const { Cell::new(null()) };
}
struct ReportingControl(*const Control);
impl ReportingControl {
    fn enter(control: &Control) -> Self {
        Self(REPORTING_CONTROL.with(|current| current.replace(control)))
    }
}
impl Drop for ReportingControl {
    fn drop(&mut self) {
        REPORTING_CONTROL.with(|current| current.set(self.0));
    }
}
struct Control {
    // Acceptance of cancellation, RUNNING publication and closure share this
    // lock. Lock order is transition -> event; the worker never takes transition.
    transition: Mutex<()>,
    stop: AtomicBool,
    interrogate: AtomicBool,
    active: AtomicBool,
    fault: AtomicU32,
    event: Mutex<Option<Arc<Event>>>,
    process_cancel: Mutex<Option<CancelToken>>,
    ipc_stage: AtomicU32,
    #[cfg(test)]
    before_ready: Mutex<Option<Arc<r4b_tests::Checkpoint>>>,
    #[cfg(test)]
    before_go: Mutex<Option<Arc<r4b_tests::Checkpoint>>>,
    #[cfg(test)]
    after_ack: Mutex<Option<Arc<r4b_tests::Checkpoint>>>,
}
impl Control {
    fn new() -> Self {
        Self {
            transition: Mutex::new(()),
            stop: AtomicBool::new(false),
            interrogate: AtomicBool::new(false),
            active: AtomicBool::new(true),
            fault: AtomicU32::new(0),
            event: Mutex::new(None),
            process_cancel: Mutex::new(None),
            ipc_stage: AtomicU32::new(0),
            #[cfg(test)]
            before_ready: Mutex::new(None),
            #[cfg(test)]
            before_go: Mutex::new(None),
            #[cfg(test)]
            after_ack: Mutex::new(None),
        }
    }
    fn install_event(&self) -> Result<Arc<Event>, ServiceError> {
        let _transition = self
            .transition
            .lock()
            .map_err(|_| ServiceError::new("control_transition_poisoned"))?;
        if !self.active.load(Ordering::SeqCst) {
            return Err(Self::inactive());
        }
        let event = Arc::new(Event::new()?);
        let mut slot = self
            .event
            .lock()
            .map_err(|_| ServiceError::new("control_lock_poisoned"))?;
        if slot.is_some() {
            return Err(ServiceError::new("duplicate_service_preparation"));
        }
        if self.stop.load(Ordering::SeqCst) {
            event.set()?;
        }
        *slot = Some(event.clone());
        Ok(event)
    }
    fn inactive() -> ServiceError {
        ServiceError {
            code: "service_not_active",
            native_code: Some(ERROR_SERVICE_NOT_ACTIVE),
        }
    }
    fn install_process_cancel(&self, cancel: CancelToken) -> Result<(), ServiceError> {
        let _transition = self
            .transition
            .lock()
            .map_err(|_| ServiceError::new("control_transition_poisoned"))?;
        if !self.active.load(Ordering::SeqCst) {
            return Err(Self::inactive());
        }
        let mut slot = self
            .process_cancel
            .lock()
            .map_err(|_| ServiceError::new("control_lock_poisoned"))?;
        if slot.is_some() {
            return Err(ServiceError::new("duplicate_service_preparation"));
        }
        if self.stop.load(Ordering::SeqCst) {
            cancel.cancel();
        }
        *slot = Some(cancel);
        Ok(())
    }
    fn request_stop(&self) -> Result<(), ServiceError> {
        if REPORTING_CONTROL.with(|current| std::ptr::eq(current.get(), self)) {
            return Err(ServiceError::new("reentrant_stop_not_allowed"));
        }
        let _transition = match self.transition.lock() {
            Ok(guard) => guard,
            Err(poison) => {
                // A status sink unwinding must not strand Worker::drop in join.
                // Recover only for cancellation; future READY still fails closed.
                let _guard = poison.into_inner();
                self.stop_locked()?;
                return Err(ServiceError::new("control_transition_poisoned"));
            }
        };
        if !self.active.load(Ordering::SeqCst) {
            return Err(Self::inactive());
        }
        self.stop_locked()
    }
    // Caller owns transition. The first accepted intent signals the worker;
    // subsequent requests cannot repeat signal/cleanup side effects.
    fn stop_locked(&self) -> Result<(), ServiceError> {
        if self.stop.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(cancel) = self
            .process_cancel
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            cancel.cancel();
        }
        let slot = self
            .event
            .lock()
            .map_err(|_| ServiceError::new("control_lock_poisoned"))?;
        if let Some(event) = slot.as_ref() {
            if let Err(e) = event.set() {
                self.fault.store(
                    e.native_code.unwrap_or(ERROR_SERVICE_SPECIFIC_ERROR),
                    Ordering::SeqCst,
                );
                return Err(e);
            }
        }
        Ok(())
    }
    fn publish_ready(
        &self,
        machine: &mut ServiceMachine,
        sink: &mut impl StatusSink,
    ) -> Result<bool, ServiceError> {
        self.publish_ready_checked(machine, sink, || Ok(()))
    }
    fn publish_ready_checked(
        &self,
        machine: &mut ServiceMachine,
        sink: &mut impl StatusSink,
        check: impl FnOnce() -> Result<(), ServiceError>,
    ) -> Result<bool, ServiceError> {
        let _transition = self
            .transition
            .lock()
            .map_err(|_| ServiceError::new("control_transition_poisoned"))?;
        if !self.active.load(Ordering::SeqCst) {
            return Err(Self::inactive());
        }
        if self.stop.load(Ordering::SeqCst) {
            return Ok(false);
        }
        check()?;
        // Hold the boundary through the synchronous status API result, so a
        // concurrently invoked STOP is accepted only before or after this report.
        let _reporting = ReportingControl::enter(self);
        let result = machine.ready(sink);
        if result.is_err() {
            // Retain the original status error, including its native SCM code.
            let _ = self.stop_locked();
        }
        result
    }
    fn clear(&self) {
        let _transition = self.transition.lock().unwrap_or_else(|p| p.into_inner());
        if !self.active.swap(false, Ordering::SeqCst) {
            return;
        }
        let _ = self.stop_locked();
        // Poison is not authority: cleanup still owns and removes the resource.
        self.event.lock().unwrap_or_else(|p| p.into_inner()).take();
        self.process_cancel
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SyntheticServiceCase {
    NormalStop,
    DuplicateStop,
    StopDuringStartup,
    StartupFailure,
    StopFailure,
    WorkerExit,
}
/// Offline cancellation only; this object cannot control any SCM service.
#[derive(Clone)]
pub struct SyntheticProcessControl {
    inner: Arc<Control>,
}
impl Default for SyntheticProcessControl {
    fn default() -> Self {
        Self::new()
    }
}
impl SyntheticProcessControl {
    /// Offline scheduling observation only; never authority or an IPC receipt.
    pub fn ipc_stage(&self) -> u32 {
        self.inner.ipc_stage.load(Ordering::SeqCst)
    }
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Control::new()),
        }
    }
    /// Accept an offline STOP intent, serialized against RUNNING publication.
    /// Calling this synchronously from this lifecycle's RUNNING StatusSink
    /// returns `reentrant_stop_not_allowed` without accepting the intent.
    /// The reporter must propagate that failure; it must not wait for another
    /// thread's STOP while its synchronous report is in progress.
    pub fn stop(&self) -> Result<(), ServiceError> {
        match self.inner.request_stop() {
            Err(e)
                if e.code() == "service_not_active" && self.inner.stop.load(Ordering::SeqCst) =>
            {
                Ok(())
            }
            result => result,
        }
    }
}
#[derive(Default)]
struct ProcessState {
    started: Option<StartedChild>,
    report: Option<LaunchReport>,
    ipc_case: Option<SyntheticIpcCase>,
    ipc: Option<SyntheticIpcReport>,
    // Set only by the internal, authorized SCM entry. Not part of IpcGate.
    scm_peer: bool,
}
/// Fixed client behaviours for the closed offline integration-test executable.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SyntheticIpcCase {
    Authenticate,
    ConnectWait,
    ChallengeWait,
    LateResponse,
    EarlyExit,
    Replay,
    WrongIdentity,
}
#[derive(Debug, Default)]
pub struct SyntheticIpcReport {
    pub authenticated: bool,
    pub process_identity_matched: bool,
    pub cancellation_observed: bool,
    pub pipe_released_before_job: bool,
    pub replay_rejected: bool,
}
fn peer_failure(e: PeerError) -> ServiceError {
    ServiceError {
        code: e.code(),
        native_code: e.native_code,
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IpcGate {
    pipe: String,
    parent: u32,
    created: u64,
    case: SyntheticIpcCase,
}

/// Body of the single fixed ignored integration-test entry. No executable,
/// environment override, command or Gateway mode can be supplied in the gate.
pub fn controlled_ipc_fixture_entry() -> Result<(), ServiceError> {
    use std::io::{BufRead, Read};
    let mut input = std::io::BufReader::new(std::io::stdin().take(2055));
    let mut go = String::new();
    input
        .read_line(&mut go)
        .map_err(|_| ServiceError::new("ipc_gate_invalid"))?;
    if go != "R2_GO\n" {
        return Err(ServiceError::new("ipc_gate_invalid"));
    }
    let mut bytes = Vec::new();
    input
        .read_to_end(&mut bytes)
        .map_err(|_| ServiceError::new("ipc_gate_invalid"))?;
    if bytes.len() > 2048 {
        return Err(ServiceError::new("ipc_gate_invalid"));
    }
    run_fixed_ipc_client(&bytes)
}

/// Ordinary Cargo bin entry. Reuses the existing R3 client; no libtest dispatch,
/// alternate command, runtime configuration or service mode is available.
pub fn standalone_ipc_child_entry() -> Result<(), ServiceError> {
    use std::io::Read;
    use windows_sys::Win32::{
        Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
        System::Pipes::PeekNamedPipe,
    };
    if std::env::args_os().len() != 1 {
        return Err(ServiceError::new("ipc_arguments_forbidden"));
    }
    let mut input = std::io::stdin();
    let raw = input.as_raw_handle();
    if unsafe { GetFileType(raw) } != FILE_TYPE_PIPE {
        return Err(ServiceError::new("ipc_bootstrap_pipe_required"));
    }
    // The fixed parent writes <=2054 bytes then closes its anonymous pipe.
    // Peek before each read avoids a blocking stdin reader or detached thread.
    // Until identity is parsed, EOF/this deadline bounds even an absent parent.
    let end = Instant::now() + Duration::from_millis(1500);
    let mut bytes = Vec::new();
    loop {
        if Instant::now() >= end {
            return Err(ServiceError::new("ipc_bootstrap_timeout"));
        }
        let mut available = 0;
        if unsafe { PeekNamedPipe(raw, null_mut(), 0, null_mut(), &mut available, null_mut()) } == 0
        {
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                break;
            }
            return Err(ServiceError::native("ipc_bootstrap_read_failed"));
        }
        if available == 0 {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        let mut buffer = [0u8; 2055];
        let count = (available as usize).min(buffer.len());
        let n = input
            .read(&mut buffer[..count])
            .map_err(|_| ServiceError::new("ipc_bootstrap_read_failed"))?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..n]);
        if bytes.len() > 2054 {
            return Err(ServiceError::new("ipc_gate_invalid"));
        }
    }
    let gate = bytes
        .strip_prefix(b"R2_GO\n")
        .ok_or_else(|| ServiceError::new("ipc_gate_invalid"))?;
    run_fixed_ipc_client(gate)
}

fn fixed_client_wait(parent: &PinnedProcess) -> Result<(), ServiceError> {
    let end = Instant::now() + Duration::from_secs(4);
    while Instant::now() < end {
        if !parent.is_alive().map_err(peer_failure)? {
            return Err(ServiceError::new("ipc_parent_exited"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
fn run_fixed_ipc_client(bytes: &[u8]) -> Result<(), ServiceError> {
    use crate::peer::{PipeName, TestPipeClient};
    use std::io::Write;
    let gate: IpcGate =
        serde_json::from_slice(bytes).map_err(|_| ServiceError::new("ipc_gate_invalid"))?;
    let parent = PinnedProcess::open_test_peer(gate.parent, gate.created).map_err(peer_failure)?;
    let name = PipeName::parse_local(&gate.pipe).map_err(peer_failure)?;
    if gate.case == SyntheticIpcCase::EarlyExit {
        return Ok(());
    }
    if gate.case == SyntheticIpcCase::ConnectWait {
        return fixed_client_wait(&parent);
    }
    let mut client = TestPipeClient::connect_fixed_child(&name, &parent, Duration::from_secs(3))
        .map_err(peer_failure)?;
    let challenge = client.challenge().map_err(peer_failure)?;
    if gate.case == SyntheticIpcCase::ChallengeWait {
        let _ = client.wait_for_close();
        return fixed_client_wait(&parent);
    }
    if gate.case == SyntheticIpcCase::LateResponse {
        thread::sleep(Duration::from_millis(150));
    }
    println!("R3_CLIENT_AUTHENTICATED");
    std::io::stdout()
        .flush()
        .map_err(|_| ServiceError::new("ipc_output_failed"))?;
    // respond verifies the fixed-purpose, session-bound challenge and ACK.
    // The marker alone is never used to accept a server-side receipt.
    if client.respond(&challenge).is_err() {
        return Ok(());
    }
    let _ = client.wait_for_close();
    // Keep the same authenticated process alive for R2's owned Job termination.
    // This bounded test wait cannot spawn a descendant or reopen a session.
    fixed_client_wait(&parent)
}

fn ipc_exchange(
    server: TestPipeServer,
    started: &StartedChild,
    case: SyntheticIpcCase,
    cancel: &CancelToken,
    control: &Control,
    state: &Mutex<ProcessState>,
    scm_policy: Option<&ScmPeerPolicy>,
) -> Result<bool, ServiceError> {
    let expected = PinnedProcess::from_controlled_child(started).map_err(peer_failure)?;
    let wrong;
    let pin = if case == SyntheticIpcCase::WrongIdentity {
        wrong = PinnedProcess::current().map_err(peer_failure)?;
        &wrong
    } else {
        &expected
    };
    let policy = TestPeerPolicy::current().map_err(peer_failure)?;
    control.ipc_stage.store(1, Ordering::SeqCst);
    let result = (|| {
        let mut session = if let Some(scm) = scm_policy {
            server.accept_scm_cancellable(pin, scm, Duration::from_secs(3), cancel)?
        } else {
            server.accept_cancellable(pin, &policy, Duration::from_secs(3), cancel)?
        };
        session.issue_challenge(Duration::from_secs(2))?;
        control.ipc_stage.store(2, Ordering::SeqCst);
        if case == SyntheticIpcCase::LateResponse {
            // Deterministic offline schedule: do not consume a response until
            // STOP's shared token is set (or this bounded checkpoint expires).
            // Thus a delayed/pending client echo cannot win merely because the
            // test controller was descheduled; R3 still decides cancellation.
            let end = Instant::now() + Duration::from_millis(1500);
            while !cancel.is_cancelled() && Instant::now() < end {
                thread::sleep(Duration::from_millis(2));
            }
        }
        let receipt = session.verify_response()?;
        // R3's final token load remains the success linearization point. STOP
        // after that point does not retroactively revoke a completed receipt.
        let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
        let trace = s.ipc.as_mut().unwrap();
        trace.authenticated = true;
        trace.process_identity_matched = receipt.token_user_matched
            && receipt.process_handle_matched
            && receipt.creation_time_matched
            && receipt.challenge_consumed
            && !receipt.production_service_identity;
        if case == SyntheticIpcCase::Replay {
            trace.replay_rejected = session
                .verify_response()
                .is_err_and(|e| e.code() == "challenge_consumed");
        }
        control.ipc_stage.store(3, Ordering::SeqCst);
        Ok::<_, PeerError>(true)
    })(); // session, pipe, challenge and pinned duplicates drop before Job cleanup.
    let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
    s.ipc.as_mut().unwrap().pipe_released_before_job = true;
    match result {
        Ok(value) => Ok(value),
        Err(e) if e.code() == "peer_cancelled" && control.stop.load(Ordering::SeqCst) => {
            s.ipc.as_mut().unwrap().cancellation_observed = true;
            Ok(false)
        }
        Err(e) => Err(peer_failure(e)),
    }
}
fn launch_failure(error: launch::LaunchError) -> ServiceError {
    ServiceError {
        code: error.code(),
        native_code: error.os_error.map(|n| n as u32),
    }
}
struct Worker {
    thread: Option<JoinHandle<Result<(), ServiceError>>>,
    ready: Option<Arc<Event>>,
    startup: Arc<Mutex<Option<Result<(), ServiceError>>>>,
    control: Arc<Control>,
    joined: bool,
    process: Option<Arc<Mutex<ProcessState>>>,
    ready_timeout: Duration,
}
impl Worker {
    fn start(
        control: Arc<Control>,
        case: Option<SyntheticServiceCase>,
    ) -> Result<Self, ServiceError> {
        let stop_event = control.install_event()?;
        let ready = Arc::new(Event::new()?);
        let thread_ready = ready.clone();
        let startup = Arc::new(Mutex::new(None));
        let thread_startup = startup.clone();
        let thread_control = control.clone();
        let thread = thread::Builder::new()
            .name("r4a-synthetic-idle".into())
            .spawn(move || {
                let start_result = if case == Some(SyntheticServiceCase::StartupFailure) {
                    Err(ServiceError::new("synthetic_start_failure"))
                } else {
                    Ok(())
                };
                *thread_startup
                    .lock()
                    .map_err(|_| ServiceError::new("worker_lock_poisoned"))? =
                    Some(start_result.clone());
                thread_ready.set()?;
                start_result?;
                if case == Some(SyntheticServiceCase::WorkerExit) {
                    return Err(ServiceError::new("synthetic_worker_exit"));
                }
                loop {
                    if thread_control.stop.load(Ordering::SeqCst) || stop_event.wait(50)? {
                        break;
                    }
                }
                if case == Some(SyntheticServiceCase::StopFailure) {
                    return Err(ServiceError::new("synthetic_stop_failure"));
                }
                Ok(())
            })
            .map_err(|e| ServiceError {
                code: "worker_create_failed",
                native_code: e.raw_os_error().map(|n| n as u32),
            })?;
        Ok(Self {
            thread: Some(thread),
            ready: Some(ready),
            startup,
            control,
            joined: false,
            process: None,
            ready_timeout: Duration::from_secs(2),
        })
    }
    fn start_process(
        control: Arc<Control>,
        request: LaunchRequest,
        state: Arc<Mutex<ProcessState>>,
    ) -> Result<Self, ServiceError> {
        let _stop_event = control.install_event()?;
        let ready = Arc::new(Event::new()?);
        let startup = Arc::new(Mutex::new(None));
        let thread_ready = ready.clone();
        let thread_startup = startup.clone();
        let thread_control = control.clone();
        let thread_state = state.clone();
        let cancel = request.cancel.clone();
        let ready_timeout = request.timeout + Duration::from_millis(500);
        let thread = thread::Builder::new()
            .name("offline-synthetic-process".into())
            .spawn(move || {
                let ipc_case = thread_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .ipc_case;
                let ipc_setup = if let Some(case) = ipc_case {
                    (|| {
                        let scm_policy = if thread_state
                            .lock()
                            .map_err(|_| ServiceError::new("worker_lock_poisoned"))?
                            .scm_peer
                        {
                            Some(ScmPeerPolicy::current().map_err(peer_failure)?)
                        } else {
                            None
                        };
                        let server = match &scm_policy {
                            Some(policy) => TestPipeServer::bind_scm(policy),
                            None => TestPipeServer::bind(),
                        }
                        .map_err(peer_failure)?;
                        let parent = PinnedProcess::current().map_err(peer_failure)?;
                        let gate = serde_json::to_vec(&IpcGate {
                            pipe: server.name().as_str().into(),
                            parent: parent.id(),
                            created: parent.creation_time(),
                            case,
                        })
                        .map_err(|_| ServiceError::new("ipc_gate_invalid"))?;
                        Ok::<_, ServiceError>((Some(server), gate, scm_policy))
                    })()
                } else {
                    Ok((None, Vec::new(), None))
                };
                let mut ipc_failure = None;
                let (mut server, gate, scm_policy) = match ipc_setup {
                    Ok(setup) => setup,
                    Err(e) => {
                        *thread_startup.lock().unwrap_or_else(|p| p.into_inner()) =
                            Some(Err(e.clone()));
                        thread_ready.set()?;
                        return Err(e);
                    }
                };
                let mut on_ready = |started: StartedChild| {
                    if thread_control.stop.load(Ordering::SeqCst) {
                        return Err(launch::error("startup_cancelled"));
                    }
                    let accepted = (|| {
                        if let Some(case) = ipc_case {
                            match ipc_exchange(
                                server.take().unwrap(),
                                &started,
                                case,
                                &cancel,
                                &thread_control,
                                &thread_state,
                                scm_policy.as_ref(),
                            ) {
                                Ok(true) => {}
                                Ok(false) => return Ok(()),
                                Err(e) => {
                                    ipc_failure = Some(e);
                                    cancel.cancel();
                                    return Ok(());
                                }
                            }
                        }
                        thread_state
                            .lock()
                            .map_err(|_| ServiceError::new("worker_lock_poisoned"))?
                            .started = Some(started);
                        *thread_startup
                            .lock()
                            .map_err(|_| ServiceError::new("worker_lock_poisoned"))? = Some(Ok(()));
                        thread_ready.set()?;
                        #[cfg(test)]
                        if let Some(point) = thread_control.after_ack.lock().unwrap().clone() {
                            point.hit()?;
                        }
                        Ok(())
                    })();
                    if let Err(error) = accepted {
                        *thread_startup.lock().unwrap_or_else(|p| p.into_inner()) =
                            Some(Err(error));
                        cancel.cancel();
                        return Err(launch::error("startup_callback_failed"));
                    }
                    Ok(())
                };
                #[cfg(test)]
                let result = if ipc_case.is_some() {
                    launch::launch_with_ipc(request, &gate, &mut |child| {
                        on_ready(child)?;
                        Ok(thread_state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .ipc
                            .as_ref()
                            .unwrap()
                            .authenticated)
                    })
                } else {
                    let point = thread_control.before_go.lock().unwrap().clone();
                    if let Some(point) = point {
                        launch::launch_with_startup_observed(request, &mut on_ready, &mut |_| {
                            point.hit().expect("bounded before-GO schedule");
                        })
                    } else {
                        launch::launch_with_startup(request, &mut on_ready)
                    }
                };
                #[cfg(not(test))]
                let result = if ipc_case.is_some() {
                    launch::launch_with_ipc(request, &gate, &mut |child| {
                        on_ready(child)?;
                        Ok(thread_state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .ipc
                            .as_ref()
                            .unwrap()
                            .authenticated)
                    })
                } else {
                    launch::launch_with_startup(request, &mut on_ready)
                };
                let completion = match result {
                    Ok(report) => {
                        let stopped = thread_control.stop.load(Ordering::SeqCst);
                        let outcome = match report.outcome {
                            LaunchOutcome::Aborted if stopped => Ok(()),
                            LaunchOutcome::TimedOut => {
                                Err(ServiceError::new("synthetic_process_timeout"))
                            }
                            _ => Err(ServiceError::new("synthetic_process_exited")),
                        };
                        thread_state
                            .lock()
                            .map_err(|_| ServiceError::new("worker_lock_poisoned"))?
                            .report = Some(report);
                        outcome
                    }
                    Err(error)
                        if thread_control.stop.load(Ordering::SeqCst)
                            && matches!(
                                error.code(),
                                "cancelled_before_spawn" | "startup_cancelled"
                            ) =>
                    {
                        Ok(())
                    }
                    Err(error) => Err(launch_failure(error)),
                };
                let completion = if let Some(error) = ipc_failure {
                    Err(error)
                } else {
                    completion
                };
                let mut status = thread_startup
                    .lock()
                    .map_err(|_| ServiceError::new("worker_lock_poisoned"))?;
                if status.is_none() {
                    *status = Some(match &completion {
                        Ok(()) => Err(ServiceError::new("synthetic_process_cancelled")),
                        Err(error) => Err(error.clone()),
                    });
                    thread_ready.set()?;
                }
                completion
            })
            .map_err(|e| ServiceError {
                code: "worker_create_failed",
                native_code: e.raw_os_error().map(|n| n as u32),
            })?;
        Ok(Self {
            thread: Some(thread),
            ready: Some(ready),
            startup,
            control,
            joined: false,
            process: Some(state),
            ready_timeout,
        })
    }
    fn ensure_process_alive(&self) -> Result<(), ServiceError> {
        if let Some(state) = &self.process {
            let state = state
                .lock()
                .map_err(|_| ServiceError::new("worker_lock_poisoned"))?;
            let child = state
                .started
                .as_ref()
                .ok_or_else(|| ServiceError::new("worker_not_ready"))?;
            if !child.is_alive().map_err(launch_failure)? {
                return Err(ServiceError::new("startup_child_exited"));
            }
        }
        Ok(())
    }
    fn await_ready(&self) -> Result<(), ServiceError> {
        let end = Instant::now() + self.ready_timeout;
        loop {
            if self
                .ready
                .as_ref()
                .ok_or_else(|| ServiceError::new("worker_not_ready"))?
                .wait(20)?
            {
                return self
                    .startup
                    .lock()
                    .map_err(|_| ServiceError::new("worker_lock_poisoned"))?
                    .as_ref()
                    .ok_or_else(|| ServiceError::new("worker_not_ready"))?
                    .clone();
            }
            if self.finished() || Instant::now() >= end {
                if let Some(result) = self
                    .startup
                    .lock()
                    .map_err(|_| ServiceError::new("worker_lock_poisoned"))?
                    .as_ref()
                {
                    return result.clone();
                }
                return Err(ServiceError::new("worker_not_ready"));
            }
        }
    }
    fn finished(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| t.is_finished())
    }
    fn join(&mut self) -> Result<(), ServiceError> {
        let result = if let Some(t) = self.thread.take() {
            self.joined = true;
            t.join()
                .unwrap_or_else(|_| Err(ServiceError::new("worker_panicked")))
        } else {
            Ok(())
        };
        self.ready.take();
        if let Some(state) = &self.process {
            state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .started
                .take();
        }
        result
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.control.request_stop();
        let _ = self.join();
    }
}
struct EngineCleanup(Arc<Control>);
impl Drop for EngineCleanup {
    fn drop(&mut self) {
        let _ = self.0.request_stop();
        self.0.clear();
    }
}

#[derive(Debug)]
pub struct SyntheticServiceReport {
    pub worker_joined: bool,
    pub resources_released: bool,
    pub prepared_before_running: bool,
}
#[derive(Debug)]
pub struct SyntheticProcessReport {
    pub lifecycle: SyntheticServiceReport,
    pub launch: Option<LaunchReport>,
    pub ipc: Option<SyntheticIpcReport>,
}
fn run_engine(
    sink: &mut impl StatusSink,
    control: Arc<Control>,
    case: Option<SyntheticServiceCase>,
) -> Result<SyntheticServiceReport, ServiceError> {
    run_engine_with_process(sink, control, case, None)
}
fn run_engine_with_process(
    sink: &mut impl StatusSink,
    control: Arc<Control>,
    case: Option<SyntheticServiceCase>,
    process: Option<(LaunchRequest, Arc<Mutex<ProcessState>>)>,
) -> Result<SyntheticServiceReport, ServiceError> {
    // The engine owns the Control -> request token binding, irrespective of
    // which internal entry supplied the service-owned Arc. Bind before START_PENDING
    // can accept STOP. Duplicate preparation must fail before installing cleanup
    // for a lifecycle owned by somebody else. R2 still validates the request
    // before creating anything; this binding grants no launch authorization.
    if let Some((request, _)) = &process {
        control.install_process_cancel(request.cancel.clone())?;
    }
    let _cleanup = EngineCleanup(control.clone());
    let mut machine = ServiceMachine::new();
    let mut worker: Option<Worker> = None;
    let mut prepared = false;
    let attempt = (|| {
        machine.start(sink)?;
        worker = Some(if let Some((request, state)) = process {
            Worker::start_process(control.clone(), request, state)?
        } else {
            Worker::start(control.clone(), case)?
        });
        if case == Some(SyntheticServiceCase::StopDuringStartup) {
            control.request_stop()?;
        }
        if let Err(error) = worker.as_ref().unwrap().await_ready() {
            if error.code() == "synthetic_process_cancelled" && control.stop.load(Ordering::SeqCst)
            {
                return Ok(());
            }
            return Err(error);
        }
        if control.stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        if worker.as_ref().unwrap().finished() {
            return worker
                .as_mut()
                .unwrap()
                .join()
                .and(Err(ServiceError::new("worker_unexpected_exit")));
        }
        #[cfg(test)]
        r4b_tests::before_ready(&control)?;
        prepared = if worker.as_ref().unwrap().process.is_some() {
            // The live process probe is taken inside the same boundary as STOP
            // acceptance and status publication. It is not loaded-code attestation.
            control.publish_ready_checked(&mut machine, sink, || {
                worker.as_ref().unwrap().ensure_process_alive()
            })?
        } else {
            control.publish_ready(&mut machine, sink)?
        };
        if !prepared {
            return Ok(());
        }
        if case.is_some() {
            control.request_stop()?;
            if case == Some(SyntheticServiceCase::DuplicateStop) {
                control.request_stop()?;
            }
        }
        loop {
            let fault = control.fault.load(Ordering::SeqCst);
            if fault != 0 {
                return Err(ServiceError {
                    code: "service_control_failed",
                    native_code: Some(fault),
                });
            }
            if control.stop.load(Ordering::SeqCst) {
                break;
            }
            if control.interrogate.swap(false, Ordering::SeqCst) {
                machine.refresh(sink)?;
            }
            if worker.as_ref().unwrap().finished() {
                return worker
                    .as_mut()
                    .unwrap()
                    .join()
                    .and(Err(ServiceError::new("worker_unexpected_exit")));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    })();
    let mut failure = attempt.err();
    if let Err(e) = control.request_stop() {
        if failure.is_none() {
            failure = Some(e);
        }
    }
    if failure.is_some() {
        machine.failed = true;
    }
    if let Err(e) = machine.begin_stop(sink) {
        if failure.is_none() {
            failure = Some(e);
        }
    }
    let mut joined = true;
    if let Some(w) = worker.as_mut() {
        if let Err(e) = w.join() {
            if failure.is_none() {
                failure = Some(e);
            }
        }
        joined = w.joined;
    }
    drop(worker);
    control.clear();
    if let Err(e) = machine.finish_stop(sink, failure.is_some()) {
        if failure.is_none() {
            failure = Some(e);
        }
    }
    if let Some(e) = failure {
        return Err(e);
    }
    // Release the mutex guard before EngineCleanup runs on return.
    let resources_released = control
        .event
        .lock()
        .map_err(|_| ServiceError::new("control_lock_poisoned"))?
        .is_none();
    Ok(SyntheticServiceReport {
        worker_joined: joined,
        resources_released,
        prepared_before_running: prepared,
    })
}
/// Explicitly offline: uses real anonymous events and a fixed idle thread, but
/// the caller's sink is not the SCM and cannot establish a service identity.
pub fn run_synthetic_lifecycle(
    sink: &mut impl StatusSink,
    case: SyntheticServiceCase,
) -> Result<SyntheticServiceReport, ServiceError> {
    run_engine(sink, Arc::new(Control::new()), Some(case))
}
/// Offline, fixed R2 payload only. No SCM entry, runtime authority, or R3 connection.
pub fn run_synthetic_process_lifecycle(
    sink: &mut impl StatusSink,
    request: LaunchRequest,
    control: SyntheticProcessControl,
) -> Result<SyntheticProcessReport, ServiceError> {
    let state = Arc::new(Mutex::new(ProcessState::default()));
    let lifecycle =
        run_engine_with_process(sink, control.inner, None, Some((request, state.clone())))?;
    let mut state = state
        .lock()
        .map_err(|_| ServiceError::new("worker_lock_poisoned"))?;
    Ok(SyntheticProcessReport {
        lifecycle,
        launch: state.report.take(),
        ipc: state.ipc.take(),
    })
}
/// Real R2 Job-bound test executable + R3 native authentication, under the same
/// R4 STOP token. Not used by SCM, Gateway or any production qualification.
pub fn run_synthetic_ipc_lifecycle(
    sink: &mut impl StatusSink,
    request: LaunchRequest,
    control: SyntheticProcessControl,
    case: SyntheticIpcCase,
) -> Result<SyntheticProcessReport, ServiceError> {
    if !matches!(
        request.target,
        launch::LaunchTarget::SyntheticIpc | launch::LaunchTarget::StandaloneIpc
    ) {
        return Err(ServiceError::new("ipc_fixture_required"));
    }
    let state = Arc::new(Mutex::new(ProcessState {
        ipc_case: Some(case),
        ipc: Some(SyntheticIpcReport::default()),
        ..Default::default()
    }));
    let lifecycle =
        run_engine_with_process(sink, control.inner, None, Some((request, state.clone())))?;
    let mut s = state
        .lock()
        .map_err(|_| ServiceError::new("worker_lock_poisoned"))?;
    Ok(SyntheticProcessReport {
        lifecycle,
        launch: s.report.take(),
        ipc: s.ipc.take(),
    })
}
// Invalid authorization never downgrades to idle. Preserve the original native error.
fn run_scm_engine(
    sink: &mut impl StatusSink,
    control: Arc<Control>,
    selection: Result<Option<LaunchRequest>, launch::LaunchError>,
) -> Result<SyntheticServiceReport, ServiceError> {
    match selection {
        Ok(None) => run_engine(sink, control, None),
        Ok(Some(request)) => {
            let state = Arc::new(Mutex::new(ProcessState {
                scm_peer: true,
                ipc_case: Some(SyntheticIpcCase::Authenticate),
                ipc: Some(SyntheticIpcReport::default()),
                ..Default::default()
            }));
            run_engine_with_process(sink, control, None, Some((request, state)))
        }
        Err(error) => {
            let _cleanup = EngineCleanup(control);
            let mut machine = ServiceMachine::new();
            let original = launch_failure(error);
            let _ = machine.start(sink);
            machine.failed = true;
            let _ = machine.begin_stop(sink);
            let _ = machine.finish_stop(sink, true);
            Err(original)
        }
    }
}
struct NativeSink(SERVICE_STATUS_HANDLE);
impl StatusSink for NativeSink {
    fn report(&mut self, snapshot: ServiceSnapshot) -> Result<(), ServiceError> {
        let state = match snapshot.phase {
            ServicePhase::StartPending => SERVICE_START_PENDING,
            ServicePhase::Running => SERVICE_RUNNING,
            ServicePhase::StopPending => SERVICE_STOP_PENDING,
            ServicePhase::Stopped => SERVICE_STOPPED,
            ServicePhase::Dormant => return Err(ServiceError::new("invalid_service_state")),
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: snapshot.accepted_controls,
            dwWin32ExitCode: snapshot.win32_exit_code,
            dwServiceSpecificExitCode: snapshot.service_exit_code,
            dwCheckPoint: snapshot.checkpoint,
            dwWaitHint: snapshot.wait_hint_ms,
        };
        if unsafe { SetServiceStatus(self.0, &status) } == 0 {
            return Err(ServiceError::native("service_status_failed"));
        }
        Ok(())
    }
}
/// No SCM registration or valid status handle is created by this negative probe.
pub fn invalid_status_handle_probe() -> Result<(), ServiceError> {
    NativeSink(null_mut()).report(ServiceMachine::new().snapshot(ServicePhase::StartPending))
}
static CONTROL: OnceLock<Arc<Control>> = OnceLock::new();
static HOST_ERROR: Mutex<Option<ServiceError>> = Mutex::new(None);
fn save_host_error(error: ServiceError) {
    let mut slot = HOST_ERROR.lock().unwrap_or_else(|_| std::process::abort());
    if slot.is_none() {
        *slot = Some(error);
    }
}
// Shared dispatch logic only. Offline tests can exercise the exact same Arc's
// STOP/SHUTDOWN effects without registering a service or inventing an SCM event.
fn dispatch_control(state: &Control, control: u32) -> u32 {
    if !state.active.load(Ordering::SeqCst) {
        return ERROR_SERVICE_NOT_ACTIVE;
    }
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => match state.request_stop() {
            Ok(()) => NO_ERROR,
            Err(e) => e.native_code.unwrap_or(ERROR_SERVICE_SPECIFIC_ERROR),
        },
        SERVICE_CONTROL_INTERROGATE => {
            state.interrogate.store(true, Ordering::SeqCst);
            NO_ERROR
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    let result = std::panic::catch_unwind(|| {
        let Some(state) = CONTROL.get() else {
            return ERROR_SERVICE_NOT_ACTIVE;
        };
        dispatch_control(state, control)
    });
    result.unwrap_or_else(|_| std::process::abort())
}
fn name_wide() -> Vec<u16> {
    TEST_SERVICE_NAME.encode_utf16().chain(Some(0)).collect()
}
unsafe fn scm_arguments_match(argc: u32, argv: *mut *mut u16) -> bool {
    if argc != 1 || argv.is_null() {
        return false;
    }
    let first = unsafe { *argv };
    if first.is_null() {
        return false;
    }
    for (i, expected) in name_wide().iter().enumerate() {
        if unsafe { *first.add(i) } != *expected {
            return false;
        }
    }
    true
}
unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    let result = std::panic::catch_unwind(|| {
        if !unsafe { scm_arguments_match(argc, argv) } {
            save_host_error(ServiceError::new("scm_arguments_rejected"));
            return;
        }
        let state = Arc::new(Control::new());
        if CONTROL.set(state.clone()).is_err() {
            save_host_error(ServiceError::new("duplicate_service_main"));
            return;
        }
        let cleanup = EngineCleanup(state.clone());
        let status =
            unsafe { RegisterServiceCtrlHandlerExW(name_wide().as_ptr(), Some(handler), null()) };
        if status.is_null() {
            save_host_error(ServiceError::native("service_handler_registration_failed"));
            return;
        }
        // No argument/environment-selected release. Absence alone preserves legacy idle.
        let selected = launch::scm_ipc_request(CancelToken::new());
        if let Err(e) = run_scm_engine(&mut NativeSink(status), state, selected) {
            save_host_error(e);
        }
        drop(cleanup);
    });
    if result.is_err() {
        std::process::abort();
    }
}
/// The only binary entry: no switches, environment-selected mode, install path,
/// external command, or Gateway launch. SCM must actually invoke service_main.
pub fn run_service_host(arguments: Vec<OsString>) -> Result<(), ServiceError> {
    if arguments.len() != 1 {
        return Err(ServiceError::new("command_line_rejected"));
    }
    let mut name = name_wide();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(ServiceError::native("scm_dispatcher_unavailable"));
    }
    let error = HOST_ERROR
        .lock()
        .map_err(|_| ServiceError::new("host_error_lock_poisoned"))?
        .clone();
    if let Some(e) = error {
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod r4b_tests {
    use super::*;
    use std::{
        fs::File,
        process::{Command, Stdio},
        sync::{mpsc, Barrier},
    };

    pub(super) struct Checkpoint {
        arrived: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    fn checkpoint() -> (Arc<Checkpoint>, mpsc::Receiver<()>, mpsc::SyncSender<()>) {
        let (arrived, rx) = mpsc::sync_channel(1);
        let (tx, release) = mpsc::sync_channel(1);
        (
            Arc::new(Checkpoint {
                arrived,
                release: Mutex::new(release),
            }),
            rx,
            tx,
        )
    }
    impl Checkpoint {
        pub(super) fn hit(&self) -> Result<(), ServiceError> {
            self.arrived
                .send(())
                .map_err(|_| ServiceError::new("test_schedule_disconnected"))?;
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| ServiceError::new("test_schedule_deadline"))
        }
    }
    pub(super) fn before_ready(control: &Control) -> Result<(), ServiceError> {
        let point = control.before_ready.lock().unwrap().clone();
        if let Some(point) = point {
            point.hit()?;
        }
        Ok(())
    }
    #[derive(Clone, Default)]
    struct Trace {
        states: Arc<Mutex<Vec<ServicePhase>>>,
        accepted: Arc<AtomicBool>,
        late: Arc<AtomicBool>,
    }
    struct Sink {
        trace: Trace,
        pause: Option<(ServicePhase, Arc<Checkpoint>)>,
        fail: Option<ServicePhase>,
    }
    impl StatusSink for Sink {
        fn report(&mut self, s: ServiceSnapshot) -> Result<(), ServiceError> {
            if let Some((phase, point)) = &self.pause {
                if s.phase == *phase {
                    point.hit()?;
                }
            }
            if self.fail == Some(s.phase) {
                // Exercise a real Win32 failure, without registering a service.
                return invalid_status_handle_probe();
            }
            if s.phase == ServicePhase::Running && self.trace.accepted.load(Ordering::SeqCst) {
                self.trace.late.store(true, Ordering::SeqCst);
            }
            self.trace.states.lock().unwrap().push(s.phase);
            Ok(())
        }
    }
    fn sink(trace: &Trace) -> Sink {
        Sink {
            trace: trace.clone(),
            pause: None,
            fail: None,
        }
    }
    fn spawn_engine(
        control: Arc<Control>,
        mut sink: Sink,
        case: SyntheticServiceCase,
    ) -> (
        mpsc::Receiver<Result<SyntheticServiceReport, ServiceError>>,
        JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let _ = tx.send(run_engine(&mut sink, control, Some(case)));
        });
        (rx, thread)
    }
    fn finish(
        run: (
            mpsc::Receiver<Result<SyntheticServiceReport, ServiceError>>,
            JoinHandle<()>,
        ),
    ) -> Result<SyntheticServiceReport, ServiceError> {
        let result = run
            .0
            .recv_timeout(Duration::from_secs(2))
            .expect("bounded lifecycle completion");
        run.1.join().unwrap();
        result
    }
    fn arrive(rx: &mpsc::Receiver<()>) {
        rx.recv_timeout(Duration::from_secs(2))
            .expect("checkpoint reached");
    }
    fn stop(control: &Control, trace: &Trace) {
        control.request_stop().unwrap();
        trace.accepted.store(true, Ordering::SeqCst);
    }
    fn assert_closed(trace: &Trace) {
        let states = trace.states.lock().unwrap();
        assert_eq!(states.last(), Some(&ServicePhase::Stopped));
        assert_eq!(
            states
                .iter()
                .filter(|s| **s == ServicePhase::Stopped)
                .count(),
            1
        );
        assert!(
            !trace.late.load(Ordering::SeqCst),
            "RUNNING published after accepted STOP"
        );
        let mut stopping = false;
        for phase in states.iter() {
            if *phase == ServicePhase::StopPending {
                stopping = true;
            }
            if stopping {
                assert_ne!(*phase, ServicePhase::Running);
            }
        }
        println!("R4B_HISTORY={states:?};SCM_CONTROL_DELIVERY:false");
    }
    fn scenario(name: &str) {
        match name {
            "ready_first" => {
                let control = Arc::new(Control::new());
                let trace = Trace::default();
                let report = finish(spawn_engine(
                    control,
                    sink(&trace),
                    SyntheticServiceCase::NormalStop,
                ))
                .unwrap();
                assert!(
                    report.prepared_before_running
                        && report.worker_joined
                        && report.resources_released
                );
                assert_eq!(
                    *trace.states.lock().unwrap(),
                    vec![
                        ServicePhase::StartPending,
                        ServicePhase::Running,
                        ServicePhase::StopPending,
                        ServicePhase::Stopped
                    ]
                );
                assert_closed(&trace);
            }
            "stop_first" | "simultaneous" => {
                let control = Arc::new(Control::new());
                let trace = Trace::default();
                let (point, arrived, release) = checkpoint();
                *control.before_ready.lock().unwrap() = Some(point);
                let run = spawn_engine(
                    control.clone(),
                    sink(&trace),
                    SyntheticServiceCase::NormalStop,
                );
                arrive(&arrived);
                if name == "stop_first" {
                    stop(&control, &trace);
                    release.send(()).unwrap();
                } else {
                    let barrier = Arc::new(Barrier::new(3));
                    let b = barrier.clone();
                    let c = control.clone();
                    let t = trace.clone();
                    let stopper = thread::spawn(move || {
                        b.wait();
                        stop(&c, &t);
                    });
                    let b = barrier.clone();
                    let releaser = thread::spawn(move || {
                        b.wait();
                        release.send(()).unwrap();
                    });
                    barrier.wait();
                    stopper.join().unwrap();
                    releaser.join().unwrap();
                }
                let report = finish(run).unwrap();
                assert!(report.worker_joined && report.resources_released);
                if name == "stop_first" {
                    assert!(
                        !trace
                            .states
                            .lock()
                            .unwrap()
                            .contains(&ServicePhase::Running),
                        "accepted cancellation must suppress READY"
                    );
                }
                assert_closed(&trace);
            }
            "report_inflight" | "status_failure" | "status_failure_close" => {
                let control = Arc::new(Control::new());
                let trace = Trace::default();
                let (point, arrived, release) = checkpoint();
                let mut output = sink(&trace);
                output.pause = Some((ServicePhase::Running, point));
                if name != "report_inflight" {
                    output.fail = Some(ServicePhase::Running);
                }
                let run = spawn_engine(control.clone(), output, SyntheticServiceCase::NormalStop);
                arrive(&arrived);
                let (tx, rx) = mpsc::sync_channel(1);
                let c = control.clone();
                let t = trace.clone();
                let (entered, entry) = mpsc::sync_channel(1);
                let closing = name == "status_failure_close";
                let stopper = thread::spawn(move || {
                    entered.send(()).unwrap();
                    if closing {
                        c.clear();
                        t.accepted.store(true, Ordering::SeqCst);
                    } else {
                        stop(&c, &t);
                    }
                    tx.send(()).unwrap();
                });
                arrive(&entry);
                // A bounded predicate wait verifies acceptance cannot pass an in-flight report.
                let prematurely_accepted = rx.recv_timeout(Duration::from_millis(100)).is_ok();
                release.send(()).unwrap();
                let result = finish(run);
                stopper.join().unwrap();
                if name != "report_inflight" {
                    let error = result.unwrap_err();
                    assert_eq!(error.code(), "service_status_failed");
                    assert_eq!(error.native_code, Some(ERROR_INVALID_HANDLE));
                    assert!(!trace
                        .states
                        .lock()
                        .unwrap()
                        .contains(&ServicePhase::Running));
                } else {
                    result.unwrap();
                }
                assert!(
                    !prematurely_accepted,
                    "STOP/close accepted while READY publication was in flight"
                );
                assert_closed(&trace);
            }
            "repeated_stop" => {
                let control = Arc::new(Control::new());
                let event = control.install_event().unwrap();
                let gate = Arc::new(Barrier::new(9));
                let mut threads = Vec::new();
                for _ in 0..8 {
                    let c = control.clone();
                    let b = gate.clone();
                    threads.push(thread::spawn(move || {
                        b.wait();
                        c.request_stop().unwrap();
                    }));
                }
                gate.wait();
                for t in threads {
                    t.join().unwrap();
                }
                assert!(event.wait(0).unwrap());
                assert!(control.active.load(Ordering::SeqCst));
                control.clear();
                drop(event);
            }
            "startup_failure" | "worker_exit" => {
                let control = Arc::new(Control::new());
                let trace = Trace::default();
                let (point, arrived, release) = checkpoint();
                let mut output = sink(&trace);
                output.pause = Some((ServicePhase::StartPending, point));
                let (case, expected) = if name == "startup_failure" {
                    (
                        SyntheticServiceCase::StartupFailure,
                        "synthetic_start_failure",
                    )
                } else {
                    (SyntheticServiceCase::WorkerExit, "synthetic_worker_exit")
                };
                let run = spawn_engine(control.clone(), output, case);
                arrive(&arrived);
                stop(&control, &trace);
                release.send(()).unwrap();
                assert_eq!(finish(run).unwrap_err().code(), expected);
                assert!(!trace
                    .states
                    .lock()
                    .unwrap()
                    .contains(&ServicePhase::Running));
                assert_closed(&trace);
            }
            "late_ready" => {
                let mut machine = ServiceMachine::new();
                let trace = Trace::default();
                let mut output = sink(&trace);
                machine.start(&mut output).unwrap();
                machine.begin_stop(&mut output).unwrap();
                assert!(machine.ready(&mut output).is_err());
                machine.finish_stop(&mut output, true).unwrap();
                assert!(machine.ready(&mut output).is_err());
                assert!(machine.refresh(&mut output).is_err());
                assert_closed(&trace);
            }
            "closed_callbacks" => {
                let control = Arc::new(Control::new());
                let trace = Trace::default();
                finish(spawn_engine(
                    control.clone(),
                    sink(&trace),
                    SyntheticServiceCase::NormalStop,
                ))
                .unwrap();
                assert!(
                    control.request_stop().is_err(),
                    "closed lifecycle must reject late callbacks"
                );
                assert!(
                    control.install_event().is_err(),
                    "closed lifecycle must not recreate events"
                );
                assert_closed(&trace);
            }
            "poison_cancel" => {
                let control = Arc::new(Control::new());
                let event = control.install_event().unwrap();
                let c = control.clone();
                assert!(thread::spawn(move || {
                    let _held = c.transition.lock().unwrap();
                    panic!("synthetic transition unwind");
                })
                .join()
                .is_err());
                assert_eq!(
                    control.request_stop().unwrap_err().code(),
                    "control_transition_poisoned"
                );
                assert!(
                    control.stop.load(Ordering::SeqCst),
                    "poisoned transition must still cancel before Worker::drop joins"
                );
                assert!(event.wait(0).unwrap());
                control.clear();
                assert!(control.install_event().is_err());
            }
            "panic_cleanup" => {
                struct PanickingSink;
                impl StatusSink for PanickingSink {
                    fn report(&mut self, snapshot: ServiceSnapshot) -> Result<(), ServiceError> {
                        if snapshot.phase == ServicePhase::Running {
                            panic!("synthetic status unwind");
                        }
                        Ok(())
                    }
                }
                let control = Arc::new(Control::new());
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_engine(
                        &mut PanickingSink,
                        control.clone(),
                        Some(SyntheticServiceCase::NormalStop),
                    )
                }));
                assert!(result.is_err());
                assert!(control.stop.load(Ordering::SeqCst));
                assert!(!control.active.load(Ordering::SeqCst));
                assert!(control.event.lock().unwrap().is_none());
                assert!(control.install_event().is_err());
                println!(
                    "R4B_PANIC_CLEANUP=worker_joined;event_released;lifecycle_closed;SCM:false"
                );
            }
            "cleanup" => {
                let control = Arc::new(Control::new());
                let event = control.install_event().unwrap();
                let weak = Arc::downgrade(&event);
                drop(event);
                let gate = Arc::new(Barrier::new(9));
                let mut threads = Vec::new();
                for _ in 0..8 {
                    let c = control.clone();
                    let b = gate.clone();
                    threads.push(thread::spawn(move || {
                        b.wait();
                        c.clear();
                    }));
                }
                gate.wait();
                for t in threads {
                    t.join().unwrap();
                }
                assert!(weak.upgrade().is_none(), "event must be released");
                assert!(!control.active.load(Ordering::SeqCst));
                assert!(
                    control.stop.load(Ordering::SeqCst),
                    "cleanup must cancel worker before closing its control event"
                );
                assert!(
                    control.install_event().is_err(),
                    "cleanup cannot reopen lifecycle"
                );
            }
            "process_before_go" => process_schedule("before_go"),
            "process_after_ack" => process_schedule("after_ack"),
            "process_simultaneous" => process_schedule("simultaneous_process"),
            "process_panic" => process_panic_cleanup(),
            "process_reentrant_stop" => process_reentrant_stop(),
            _ => panic!("unknown fixed test scenario"),
        }
    }
    // This entry is only called by bounded child test processes, never by the service binary.
    #[test]
    #[ignore]
    fn schedule_child() {
        scenario(&std::env::var("R4B_TEST_SCENARIO").unwrap());
    }
    fn isolated(name: &str) {
        let root = std::env::var_os("GATEWAY_CANDIDATE_TEMP_ROOT").unwrap();
        let out = std::path::PathBuf::from(root).join(format!("r4b-{name}-{}", std::process::id()));
        let stdout = out.with_extension("stdout.log");
        let stderr = out.with_extension("stderr.log");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "service::r4b_tests::schedule_child",
                "--nocapture",
            ])
            .env("R4B_TEST_SCENARIO", name)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                panic!("bounded synthetic test process deadline: {name}");
            }
            thread::sleep(Duration::from_millis(5));
        };
        let output = std::fs::read_to_string(&stdout).unwrap();
        let errors = std::fs::read_to_string(&stderr).unwrap();
        println!(
            "R4B_SCHEDULE={name};EXIT={:?};SCM:false\n{output}",
            status.code()
        );
        assert!(status.success(), "scenario {name} failed: {errors}");
    }
    macro_rules! isolated_test {
        ($name:ident,$case:literal) => {
            #[test]
            fn $name() {
                isolated($case);
            }
        };
    }
    isolated_test!(ready_precedes_stop, "ready_first");
    isolated_test!(accepted_stop_precedes_ready, "stop_first");
    isolated_test!(simultaneous_ready_stop_has_one_history, "simultaneous");
    isolated_test!(stop_acceptance_waits_for_inflight_ready, "report_inflight");
    isolated_test!(repeated_stops_are_idempotent, "repeated_stop");
    isolated_test!(
        startup_failure_races_with_internal_cancel,
        "startup_failure"
    );
    isolated_test!(native_status_failure_survives_stop_race, "status_failure");
    isolated_test!(
        native_status_failure_survives_close_race,
        "status_failure_close"
    );
    isolated_test!(poisoned_transition_still_cancels_worker, "poison_cancel");
    isolated_test!(
        status_unwind_joins_worker_and_closes_lifecycle,
        "panic_cleanup"
    );
    isolated_test!(late_ready_cannot_reopen_stop_pending, "late_ready");
    isolated_test!(closed_lifecycle_rejects_callbacks, "closed_callbacks");
    isolated_test!(parallel_cleanup_releases_event_once, "cleanup");
    isolated_test!(worker_exit_survives_cancel_race, "worker_exit");

    use crate::launch::{
        LaunchTarget, SyntheticCase, NODE_TEST_TOOL, SYNTHETIC_ENTRY, SYNTHETIC_ENTRY_SOURCE,
        SYNTHETIC_PACKAGE,
    };
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, sync::atomic::AtomicU64};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    struct RaceFixture {
        root: PathBuf,
        manifest: Value,
    }
    impl RaceFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "service-process-race-{}-{}",
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
    impl Drop for RaceFixture {
        fn drop(&mut self) {
            assert!(self.root.starts_with(std::env::temp_dir()));
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn phases(t: &Trace) -> Vec<ServicePhase> {
        t.states.lock().unwrap().clone()
    }
    fn authorized_fixture(f: &RaceFixture) -> LaunchRequest {
        let bin = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("cmg-runtime-boundary-ipc-child.exe");
        let child = fs::read(bin).unwrap();
        let host = fs::read(std::env::current_exe().unwrap()).unwrap();
        let mut manifest = f.manifest.clone();
        manifest["files"].as_array_mut().unwrap().push(json!({"path":"app/cmg-runtime-boundary-ipc-child.exe","kind":"resource","size":child.len(),"sha256":hash(&child)}));
        manifest["files"]
            .as_array_mut()
            .unwrap()
            .sort_by_key(|v| v["path"].as_str().unwrap().to_owned());
        let raw = serde_json::to_vec(&manifest).unwrap();
        let id = format!(
            "ipc-{}",
            hash(format!("{}{}{}", hash(&host), hash(&child), hash(&raw)).as_bytes())
        );
        let version = f.root.join(&id);
        let tree = version.join("ipc-fixture");
        for d in ["app/src/gateway", "temp", "work"] {
            fs::create_dir_all(tree.join(d)).unwrap();
        }
        for p in [
            "app/package.json",
            SYNTHETIC_ENTRY,
            "closure-report.json",
            "js-dependency-graph.json",
        ] {
            fs::copy(f.root.join(p), tree.join(p)).unwrap();
        }
        fs::write(tree.join("app/cmg-runtime-boundary-ipc-child.exe"), &child).unwrap();
        fs::write(version.join("ipc-manifest-v2.json"), &raw).unwrap();
        let hostpath = version.join("cmg-runtime-boundary-test-service.exe");
        fs::write(&hostpath, &host).unwrap();
        fs::write(version.join("ipc-start-authorization.json"),serde_json::to_vec(&json!({"schema_version":1,"purpose":"cmg-fixed-ipc-test-start","service_name":TEST_SERVICE_NAME,"artifact_id":id,"host_sha256":hash(&host),"child_sha256":hash(&child),"manifest_sha256":hash(&raw)})).unwrap()).unwrap();
        launch::offline_scm_candidate(&hostpath, CancelToken::new()).unwrap()
    }
    #[test]
    fn scm_policy_does_not_fall_back_to_medium_developer_identity() {
        let f = RaceFixture::new();
        let request = authorized_fixture(&f);
        let trace = Trace::default();
        let control = Arc::new(Control::new());
        struct StopRunning(Sink, Arc<Control>);
        impl StatusSink for StopRunning {
            fn report(&mut self, s: ServiceSnapshot) -> Result<(), ServiceError> {
                self.0.report(s)?;
                if s.phase == ServicePhase::Running {
                    self.1.request_stop()?;
                }
                Ok(())
            }
        }
        let mut output = StopRunning(sink(&trace), control.clone());
        let result = run_scm_engine(&mut output, control, Ok(Some(request)));
        assert!(
            result.is_err(),
            "an offline candidate must not authorize a developer token as an SCM peer"
        );
        assert!(!phases(&trace).contains(&ServicePhase::Running));
        assert_closed(&trace);
    }
    #[test]
    fn offline_authorized_candidate_reuses_engine_receipt_and_cleanup() {
        let f = RaceFixture::new();
        let request = authorized_fixture(&f);
        let control = SyntheticProcessControl::new();
        let trace = Trace::default();
        let mut output = sink(&trace);
        // The sink accepts STOP immediately after the real authentication receipt.
        struct StopSink<'a>(&'a mut Sink, mpsc::SyncSender<()>);
        impl StatusSink for StopSink<'_> {
            fn report(&mut self, s: ServiceSnapshot) -> Result<(), ServiceError> {
                self.0.report(s)?;
                if s.phase == ServicePhase::Running {
                    self.1.send(()).unwrap();
                }
                Ok(())
            }
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let stop_control = control.inner.clone();
        let stopper = thread::spawn(move || {
            rx.recv_timeout(Duration::from_secs(3)).unwrap();
            stop_control.request_stop().unwrap();
        });
        let mut output = StopSink(&mut output, tx);
        // Content-only offline authorization is deliberately not an SCM token.
        // Exercise the same engine with the unchanged offline test-peer policy.
        let state = Arc::new(Mutex::new(ProcessState {
            ipc_case: Some(SyntheticIpcCase::Authenticate),
            ipc: Some(SyntheticIpcReport::default()),
            ..Default::default()
        }));
        let result = run_engine_with_process(
            &mut output,
            control.inner.clone(),
            None,
            Some((request, state)),
        )
        .unwrap();
        stopper.join().unwrap();
        assert!(
            result.prepared_before_running && result.worker_joined && result.resources_released
        );
        assert_eq!(
            phases(&trace)
                .iter()
                .filter(|s| **s == ServicePhase::Running)
                .count(),
            1
        );
        assert_eq!(
            phases(&trace)
                .iter()
                .filter(|s| **s == ServicePhase::Stopped)
                .count(),
            1
        );
    }
    #[test]
    fn scm_invalid_authorization_never_runs_or_falls_back_to_idle() {
        let trace = Trace::default();
        let mut output = sink(&trace);
        let control = Arc::new(Control::new());
        let error = run_scm_engine(
            &mut output,
            control,
            Err(launch::error("scm_authorization_invalid")),
        )
        .unwrap_err();
        assert_eq!(error.code(), "scm_authorization_invalid");
        assert_eq!(
            phases(&trace),
            vec![
                ServicePhase::StartPending,
                ServicePhase::StopPending,
                ServicePhase::Stopped
            ]
        );
    }
    #[test]
    fn scm_preaccepted_stop_does_not_bypass_service_identity_validation() {
        let f = RaceFixture::new();
        let request = authorized_fixture(&f);
        let control = Arc::new(Control::new());
        control.request_stop().unwrap();
        let trace = Trace::default();
        let mut output = sink(&trace);
        let error = run_scm_engine(&mut output, control, Ok(Some(request))).unwrap_err();
        assert_eq!(error.code(), "peer_identity_denied");
        assert!(!phases(&trace).contains(&ServicePhase::Running));
        assert_closed(&trace);
    }

    #[test]
    fn scm_authorized_challenge_wait_cancel_reclaims_real_ipc_and_job() {
        let f = RaceFixture::new();
        let request = authorized_fixture(&f);
        let control = Arc::new(Control::new());
        let c = control.clone();
        let state = Arc::new(Mutex::new(ProcessState {
            ipc_case: Some(SyntheticIpcCase::ChallengeWait),
            ipc: Some(SyntheticIpcReport::default()),
            ..Default::default()
        }));
        let trace = Trace::default();
        let mut output = sink(&trace);
        let stopper = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while c.ipc_stage.load(Ordering::SeqCst) != 2 {
                assert!(Instant::now() < deadline, "bounded real challenge wait");
                thread::sleep(Duration::from_millis(5));
            }
            c.request_stop().unwrap();
            c.request_stop().unwrap();
        });
        let result =
            run_engine_with_process(&mut output, control, None, Some((request, state.clone())))
                .unwrap();
        stopper.join().unwrap();
        let state = state.lock().unwrap();
        let ipc = state.ipc.as_ref().unwrap();
        let report = state.report.as_ref().unwrap();
        assert!(ipc.cancellation_observed && !ipc.authenticated && ipc.pipe_released_before_job);
        assert!(report.process_reaped && report.job_closed && report.output_readers_joined);
        assert!(result.worker_joined && result.resources_released);
        assert!(!phases(&trace).contains(&ServicePhase::Running));
        assert_closed(&trace);
    }
    #[test]
    fn scm_authorized_request_mutation_and_changed_record_are_rejected_before_running() {
        for mutation in ["argument", "environment", "record", "child"] {
            let f = RaceFixture::new();
            let mut request = authorized_fixture(&f);
            match mutation {
                "argument" => request.arguments.push("--gateway".into()),
                "environment" => request
                    .environment_overrides
                    .push(("PATH".into(), "unapproved".into())),
                "record" => {
                    fs::write(
                        request
                            .release_root
                            .parent()
                            .unwrap()
                            .join("ipc-start-authorization.json"),
                        b"{}",
                    )
                    .unwrap();
                }
                _ => {
                    fs::write(&request.executable, b"changed after validation").unwrap();
                }
            }
            let trace = Trace::default();
            let mut output = sink(&trace);
            assert!(
                run_scm_engine(&mut output, Arc::new(Control::new()), Ok(Some(request))).is_err()
            );
            assert!(!phases(&trace).contains(&ServicePhase::Running));
            assert_closed(&trace);
        }
    }
    #[test]
    fn scm_missing_authorization_retains_idle_and_native_failure_is_preserved() {
        assert!(launch::scm_ipc_request(CancelToken::new())
            .unwrap()
            .is_none());
        let control = Arc::new(Control::new());
        control.request_stop().unwrap();
        let trace = Trace::default();
        let mut output = sink(&trace);
        assert!(
            run_scm_engine(&mut output, control, Ok(None))
                .unwrap()
                .resources_released
        );
        assert_closed(&trace);
        let trace = Trace::default();
        let mut output = sink(&trace);
        let mut error = launch::error("scm_acl_query_failed");
        error.os_error = Some(5);
        let error = run_scm_engine(&mut output, Arc::new(Control::new()), Err(error)).unwrap_err();
        assert_eq!(error.native_code, Some(5));
        assert!(!phases(&trace).contains(&ServicePhase::Running));
    }
    fn process_schedule(name: &str) {
        let fixture = RaceFixture::new();
        let control = SyntheticProcessControl::new();
        let trace = Trace::default();
        let (point, arrived, release) = checkpoint();
        let ack_schedule = if name == "after_ack" {
            let (point, arrived, release) = checkpoint();
            *control.inner.after_ack.lock().unwrap() = Some(point);
            Some((arrived, release))
        } else {
            None
        };
        if name == "before_go" {
            *control.inner.before_go.lock().unwrap() = Some(point);
        } else {
            *control.inner.before_ready.lock().unwrap() = Some(point);
        }
        let mut request = fixture.request(SyntheticCase::Wait);
        request.timeout = Duration::from_secs(4);
        let c = control.clone();
        let mut output = sink(&trace);
        let (tx, rx) = mpsc::sync_channel(1);
        let runner = thread::spawn(move || {
            tx.send(run_synthetic_process_lifecycle(&mut output, request, c))
                .unwrap();
        });
        arrive(&arrived);
        if let Some((arrived, _)) = &ack_schedule {
            // The process worker is still inside its accepted-ACK callback,
            // while the lifecycle thread has not yet published RUNNING.
            arrive(arrived);
        }
        if name == "simultaneous_process" {
            let gate = Arc::new(Barrier::new(3));
            let g = gate.clone();
            let c = control.clone();
            let stopper = thread::spawn(move || {
                g.wait();
                c.stop().unwrap();
            });
            let g = gate.clone();
            let releaser = thread::spawn(move || {
                g.wait();
                release.send(()).unwrap();
            });
            gate.wait();
            stopper.join().unwrap();
            releaser.join().unwrap();
        } else {
            stop(&control.inner, &trace);
            release.send(()).unwrap();
        }
        if let Some((_, release)) = ack_schedule {
            release.send(()).unwrap();
        }
        let report = rx
            .recv_timeout(Duration::from_secs(4))
            .expect("bounded process cleanup")
            .unwrap();
        runner.join().unwrap();
        assert!(report.lifecycle.worker_joined && report.lifecycle.resources_released);
        if name != "simultaneous_process" {
            assert!(!trace
                .states
                .lock()
                .unwrap()
                .contains(&ServicePhase::Running));
            assert!(!report.lifecycle.prepared_before_running);
        }
        if name != "before_go" {
            let launch = report
                .launch
                .expect("ACK was observed before READY checkpoint");
            assert!(launch.startup_confirmed && launch.output_readers_joined);
            assert!(launch.process_reaped && launch.job_closed);
            assert_eq!(launch.outcome, LaunchOutcome::Aborted);
        }
        assert_closed(&trace);
    }

    #[test]
    fn stop_before_go_cancels_real_suspended_child() {
        isolated("process_before_go");
    }
    #[test]
    fn stop_after_ack_suppresses_late_running() {
        isolated("process_after_ack");
    }
    #[test]
    fn simultaneous_process_ready_stop_is_linearized() {
        isolated("process_simultaneous");
    }
    fn process_panic_cleanup() {
        struct PanickingSink;
        impl StatusSink for PanickingSink {
            fn report(&mut self, snapshot: ServiceSnapshot) -> Result<(), ServiceError> {
                if snapshot.phase == ServicePhase::Running {
                    panic!("offline process status unwind");
                }
                Ok(())
            }
        }
        let fixture = RaceFixture::new();
        let request = fixture.request(SyntheticCase::Wait);
        let control = Arc::new(Control::new());
        let state = Arc::new(Mutex::new(ProcessState::default()));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_engine_with_process(
                &mut PanickingSink,
                control.clone(),
                None,
                Some((request, state.clone())),
            )
        }));
        assert!(outcome.is_err());
        assert!(!control.active.load(Ordering::SeqCst));
        assert!(control.event.lock().unwrap().is_none());
        assert!(control.process_cancel.lock().unwrap().is_none());
        let mut state = state.lock().unwrap();
        assert!(
            state.started.is_none(),
            "duplicate process probe must be closed"
        );
        let report = state
            .report
            .take()
            .expect("process worker joined during unwind");
        assert!(report.process_reaped && report.job_closed && report.output_readers_joined);
        assert_eq!(report.outcome, LaunchOutcome::Aborted);
    }
    #[test]
    fn process_status_unwind_reaps_child_and_joins_readers() {
        isolated("process_panic");
    }
    fn process_reentrant_stop() {
        struct ReentrantSink {
            control: SyntheticProcessControl,
            states: Vec<ServicePhase>,
        }
        impl StatusSink for ReentrantSink {
            fn report(&mut self, snapshot: ServiceSnapshot) -> Result<(), ServiceError> {
                if snapshot.phase == ServicePhase::Running {
                    return self.control.stop();
                }
                self.states.push(snapshot.phase);
                Ok(())
            }
        }
        let fixture = RaceFixture::new();
        let request = fixture.request(SyntheticCase::Wait);
        let control = SyntheticProcessControl::new();
        let state = Arc::new(Mutex::new(ProcessState::default()));
        let mut sink = ReentrantSink {
            control: control.clone(),
            states: vec![],
        };
        let error = run_engine_with_process(
            &mut sink,
            control.inner.clone(),
            None,
            Some((request, state.clone())),
        )
        .unwrap_err();
        assert_eq!(error.code(), "reentrant_stop_not_allowed");
        assert_eq!(
            sink.states,
            vec![
                ServicePhase::StartPending,
                ServicePhase::StopPending,
                ServicePhase::Stopped
            ]
        );
        let mut state = state.lock().unwrap();
        assert!(state.started.is_none());
        let report = state
            .report
            .take()
            .expect("worker joined after failed status report");
        assert!(report.process_reaped && report.job_closed && report.output_readers_joined);
        assert_eq!(report.outcome, LaunchOutcome::Aborted);
        assert!(REPORTING_CONTROL.with(|current| current.get().is_null()));
    }
    #[test]
    fn process_sink_stop_reentry_fails_without_deadlock_and_cleans_up() {
        isolated("process_reentrant_stop");
    }

    #[test]
    fn engine_adapter_binds_service_owned_control_before_start_pending() {
        struct BindingSink {
            control: Arc<Control>,
            cancel: CancelToken,
            phases: Vec<ServicePhase>,
        }
        impl StatusSink for BindingSink {
            fn report(&mut self, snapshot: ServiceSnapshot) -> Result<(), ServiceError> {
                self.phases.push(snapshot.phase);
                if snapshot.phase == ServicePhase::StartPending {
                    self.control.request_stop()?;
                    assert!(
                        self.cancel.is_cancelled(),
                        "accepted service-owned STOP did not reach the request's R2 token"
                    );
                }
                Ok(())
            }
        }
        let fixture = RaceFixture::new();
        let request = fixture.request(SyntheticCase::Wait);
        let control = Arc::new(Control::new());
        let state = Arc::new(Mutex::new(ProcessState::default()));
        let mut sink = BindingSink {
            control: control.clone(),
            cancel: request.cancel.clone(),
            phases: vec![],
        };
        // Deliberately use the internal engine with the service-owned Arc, not
        // the public wrapper's preinstalled token. No SCM is registered here.
        let report =
            run_engine_with_process(&mut sink, control, None, Some((request, state.clone())))
                .unwrap();
        assert!(report.worker_joined && report.resources_released);
        assert_eq!(
            sink.phases,
            vec![
                ServicePhase::StartPending,
                ServicePhase::StopPending,
                ServicePhase::Stopped
            ]
        );
        assert!(state.lock().unwrap().report.is_none());
    }

    #[test]
    fn engine_adapter_handler_stop_and_shutdown_cancel_the_original_r2_token() {
        struct HandlerSink {
            control: Arc<Control>,
            kind: u32,
            phases: Vec<ServicePhase>,
            calls: Vec<thread::JoinHandle<u32>>,
        }
        impl StatusSink for HandlerSink {
            fn report(&mut self, s: ServiceSnapshot) -> Result<(), ServiceError> {
                self.phases.push(s.phase);
                if s.phase == ServicePhase::Running {
                    for _ in 0..4 {
                        let state = self.control.clone();
                        let kind = self.kind;
                        // RUNNING publication owns transition. Never join a
                        // control-delivery thread from inside the status sink.
                        self.calls
                            .push(thread::spawn(move || dispatch_control(&state, kind)));
                    }
                }
                Ok(())
            }
        }
        for kind in [SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN] {
            let fixture = RaceFixture::new();
            let request = fixture.request(SyntheticCase::Wait);
            let cancel = request.cancel.clone();
            let control = Arc::new(Control::new());
            let state = Arc::new(Mutex::new(ProcessState::default()));
            let mut sink = HandlerSink {
                control: control.clone(),
                kind,
                phases: vec![],
                calls: vec![],
            };
            let report = run_engine_with_process(
                &mut sink,
                control.clone(),
                None,
                Some((request, state.clone())),
            )
            .unwrap();
            for call in sink.calls {
                assert!(matches!(
                    call.join().unwrap(),
                    NO_ERROR | ERROR_SERVICE_NOT_ACTIVE
                ));
            }
            assert!(cancel.is_cancelled());
            assert!(report.worker_joined && report.resources_released);
            assert_eq!(
                sink.phases,
                vec![
                    ServicePhase::StartPending,
                    ServicePhase::Running,
                    ServicePhase::StopPending,
                    ServicePhase::Stopped
                ]
            );
            let launch = state.lock().unwrap().report.take().unwrap();
            assert_eq!(launch.outcome, LaunchOutcome::Aborted);
            assert!(launch.job_closed && launch.process_reaped && launch.output_readers_joined);
            assert_eq!(dispatch_control(&control, kind), ERROR_SERVICE_NOT_ACTIVE);
        }
    }

    #[test]
    fn engine_adapter_duplicate_preparation_does_not_cancel_or_clear_the_owner() {
        let fixture = RaceFixture::new();
        let request = fixture.request(SyntheticCase::Wait);
        let attempted = request.cancel.clone();
        let owner = CancelToken::new();
        let control = Arc::new(Control::new());
        control.install_process_cancel(owner.clone()).unwrap();
        let state = Arc::new(Mutex::new(ProcessState::default()));
        let trace = Trace::default();
        let mut sink = sink(&trace);
        let error = run_engine_with_process(
            &mut sink,
            control.clone(),
            None,
            Some((request, state.clone())),
        )
        .unwrap_err();
        assert_eq!(error.code(), "duplicate_service_preparation");
        assert!(control.active.load(Ordering::SeqCst));
        assert!(!owner.is_cancelled() && !attempted.is_cancelled());
        assert!(control.event.lock().unwrap().is_none() && state.lock().unwrap().report.is_none());
        assert!(trace.states.lock().unwrap().is_empty());
        assert_eq!(
            dispatch_control(&control, SERVICE_CONTROL_SHUTDOWN),
            NO_ERROR
        );
        assert!(owner.is_cancelled() && !attempted.is_cancelled());
        control.clear();
    }
}

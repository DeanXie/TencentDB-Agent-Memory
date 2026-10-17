//! R4A test-only SCM host. No service installation, Gateway, issuer or verifier.
//! Offline sinks exercise lifecycle logic; they do not prove actual SCM behavior.
use std::{
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
struct Control {
    // Acceptance of cancellation, RUNNING publication and closure share this
    // lock. Lock order is transition -> event; the worker never takes transition.
    transition: Mutex<()>,
    stop: AtomicBool,
    interrogate: AtomicBool,
    active: AtomicBool,
    fault: AtomicU32,
    event: Mutex<Option<Arc<Event>>>,
    #[cfg(test)]
    before_ready: Mutex<Option<Arc<r4b_tests::Checkpoint>>>,
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
            #[cfg(test)]
            before_ready: Mutex::new(None),
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
    fn request_stop(&self) -> Result<(), ServiceError> {
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
        // Hold the boundary through the synchronous status API result, so a
        // concurrently invoked STOP is accepted only before or after this report.
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
struct Worker {
    thread: Option<JoinHandle<Result<(), ServiceError>>>,
    ready: Option<Arc<Event>>,
    startup: Arc<Mutex<Option<Result<(), ServiceError>>>>,
    control: Arc<Control>,
    joined: bool,
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
        })
    }
    fn await_ready(&self) -> Result<(), ServiceError> {
        let end = Instant::now() + Duration::from_secs(2);
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
fn run_engine(
    sink: &mut impl StatusSink,
    control: Arc<Control>,
    case: Option<SyntheticServiceCase>,
) -> Result<SyntheticServiceReport, ServiceError> {
    let _cleanup = EngineCleanup(control.clone());
    let mut machine = ServiceMachine::new();
    let mut worker: Option<Worker> = None;
    let mut prepared = false;
    let attempt = (|| {
        machine.start(sink)?;
        worker = Some(Worker::start(control.clone(), case)?);
        if case == Some(SyntheticServiceCase::StopDuringStartup) {
            control.request_stop()?;
        }
        worker.as_ref().unwrap().await_ready()?;
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
        prepared = control.publish_ready(&mut machine, sink)?;
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
        if let Err(e) = run_engine(&mut NativeSink(status), state, None) {
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
        fn hit(&self) -> Result<(), ServiceError> {
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
}

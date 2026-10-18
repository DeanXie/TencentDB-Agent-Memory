use std::{
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use windows_runtime_boundary::peer::*;
use windows_runtime_boundary::CancelToken;
use windows_sys::Win32::System::Pipes::{GetNamedPipeHandleStateW, PIPE_NOWAIT};
use windows_sys::Win32::{
    Foundation::*, Security::Authorization::*, Security::*, System::Threading::*,
};
use windows_sys::Win32::{Storage::FileSystem::*, System::Pipes::GetNamedPipeClientProcessId};

const WAIT: Duration = Duration::from_secs(3);

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn child(name: &PipeName, role: &str, second: Option<&PipeName>) -> ChildGuard {
    let parent = PinnedProcess::current().unwrap();
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "peer_child_entry", "--ignored", "--nocapture"])
        .env_clear()
        .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
        .env("R3_ROLE", role)
        .env("R3_PIPE", name.as_str())
        .env("R3_PARENT", parent.id().to_string())
        .env("R3_CREATED", parent.creation_time().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(n) = second {
        c.env("R3_SECOND", n.as_str());
    }
    ChildGuard(c.spawn().unwrap())
}
fn finish(child: &mut ChildGuard) {
    let end = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "synthetic client failed: {status}");
            break;
        }
        assert!(Instant::now() < end, "synthetic client did not exit");
        thread::sleep(Duration::from_millis(5));
    }
}
fn assert_server_token_restored() {
    let mut h = std::ptr::null_mut();
    unsafe {
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut h);
        let error = GetLastError();
        if opened != 0 {
            CloseHandle(h);
        }
        assert_eq!(opened, 0, "server thread retained an impersonation token");
        assert_eq!(error, ERROR_NO_TOKEN);
    }
}
fn run(role: &str, ttl: Duration) -> Result<PeerReceipt, PeerError> {
    let server = TestPipeServer::bind().unwrap();
    let mut child = child(server.name(), role, None);
    let expected = PinnedProcess::from_child(&child.0).unwrap();
    let policy = TestPeerPolicy::current().unwrap();
    let result = (|| {
        let mut session = server.accept(&expected, &policy, WAIT)?;
        session.issue_challenge(ttl)?;
        if role == "expired" {
            thread::sleep(Duration::from_millis(90));
        }
        if role == "exit" {
            finish(&mut child);
        }
        let r = session.verify_response()?;
        if role == "replay" {
            return session.verify_response();
        }
        Ok(r)
    })();
    assert_server_token_restored();
    finish(&mut child);
    result
}
#[test]
#[ignore = "subprocess entry; invoked explicitly by real IPC tests"]
fn peer_child_entry() {
    let name = PipeName::parse_local(&std::env::var("R3_PIPE").unwrap()).unwrap();
    let parent = PinnedProcess::open_test_peer(
        std::env::var("R3_PARENT").unwrap().parse().unwrap(),
        std::env::var("R3_CREATED").unwrap().parse().unwrap(),
    )
    .unwrap();
    let role = std::env::var("R3_ROLE").unwrap();
    if role.starts_with("cancel_") {
        cancel_child_role(&name, &parent, &role);
        return;
    }
    if role == "silent" {
        let wide = name
            .as_str()
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let end = Instant::now() + WAIT;
        let handle = loop {
            let h = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    0x0012019b,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                    std::ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                break h;
            }
            assert!(Instant::now() < end);
            thread::sleep(Duration::from_millis(2));
        };
        thread::sleep(Duration::from_millis(150));
        unsafe {
            CloseHandle(handle);
        }
        return;
    }
    if role == "server_mismatch" {
        let server = TestPipeServer::bind_name(name).unwrap();
        assert_eq!(
            server
                .accept(&parent, &TestPeerPolicy::current().unwrap(), WAIT)
                .unwrap_err()
                .code(),
            "pipe_disconnected"
        );
        return;
    }
    if role == "server_crash" {
        let server = TestPipeServer::bind_name(name).unwrap();
        let _s = server
            .accept(&parent, &TestPeerPolicy::current().unwrap(), WAIT)
            .unwrap();
        std::process::exit(7);
    }
    let qos = if role == "anonymous" {
        ClientTokenQuality::Anonymous
    } else {
        ClientTokenQuality::Impersonation
    };
    let mut client = TestPipeClient::connect(&name, &parent, qos, WAIT).unwrap();
    if role == "anonymous" {
        assert!(client.challenge().is_err());
        return;
    }
    let mut challenge = match client.challenge() {
        Ok(c) => c,
        Err(_) if role == "denied" => return,
        Err(e) => panic!("{e:?}"),
    };
    match role.as_str() {
        "exit" => return,
        "disconnect" => {
            drop(client);
            thread::sleep(Duration::from_millis(120));
            return;
        }
        "expired" => thread::sleep(Duration::from_millis(120)),
        "wrong_purpose" => challenge.purpose = "another-purpose".into(),
        "wrong_version" => challenge.version += 1,
        "wrong_nonce" => challenge.nonce[0] ^= 1,
        "cross_session" => {
            let other = PipeName::parse_local(&std::env::var("R3_SECOND").unwrap()).unwrap();
            let mut c2 = TestPipeClient::connect(&other, &parent, qos, WAIT).unwrap();
            let c2_challenge = c2.challenge().unwrap();
            let _ = client.respond(&c2_challenge);
            let _ = c2.respond(&challenge);
            return;
        }
        "oversize" => {
            let _ = client.send_test_length(MAX_PEER_MESSAGE as u32 + 1);
            let _ = client.wait_for_close();
            return;
        }
        "partial" => {
            client.send_test_length(128).unwrap();
            let _ = client.wait_for_close();
            return;
        }
        "invalid" => {
            let _ = client.send_test_frame(b"{not-json");
            let _ = client.wait_for_close();
            return;
        }
        _ => (),
    }
    let result = client.respond(&challenge);
    if role == "valid" || role == "replay" {
        assert!(result.is_ok());
        if role == "replay" {
            assert!(client.respond(&challenge).is_err());
        }
        let _ = client.wait_for_close();
    } else {
        assert!(result.is_err());
    }
}
#[test]
fn valid_real_two_process_pipe() {
    let r = run("valid", Duration::from_secs(1)).unwrap();
    assert!(
        r.token_user_matched
            && r.process_handle_matched
            && r.creation_time_matched
            && r.challenge_consumed
    );
    assert_eq!(r.integrity_rid, 8192);
    assert!(!r.elevated && !r.production_service_identity);
    println!("R3_RECEIPT=real_two_process_pipe;token_user_matched=true;process_handle_matched=true;creation_time_matched=true;integrity=Medium;elevated=false;challenge_consumed=true;production_service_identity=false");
}
#[test]
fn real_process_handle_and_creation_are_pinned() {
    let p = PinnedProcess::current().unwrap();
    assert_eq!(p.id(), std::process::id());
    assert!(p.creation_time() > 0);
    assert!(p.is_alive().unwrap());
    assert_eq!(
        PinnedProcess::open_test_peer(p.id(), p.creation_time() + 1)
            .unwrap_err()
            .code(),
        "process_identity_mismatch"
    );
}
#[test]
fn wrong_sid_is_rejected() {
    let server = TestPipeServer::bind().unwrap();
    let mut c = child(server.name(), "denied", None);
    let p = PinnedProcess::from_child(&c.0).unwrap();
    let null_sid = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let policy = TestPeerPolicy::from_sid(&null_sid).unwrap();
    assert_eq!(
        server.accept(&p, &policy, WAIT).unwrap_err().code(),
        "peer_identity_denied"
    );
    finish(&mut c);
}
#[test]
fn insufficient_policy_identity_fails_closed() {
    assert_eq!(
        TestPeerPolicy::from_sid(&[]).unwrap_err().code(),
        "invalid_sid_policy"
    );
}
#[test]
fn truncated_and_overlong_sid_policies_are_rejected() {
    for sid in [vec![1], vec![1, 15, 0, 0, 0, 0, 0, 0], vec![1; 80]] {
        assert_eq!(
            TestPeerPolicy::from_sid(&sid).unwrap_err().code(),
            "invalid_sid_policy"
        );
    }
}
#[test]
fn anonymous_token_cannot_authenticate() {
    let error = run("anonymous", Duration::from_secs(1)).unwrap_err();
    println!(
        "R3_TOKEN_FAILURE_RECEIPT=code:{};native:{:?};server_token_restored=true",
        error.code(),
        error.native_code
    );
    assert!(matches!(
        error.code(),
        "token_unavailable" | "impersonation_insufficient" | "impersonation_failed"
    ));
}
#[test]
fn name_squatting_first_instance_is_rejected() {
    let s = TestPipeServer::bind().unwrap();
    assert_eq!(
        TestPipeServer::bind_name(s.name().clone())
            .unwrap_err()
            .code(),
        "pipe_name_unavailable"
    );
}
#[test]
fn nonlocal_pipe_namespace_is_rejected() {
    for s in [
        r"\\remote\pipe\cmg-r3-test-a",
        r"\\localhost\pipe\cmg-r3-test-a",
        r"\\.\pipe\arbitrary",
    ] {
        assert_eq!(
            PipeName::parse_local(s).unwrap_err().code(),
            "invalid_pipe_name"
        );
    }
}
#[test]
fn pipe_has_explicit_current_user_only_dacl() {
    let s = TestPipeServer::bind().unwrap();
    unsafe {
        let mut dacl = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        assert_eq!(
            GetSecurityInfo(
                s.raw_handle_for_test(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd
            ),
            0
        );
        assert!(!dacl.is_null());
        assert_eq!((*dacl).AceCount, 1);
        let mut ace = std::ptr::null_mut();
        assert_ne!(GetAce(dacl, 0, &mut ace), 0);
        let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
        assert_eq!(allowed.Header.AceType, 0);
        assert_eq!(allowed.Mask, 0x0012019b);
        assert_eq!(allowed.Mask & 4, 0);
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            GetSecurityDescriptorControl(sd, &mut control, &mut revision),
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let expected = TestPeerPolicy::current().unwrap();
        assert_ne!(
            EqualSid(
                (&allowed.SidStart as *const u32).cast_mut().cast(),
                expected.sid_bytes().as_ptr().cast_mut().cast()
            ),
            0
        );
        assert!(s.local_only() && s.first_instance_only());
        LocalFree(sd);
    }
}
#[test]
fn impersonation_failure_before_connection_is_closed() {
    let s = TestPipeServer::bind().unwrap();
    let failure = unsafe {
        verify_pipe_token_for_test(s.raw_handle_for_test(), &TestPeerPolicy::current().unwrap())
    }
    .unwrap_err();
    println!(
        "R3_IMPERSONATION_FAILURE_RECEIPT=code:{};native:{:?}",
        failure.code(),
        failure.native_code
    );
    assert_eq!(failure.code(), "impersonation_failed");
    let mut h = std::ptr::null_mut();
    unsafe {
        assert_eq!(
            OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut h),
            0
        );
        assert_eq!(GetLastError(), ERROR_NO_TOKEN);
    }
}
#[test]
fn challenge_consumes_only_once() {
    assert_eq!(
        run("replay", Duration::from_secs(1)).unwrap_err().code(),
        "challenge_consumed"
    );
}
#[test]
fn challenge_expiry_rejects_response() {
    assert_eq!(
        run("expired", Duration::from_millis(30))
            .unwrap_err()
            .code(),
        "challenge_expired"
    );
}
#[test]
fn purpose_is_bound() {
    assert_eq!(
        run("wrong_purpose", Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "challenge_mismatch"
    );
}
#[test]
fn protocol_version_is_bound() {
    assert_eq!(
        run("wrong_version", Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "challenge_mismatch"
    );
}
#[test]
fn nonce_is_bound() {
    assert_eq!(
        run("wrong_nonce", Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "challenge_mismatch"
    );
}
#[test]
fn different_sessions_cannot_swap_challenges() {
    let a = TestPipeServer::bind().unwrap();
    let b = TestPipeServer::bind().unwrap();
    let mut c = child(a.name(), "cross_session", Some(b.name()));
    let p = PinnedProcess::from_child(&c.0).unwrap();
    let policy = TestPeerPolicy::current().unwrap();
    let mut sa = a.accept(&p, &policy, WAIT).unwrap();
    sa.issue_challenge(Duration::from_secs(1)).unwrap();
    let mut sb = b.accept(&p, &policy, WAIT).unwrap();
    sb.issue_challenge(Duration::from_secs(1)).unwrap();
    assert_eq!(
        sa.verify_response().unwrap_err().code(),
        "challenge_mismatch"
    );
    assert_eq!(
        sb.verify_response().unwrap_err().code(),
        "challenge_mismatch"
    );
    finish(&mut c);
}
#[test]
fn disconnected_session_is_invalid() {
    assert_eq!(
        run("disconnect", Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "pipe_disconnected"
    );
}
#[test]
fn exited_client_is_invalid() {
    assert_eq!(
        run("exit", Duration::from_secs(1)).unwrap_err().code(),
        "peer_exited"
    );
}
#[test]
fn oversized_frame_is_rejected_before_allocation() {
    assert_eq!(
        run("oversize", Duration::from_secs(1)).unwrap_err().code(),
        "message_too_large"
    );
}
#[test]
fn invalid_message_is_rejected() {
    assert_eq!(
        run("invalid", Duration::from_secs(1)).unwrap_err().code(),
        "invalid_message"
    );
}
#[test]
fn connection_timeout_is_bounded_and_name_reusable() {
    let s = TestPipeServer::bind().unwrap();
    let name = s.name().clone();
    let p = PinnedProcess::current().unwrap();
    let now = Instant::now();
    assert_eq!(
        s.accept(
            &p,
            &TestPeerPolicy::current().unwrap(),
            Duration::from_millis(40)
        )
        .unwrap_err()
        .code(),
        "timeout"
    );
    assert!(now.elapsed() < Duration::from_secs(1));
    assert!(TestPipeServer::bind_name(name).is_ok());
}
#[test]
fn server_abnormal_exit_fails_closed() {
    let name = PipeName::random().unwrap();
    let mut c = child(&name, "server_crash", None);
    let p = PinnedProcess::from_child(&c.0).unwrap();
    let mut client =
        TestPipeClient::connect(&name, &p, ClientTokenQuality::Impersonation, WAIT).unwrap();
    assert!(client.challenge().is_err());
    let end = Instant::now() + WAIT;
    loop {
        if let Some(status) = c.0.try_wait().unwrap() {
            assert_eq!(status.code(), Some(7));
            break;
        }
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn wrong_server_instance_is_rejected_before_sending_hello() {
    let name = PipeName::random().unwrap();
    let mut c = child(&name, "server_mismatch", None);
    let wrong = PinnedProcess::current().unwrap();
    let result = TestPipeClient::connect(&name, &wrong, ClientTokenQuality::Impersonation, WAIT);
    assert_eq!(
        result.err().expect("wrong server was accepted").code(),
        "process_identity_mismatch"
    );
    finish(&mut c);
}
#[test]
fn peer_policy_rejects_wrong_process_even_same_user() {
    let server = TestPipeServer::bind().unwrap();
    let mut c = child(server.name(), "denied", None);
    let wrong = PinnedProcess::current().unwrap();
    assert_eq!(
        server
            .accept(&wrong, &TestPeerPolicy::current().unwrap(), WAIT)
            .unwrap_err()
            .code(),
        "process_identity_mismatch"
    );
    finish(&mut c);
}
#[test]
fn repeated_connections_release_process_and_pipe_handles() {
    unsafe {
        let mut before = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut before), 0);
        for _ in 0..8 {
            assert!(run("valid", Duration::from_secs(1)).is_ok());
        }
        let mut after = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut after), 0);
        assert!(after <= before + 2, "handle leak: {before} -> {after}");
        println!("R3_HANDLE_RECEIPT=before:{before};after:{after};repetitions:8");
    }
}
#[test]
fn pipe_wait_mode_has_no_pending_io_to_drain_after_timeout() {
    let server = TestPipeServer::bind().unwrap();
    let mut state = 0;
    unsafe {
        assert_ne!(
            GetNamedPipeHandleStateW(
                server.raw_handle_for_test(),
                &mut state,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0
            ),
            0
        );
    }
    assert_ne!(
        state & PIPE_NOWAIT,
        0,
        "bounded polling requires a real nonblocking pipe"
    );
}
#[test]
fn connected_client_without_hello_times_out_and_releases_pipe() {
    let server = TestPipeServer::bind().unwrap();
    let name = server.name().clone();
    let mut c = child(&name, "silent", None);
    let p = PinnedProcess::from_child(&c.0).unwrap();
    let end = Instant::now() + WAIT;
    loop {
        let mut actual = 0;
        if unsafe { GetNamedPipeClientProcessId(server.raw_handle_for_test(), &mut actual) } != 0 {
            assert_eq!(actual, p.id());
            break;
        }
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(2));
    }
    let start = Instant::now();
    assert_eq!(
        server
            .accept(
                &p,
                &TestPeerPolicy::current().unwrap(),
                Duration::from_millis(40)
            )
            .unwrap_err()
            .code(),
        "timeout"
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(TestPipeServer::bind_name(name).is_ok());
    finish(&mut c);
}
#[test]
fn partial_frame_body_times_out_without_pending_io() {
    let start = Instant::now();
    assert_eq!(
        run("partial", Duration::from_millis(60))
            .unwrap_err()
            .code(),
        "challenge_expired"
    );
    assert!(start.elapsed() < Duration::from_secs(1));
}
#[test]
fn rejection_and_timeout_paths_release_handles() {
    unsafe {
        let mut before = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut before), 0);
        for _ in 0..3 {
            for (role, ttl) in [
                ("partial", 60),
                ("expired", 30),
                ("disconnect", 1000),
                ("invalid", 1000),
            ] {
                assert!(run(role, Duration::from_millis(ttl)).is_err());
            }
            let server = TestPipeServer::bind().unwrap();
            let p = PinnedProcess::current().unwrap();
            assert_eq!(
                server
                    .accept(
                        &p,
                        &TestPeerPolicy::current().unwrap(),
                        Duration::from_millis(15)
                    )
                    .unwrap_err()
                    .code(),
                "timeout"
            );
        }
        let mut after = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut after), 0);
        assert!(
            after <= before + 2,
            "rejection/timeout handle leak: {before} -> {after}"
        );
        println!("R3_REJECTION_HANDLE_RECEIPT=before:{before};after:{after};cases:15");
    }
}

#[test]
fn cancel_pre_cancelled_accept_rejects_without_waiting() {
    let server = TestPipeServer::bind().unwrap();
    let name = server.name().clone();
    let expected = PinnedProcess::current().unwrap();
    let cancel = CancelToken::new();
    cancel.cancel();
    let error = server
        .accept_cancellable(
            &expected,
            &TestPeerPolicy::current().unwrap(),
            Duration::from_millis(100),
            &cancel,
        )
        .unwrap_err();
    assert_eq!(error.code(), "peer_cancelled");
    assert!(TestPipeServer::bind_name(name).is_ok());
    assert_server_token_restored();
}

#[test]
fn cancel_accept_wait_observes_same_r2_token_before_deadline() {
    let server = TestPipeServer::bind().unwrap();
    let name = server.name().clone();
    let cancel = CancelToken::new();
    let worker_cancel = cancel.clone();
    let (entered, entry) = std::sync::mpsc::sync_channel(1);
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let expected = PinnedProcess::current().unwrap();
        entered.send(()).unwrap();
        let result = server
            .accept_cancellable(
                &expected,
                &TestPeerPolicy::current().unwrap(),
                Duration::from_millis(1500),
                &worker_cancel,
            )
            .map(|_| ());
        assert_server_token_restored();
        tx.send(result).unwrap();
    });
    entry.recv_timeout(WAIT).unwrap();
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "real accept must still be waiting"
    );
    let start = Instant::now();
    cancel.cancel();
    let result = rx.recv_timeout(WAIT).unwrap();
    worker.join().unwrap();
    assert_eq!(result.unwrap_err().code(), "peer_cancelled");
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(TestPipeServer::bind_name(name).is_ok());
}

#[test]
fn cancel_after_challenge_rejects_late_real_response() {
    let server = TestPipeServer::bind().unwrap();
    let mut child = child(server.name(), "valid", None);
    let expected = PinnedProcess::from_child(&child.0).unwrap();
    let cancel = CancelToken::new();
    let mut session = server
        .accept_cancellable(
            &expected,
            &TestPeerPolicy::current().unwrap(),
            WAIT,
            &cancel,
        )
        .unwrap();
    session.issue_challenge(Duration::from_secs(1)).unwrap();
    cancel.cancel();
    assert_eq!(
        session.verify_response().unwrap_err().code(),
        "peer_cancelled"
    );
    assert!(session.verify_response().is_err());
    assert_server_token_restored();
    // Cancellation closes the pipe; this valid legacy client must observe failure.
    // Drop owns only this synthetic child, even when the RED assertion unwinds.
    let _ = child.0.kill();
    let _ = child.0.wait();
}

// Fixed synthetic roles, with stdin gates and bounded parent-side waits. The
// fixture kills/reaps its own child before joining its sole stdout reader.
struct ControlledPeer {
    child: ChildGuard,
    lines: std::sync::mpsc::Receiver<String>,
    reader: Option<thread::JoinHandle<()>>,
}
impl ControlledPeer {
    fn new(name: &PipeName, role: &str) -> Self {
        use std::io::BufRead;
        let parent = PinnedProcess::current().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "peer_child_entry", "--ignored", "--nocapture"])
            .env_clear()
            .env("SystemRoot", "C:\\Windows")
            .env("R3_ROLE", role)
            .env("R3_PIPE", name.as_str())
            .env("R3_PARENT", parent.id().to_string())
            .env("R3_CREATED", parent.creation_time().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = ChildGuard(command.spawn().unwrap());
        let stdout = child.0.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            child,
            lines,
            reader: Some(reader),
        }
    }
    fn step(&self, marker: &str) {
        let end = Instant::now() + WAIT;
        loop {
            let line = self
                .lines
                .recv_timeout(end.saturating_duration_since(Instant::now()))
                .expect("bounded synthetic child progress");
            if line.contains(marker) {
                return;
            }
        }
    }
    fn go(&mut self) {
        use std::io::Write;
        self.child
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"G")
            .unwrap();
    }
    fn finish(&mut self) {
        finish(&mut self.child);
    }
}
impl Drop for ControlledPeer {
    fn drop(&mut self) {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        self.child.0.stdin.take();
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}
fn child_gate() {
    use std::io::Read;
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b'G']);
}
fn child_step(marker: &str) {
    use std::io::Write;
    println!("R3_CANCEL_{marker}");
    std::io::stdout().flush().unwrap();
}
fn cancel_child_role(name: &PipeName, parent: &PinnedProcess, role: &str) {
    if role.starts_with("cancel_server_") {
        let server = TestPipeServer::bind_name(name.clone()).unwrap();
        child_step("BOUND");
        let mut session = server
            .accept(parent, &TestPeerPolicy::current().unwrap(), WAIT)
            .unwrap();
        if role == "cancel_server_ack" {
            session.issue_challenge(Duration::from_secs(2)).unwrap();
        }
        child_step("ACCEPTED");
        child_gate();
        if role == "cancel_server_ack" {
            assert!(session.verify_response().is_err());
        }
        return;
    }
    if role == "cancel_no_hello" {
        let wide = name
            .as_str()
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0x0012019b,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(raw, INVALID_HANDLE_VALUE);
        child_step("CONNECTED");
        child_gate();
        unsafe {
            CloseHandle(raw);
        }
        return;
    }
    let mut client =
        TestPipeClient::connect(name, parent, ClientTokenQuality::Impersonation, WAIT).unwrap();
    if role == "cancel_expect_closed" {
        assert!(client.challenge().is_err());
        return;
    }
    if role == "cancel_partial" {
        client.send_test_length(128).unwrap();
        child_step("PARTIAL");
        child_gate();
        assert!(client.send_test_frame(b"late").is_err());
        child_step("LATE_REJECTED");
        return;
    }
    let challenge = client.challenge().unwrap();
    child_step("CHALLENGE");
    child_gate();
    let result = client.respond(&challenge);
    if role == "cancel_late" {
        assert!(result.is_err());
        child_step("LATE_REJECTED");
    } else if role == "cancel_valid" {
        result.unwrap();
    } else {
        assert_eq!(role, "cancel_race");
    }
    let _ = client.wait_for_close();
}

#[test]
fn cancel_client_connect_wait_is_bounded() {
    let name = PipeName::random().unwrap();
    let cancel = CancelToken::new();
    let token = cancel.clone();
    let (entered, rx_entered) = std::sync::mpsc::sync_channel(1);
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let expected = PinnedProcess::current().unwrap();
        entered.send(()).unwrap();
        tx.send(
            TestPipeClient::connect_cancellable(
                &name,
                &expected,
                ClientTokenQuality::Impersonation,
                WAIT,
                &token,
            )
            .map(|_| ()),
        )
        .unwrap();
    });
    rx_entered.recv_timeout(WAIT).unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    cancel.cancel();
    let result = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    worker.join().unwrap();
    assert_eq!(result.unwrap_err().code(), "peer_cancelled");
}

#[test]
fn cancel_connected_hello_read_closes_server_pipe() {
    let server = TestPipeServer::bind().unwrap();
    let name = server.name().clone();
    let mut child = ControlledPeer::new(&name, "cancel_no_hello");
    child.step("R3_CANCEL_CONNECTED");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let token = cancel.clone();
        let expected = &expected;
        let worker = scope.spawn(move || {
            let result = server
                .accept_cancellable(expected, &TestPeerPolicy::current().unwrap(), WAIT, &token)
                .map(|_| ());
            assert_server_token_restored();
            tx.send(result).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        cancel.cancel();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .code(),
            "peer_cancelled"
        );
        worker.join().unwrap();
    });
    child.go();
    child.finish();
    assert!(TestPipeServer::bind_name(name).is_ok());
}

#[test]
fn cancel_partial_frame_read_and_late_bytes_are_rejected() {
    let server = TestPipeServer::bind().unwrap();
    let mut child = ControlledPeer::new(server.name(), "cancel_partial");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    let mut session = server
        .accept_cancellable(
            &expected,
            &TestPeerPolicy::current().unwrap(),
            WAIT,
            &cancel,
        )
        .unwrap();
    session.issue_challenge(Duration::from_secs(2)).unwrap();
    child.step("R3_CANCEL_PARTIAL");
    thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let s = &mut session;
        let worker = scope.spawn(move || {
            let result = s.verify_response();
            assert_server_token_restored();
            tx.send(result).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        cancel.cancel();
        cancel.cancel();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .code(),
            "peer_cancelled"
        );
        worker.join().unwrap();
    });
    assert_eq!(
        session.verify_response().unwrap_err().code(),
        "session_closed"
    );
    child.go();
    child.step("R3_CANCEL_LATE_REJECTED");
    child.finish();
}

#[test]
fn cancel_waiting_challenge_response_rejects_late_authentication() {
    let server = TestPipeServer::bind().unwrap();
    let mut child = ControlledPeer::new(server.name(), "cancel_late");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    let mut session = server
        .accept_cancellable(
            &expected,
            &TestPeerPolicy::current().unwrap(),
            WAIT,
            &cancel,
        )
        .unwrap();
    session.issue_challenge(Duration::from_secs(2)).unwrap();
    child.step("R3_CANCEL_CHALLENGE");
    thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let s = &mut session;
        let worker = scope.spawn(move || {
            tx.send(s.verify_response()).unwrap();
            assert_server_token_restored();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        cancel.cancel();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .code(),
            "peer_cancelled"
        );
        worker.join().unwrap();
    });
    assert!(session.issue_challenge(Duration::from_secs(1)).is_err());
    child.go();
    child.step("R3_CANCEL_LATE_REJECTED");
    child.finish();
}

#[test]
fn cancel_client_challenge_read_closes_owned_pipe() {
    let name = PipeName::random().unwrap();
    let mut child = ControlledPeer::new(&name, "cancel_server_idle");
    child.step("R3_CANCEL_BOUND");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    let mut client = TestPipeClient::connect_cancellable(
        &name,
        &expected,
        ClientTokenQuality::Impersonation,
        WAIT,
        &cancel,
    )
    .unwrap();
    child.step("R3_CANCEL_ACCEPTED");
    thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let c = &mut client;
        let worker = scope.spawn(move || {
            tx.send(c.challenge()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        cancel.cancel();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .code(),
            "peer_cancelled"
        );
        worker.join().unwrap();
    });
    assert_eq!(client.challenge().unwrap_err().code(), "session_closed");
    child.go();
    child.finish();
}

#[test]
fn cancel_client_waiting_ack_is_not_authentication_success() {
    let name = PipeName::random().unwrap();
    let mut child = ControlledPeer::new(&name, "cancel_server_ack");
    child.step("R3_CANCEL_BOUND");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    let mut client = TestPipeClient::connect_cancellable(
        &name,
        &expected,
        ClientTokenQuality::Impersonation,
        WAIT,
        &cancel,
    )
    .unwrap();
    child.step("R3_CANCEL_ACCEPTED");
    let challenge = client.challenge().unwrap();
    thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let c = &mut client;
        let worker = scope.spawn(move || {
            tx.send(c.respond(&challenge)).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        cancel.cancel();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .code(),
            "peer_cancelled"
        );
        worker.join().unwrap();
    });
    child.go();
    child.finish();
}

#[test]
fn cancel_full_pipe_write_is_bounded_and_closes_client() {
    let name = PipeName::random().unwrap();
    let mut child = ControlledPeer::new(&name, "cancel_server_idle");
    child.step("R3_CANCEL_BOUND");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    let mut client = TestPipeClient::connect_cancellable(
        &name,
        &expected,
        ClientTokenQuality::Impersonation,
        WAIT,
        &cancel,
    )
    .unwrap();
    child.step("R3_CANCEL_ACCEPTED");
    thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let (written, first_write) = std::sync::mpsc::sync_channel(1);
        let c = &mut client;
        let worker = scope.spawn(move || {
            let result = (|| {
                c.send_test_frame(&[7; 64])?;
                written.send(()).unwrap();
                (0..10_000).try_for_each(|_| c.send_test_frame(&[7; 64]))
            })();
            tx.send(result).unwrap();
        });
        // Prove the worker has performed real writes before cancelling; this is
        // not merely a worker that has yet to be scheduled. The peer deliberately
        // does not drain its finite buffer, so this write sequence cannot finish.
        first_write.recv_timeout(WAIT).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        cancel.cancel();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .code(),
            "peer_cancelled"
        );
        worker.join().unwrap();
    });
    assert_eq!(
        client.send_test_frame(b"late").unwrap_err().code(),
        "session_closed"
    );
    child.go();
    child.finish();
}

#[test]
fn cancel_one_session_does_not_cancel_another() {
    let sa = TestPipeServer::bind().unwrap();
    let sb = TestPipeServer::bind().unwrap();
    let mut a = ControlledPeer::new(sa.name(), "cancel_late");
    let mut b = ControlledPeer::new(sb.name(), "cancel_valid");
    let pa = PinnedProcess::from_child(&a.child.0).unwrap();
    let pb = PinnedProcess::from_child(&b.child.0).unwrap();
    let ca = CancelToken::new();
    let cb = CancelToken::new();
    let policy = TestPeerPolicy::current().unwrap();
    let mut a_session = sa.accept_cancellable(&pa, &policy, WAIT, &ca).unwrap();
    let mut b_session = sb.accept_cancellable(&pb, &policy, WAIT, &cb).unwrap();
    a_session.issue_challenge(Duration::from_secs(2)).unwrap();
    b_session.issue_challenge(Duration::from_secs(2)).unwrap();
    a.step("R3_CANCEL_CHALLENGE");
    b.step("R3_CANCEL_CHALLENGE");
    ca.cancel();
    assert_eq!(
        a_session.verify_response().unwrap_err().code(),
        "peer_cancelled"
    );
    b.go();
    let result = b_session.verify_response().unwrap();
    assert!(
        result.token_user_matched
            && result.process_handle_matched
            && result.creation_time_matched
            && result.challenge_consumed
    );
    assert!(!result.production_service_identity);
    drop(b_session);
    b.finish();
    a.go();
    a.step("R3_CANCEL_LATE_REJECTED");
    a.finish();
    assert_server_token_restored();
}

#[test]
fn cancel_authentication_race_has_no_success_after_observed_cancel() {
    for _ in 0..4 {
        let server = TestPipeServer::bind().unwrap();
        let mut child = ControlledPeer::new(server.name(), "cancel_race");
        let expected = PinnedProcess::from_child(&child.child.0).unwrap();
        let cancel = CancelToken::new();
        let mut session = server
            .accept_cancellable(
                &expected,
                &TestPeerPolicy::current().unwrap(),
                WAIT,
                &cancel,
            )
            .unwrap();
        session.issue_challenge(Duration::from_secs(2)).unwrap();
        child.step("R3_CANCEL_CHALLENGE");
        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        let g = gate.clone();
        let token = cancel.clone();
        let stopper = thread::spawn(move || {
            g.wait();
            token.cancel();
        });
        child.go();
        gate.wait();
        let result = session.verify_response();
        stopper.join().unwrap();
        match result {
            Ok(receipt) => {
                assert!(
                    receipt.challenge_consumed
                        && receipt.token_user_matched
                        && receipt.process_handle_matched
                );
                assert!(!receipt.production_service_identity);
                assert_eq!(
                    session.verify_response().unwrap_err().code(),
                    "peer_cancelled"
                );
            }
            Err(error) => assert_eq!(error.code(), "peer_cancelled"),
        }
        // The barrier allows either linearized history; once cancellation is
        // known to precede the next call it can never yield another receipt.
        assert_eq!(
            session.verify_response().unwrap_err().code(),
            "session_closed"
        );
        drop(session);
        child.finish();
        assert_server_token_restored();
    }
}

#[test]
fn cancel_repeated_requests_and_failures_release_handles() {
    unsafe {
        let mut before = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut before), 0);
        for _ in 0..3 {
            cancel_connected_hello_read_closes_server_pipe();
            cancel_partial_frame_read_and_late_bytes_are_rejected();
            cancel_client_waiting_ack_is_not_authentication_success();
            let token = CancelToken::new();
            let threads = (0..8)
                .map(|_| {
                    let t = token.clone();
                    thread::spawn(move || {
                        t.cancel();
                        t.cancel();
                    })
                })
                .collect::<Vec<_>>();
            for t in threads {
                t.join().unwrap();
            }
            let s = TestPipeServer::bind().unwrap();
            let p = PinnedProcess::current().unwrap();
            assert_eq!(
                s.accept_cancellable(&p, &TestPeerPolicy::current().unwrap(), WAIT, &token)
                    .unwrap_err()
                    .code(),
                "peer_cancelled"
            );
        }
        let mut after = 0;
        assert_ne!(GetProcessHandleCount(GetCurrentProcess(), &mut after), 0);
        assert!(after <= before + 2, "cancel handle leak: {before}->{after}");
        assert_server_token_restored();
    }
}

#[test]
fn cancel_pre_cancelled_client_has_no_connect_side_effect() {
    let token = CancelToken::new();
    token.cancel();
    let expected = PinnedProcess::current().unwrap();
    let name = PipeName::random().unwrap();
    let start = Instant::now();
    let result = TestPipeClient::connect_cancellable(
        &name,
        &expected,
        ClientTokenQuality::Impersonation,
        WAIT,
        &token,
    );
    assert_eq!(result.err().unwrap().code(), "peer_cancelled");
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(TestPipeServer::bind_name(name).is_ok());
}

#[test]
fn cancel_before_issue_challenge_closes_authenticated_session() {
    let server = TestPipeServer::bind().unwrap();
    let mut child = ControlledPeer::new(server.name(), "cancel_expect_closed");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    let mut session = server
        .accept_cancellable(
            &expected,
            &TestPeerPolicy::current().unwrap(),
            WAIT,
            &cancel,
        )
        .unwrap();
    cancel.cancel();
    assert_eq!(
        session
            .issue_challenge(Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "peer_cancelled"
    );
    assert_eq!(
        session.verify_response().unwrap_err().code(),
        "session_closed"
    );
    child.finish();
    assert_server_token_restored();
}

#[test]
fn cancel_after_success_invalidates_session_without_revoking_receipt() {
    let server = TestPipeServer::bind().unwrap();
    let mut child = ControlledPeer::new(server.name(), "cancel_valid");
    let expected = PinnedProcess::from_child(&child.child.0).unwrap();
    let cancel = CancelToken::new();
    let mut session = server
        .accept_cancellable(
            &expected,
            &TestPeerPolicy::current().unwrap(),
            WAIT,
            &cancel,
        )
        .unwrap();
    session.issue_challenge(Duration::from_secs(2)).unwrap();
    child.step("R3_CANCEL_CHALLENGE");
    child.go();
    let receipt = session.verify_response().unwrap();
    cancel.cancel();
    assert!(
        receipt.token_user_matched
            && receipt.process_handle_matched
            && receipt.creation_time_matched
            && receipt.challenge_consumed
    );
    assert!(!receipt.production_service_identity);
    assert_eq!(
        session.verify_response().unwrap_err().code(),
        "peer_cancelled"
    );
    assert_eq!(
        session
            .issue_challenge(Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "session_closed"
    );
    child.finish();
    assert_server_token_restored();
}

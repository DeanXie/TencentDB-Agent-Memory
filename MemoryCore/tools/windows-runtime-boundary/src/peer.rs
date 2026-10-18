//! Nonauthoritative test IPC. Supervisor-supplied pins are not service identities.
//! This module never exposes a Gateway operation or L4 evidence issuance.
//! Cancellable entries share the caller's R2 token. Observed cancellation closes
//! the operation's pipe/session before returning; cancelling an idle session is
//! observed by its next operation (or the owner drops it). No watcher is spawned.
//! A successful receipt linearizes at its final cancellation check. Cancellation
//! after that point does not revoke it, and the next operation must still fail.
//! A client observing ACK is not a server receipt: cancellation can win the
//! server's final check after ACK delivery. Only the returned server receipt
//! establishes completion under this offline protocol's cancellation contract.
use crate::launch::CancelToken;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    mem::{size_of, zeroed},
    os::windows::io::AsRawHandle,
    process::Child,
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Cryptography::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*},
};

pub const MAX_PEER_MESSAGE: usize = 2048;
const PREFIX: &str = r"\\.\pipe\cmg-r3-test-";
const HELLO: &[u8] = b"cmg-r3-peer/1/hello";
const ACK: &[u8] = b"cmg-r3-peer/1/consumed";
const PURPOSE: &str = "cmg-r3-test-peer-authentication";
// FILE_GENERIC_READ | FILE_GENERIC_WRITE, minus FILE_CREATE_PIPE_INSTANCE (4).
const CLIENT_RIGHTS: u32 = 0x0012019b;

#[derive(Debug)]
pub struct PeerError {
    code: &'static str,
    pub native_code: Option<u32>,
}
impl PeerError {
    pub fn code(&self) -> &'static str {
        self.code
    }
    fn new(code: &'static str) -> Self {
        Self {
            code,
            native_code: None,
        }
    }
    fn os(code: &'static str) -> Self {
        Self {
            code,
            native_code: Some(unsafe { GetLastError() }),
        }
    }
    fn io() -> Self {
        let e = unsafe { GetLastError() };
        let code = match e {
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED => "pipe_disconnected",
            _ => "pipe_io_failed",
        };
        Self {
            code,
            native_code: Some(e),
        }
    }
}
type Result<T> = std::result::Result<T, PeerError>;

struct Handle(HANDLE);
impl Handle {
    fn checked(h: HANDLE, code: &'static str) -> Result<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            Err(PeerError::os(code))
        } else {
            Ok(Self(h))
        }
    }
}
impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedWindowsHandle")
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
// Owned, non-inheritable OS handles, not Rust memory references.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
struct LocalAllocation(*mut std::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(PeerError::new("system_random_failed"));
    }
    Ok(bytes)
}
#[derive(Debug, Clone)]
pub struct PipeName(String);
impl PipeName {
    pub fn random() -> Result<Self> {
        Ok(Self(format!(
            "{PREFIX}{}",
            random()?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )))
    }
    pub fn parse_local(name: &str) -> Result<Self> {
        let tail = name
            .strip_prefix(PREFIX)
            .ok_or_else(|| PeerError::new("invalid_pipe_name"))?;
        if tail.len() != 64
            || !tail
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PeerError::new("invalid_pipe_name"));
        }
        Ok(Self(name.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn wide(&self) -> Vec<u16> {
        self.0.encode_utf16().chain(Some(0)).collect()
    }
}

fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 4096 {
        return Err(PeerError::os("token_unavailable"));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(PeerError::os("token_unavailable"));
    }
    Ok(buffer)
}
#[derive(Clone)]
struct TokenSnapshot {
    sid: Vec<u8>,
    integrity: u32,
    elevated: bool,
}
fn copy_sid(sid: PSID) -> Result<Vec<u8>> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(PeerError::new("invalid_sid_policy"));
    }
    let len = unsafe { GetLengthSid(sid) } as usize;
    if !(8..=68).contains(&len) {
        return Err(PeerError::new("invalid_sid_policy"));
    }
    Ok(unsafe { std::slice::from_raw_parts(sid.cast(), len) }.to_vec())
}
fn token_snapshot(token: HANDLE) -> Result<TokenSnapshot> {
    let user = token_info(token, TokenUser)?;
    let sid = copy_sid(unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid })?;
    let label = token_info(token, TokenIntegrityLevel)?;
    let integrity_sid = unsafe {
        (*(label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()))
            .Label
            .Sid
    };
    if unsafe { IsValidSid(integrity_sid) } == 0 {
        return Err(PeerError::new("token_unavailable"));
    }
    let count = unsafe { *GetSidSubAuthorityCount(integrity_sid) };
    if count == 0 {
        return Err(PeerError::new("token_unavailable"));
    }
    let integrity = unsafe { *GetSidSubAuthority(integrity_sid, u32::from(count) - 1) };
    let elevation = token_info(token, TokenElevation)?;
    let elevated =
        unsafe { (*(elevation.as_ptr().cast::<TOKEN_ELEVATION>())).TokenIsElevated != 0 };
    Ok(TokenSnapshot {
        sid,
        integrity,
        elevated,
    })
}
fn process_token(process: HANDLE) -> Result<TokenSnapshot> {
    let mut raw = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(PeerError::os("token_unavailable"));
    }
    let token = Handle::checked(raw, "token_unavailable")?;
    token_snapshot(token.0)
}
fn creation_time(process: HANDLE) -> Result<u64> {
    let (mut c, mut e, mut k, mut u) = unsafe { (zeroed(), zeroed(), zeroed(), zeroed()) };
    if unsafe { GetProcessTimes(process, &mut c, &mut e, &mut k, &mut u) } == 0 {
        return Err(PeerError::os("process_identity_unavailable"));
    }
    Ok((u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
}
fn duplicate(raw: HANDLE) -> Result<Handle> {
    let mut result = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut result,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(PeerError::os("process_identity_unavailable"));
    }
    Handle::checked(result, "process_identity_unavailable")
}
/// Retains the original process handle and creation identity; PID alone is not
/// authorization. Only the synthetic supervisor establishes these test pins.
pub struct PinnedProcess {
    handle: Handle,
    id: u32,
    created: u64,
    token: TokenSnapshot,
}
impl fmt::Debug for PinnedProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedTestProcess(redacted)")
    }
}
impl PinnedProcess {
    /// Only R2's retained original process object can enter this adapter. No
    /// caller-supplied PID/SID or authentication result is accepted.
    pub(crate) fn from_controlled_child(child: &crate::launch::StartedChild) -> Result<Self> {
        Self::from_handle(duplicate(child.process_handle().as_raw_handle())?)
    }
    fn from_handle(handle: Handle) -> Result<Self> {
        let id = unsafe { GetProcessId(handle.0) };
        if id == 0 {
            return Err(PeerError::os("process_identity_unavailable"));
        }
        let created = creation_time(handle.0)?;
        let token = process_token(handle.0)?;
        Ok(Self {
            handle,
            id,
            created,
            token,
        })
    }
    pub fn current() -> Result<Self> {
        Self::from_handle(duplicate(unsafe { GetCurrentProcess() })?)
    }
    pub fn from_child(child: &Child) -> Result<Self> {
        Self::from_handle(duplicate(child.as_raw_handle())?)
    }
    pub fn open_test_peer(id: u32, expected_creation: u64) -> Result<Self> {
        let handle = Handle::checked(
            unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZATION_SYNCHRONIZE,
                    0,
                    id,
                )
            },
            "process_identity_unavailable",
        )?;
        let p = Self::from_handle(handle)?;
        if p.created != expected_creation {
            return Err(PeerError::new("process_identity_mismatch"));
        }
        if !p.is_alive()? {
            return Err(PeerError::new("peer_exited"));
        }
        Ok(p)
    }
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn creation_time(&self) -> u64 {
        self.created
    }
    pub fn is_alive(&self) -> Result<bool> {
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(PeerError::os("process_wait_failed")),
        }
    }
    fn alive(&self) -> Result<()> {
        if self.is_alive()? {
            Ok(())
        } else {
            Err(PeerError::new("peer_exited"))
        }
    }
}

#[derive(Clone)]
pub struct TestPeerPolicy {
    sid: Vec<u8>,
}
impl fmt::Debug for TestPeerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TestOnlySidPolicy(redacted)")
    }
}
impl TestPeerPolicy {
    pub fn current() -> Result<Self> {
        Ok(Self {
            sid: process_token(unsafe { GetCurrentProcess() })?.sid,
        })
    }
    pub fn from_sid(sid: &[u8]) -> Result<Self> {
        // Bound the buffer before Win32 inspects this caller-supplied SID.
        if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 || sid.len() != 8 + 4 * usize::from(sid[1]) {
            return Err(PeerError::new("invalid_sid_policy"));
        }
        Ok(Self {
            sid: copy_sid(sid.as_ptr().cast_mut().cast())?,
        })
    }
    pub fn sid_bytes(&self) -> &[u8] {
        &self.sid
    }
    fn accepts(&self, t: &TokenSnapshot) -> bool {
        t.sid == self.sid && t.integrity == 8192 && !t.elevated
    }
}

struct ImpersonationGuard {
    active: bool,
}
impl ImpersonationGuard {
    fn revert(&mut self) {
        if self.active {
            // Never continue on a server thread with an unreverted client token.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
            self.active = false;
        }
    }
}
impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        self.revert();
    }
}
fn impersonated_token(pipe: HANDLE) -> Result<TokenSnapshot> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(PeerError::os("impersonation_failed"));
    }
    let mut guard = ImpersonationGuard { active: true };
    let result = (|| {
        let mut raw = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
            return Err(PeerError::os("token_unavailable"));
        }
        let token = Handle::checked(raw, "token_unavailable")?;
        let level = token_info(token.0, TokenImpersonationLevel)?;
        if unsafe { *level.as_ptr().cast::<i32>() } < SecurityImpersonation {
            return Err(PeerError::new("impersonation_insufficient"));
        }
        token_snapshot(token.0)
    })();
    // While impersonating, only token inspection and cleanup are performed.
    guard.revert();
    result
}
/// Exercises native failure paths on a test-owned pipe.
/// # Safety
/// The handle must remain valid for this call.
pub unsafe fn verify_pipe_token_for_test(pipe: HANDLE, policy: &TestPeerPolicy) -> Result<()> {
    if policy.accepts(&impersonated_token(pipe)?) {
        Ok(())
    } else {
        Err(PeerError::new("peer_identity_denied"))
    }
}

fn deadline(timeout: Duration) -> Result<Instant> {
    if !(Duration::from_millis(10)..=Duration::from_secs(5)).contains(&timeout) {
        return Err(PeerError::new("invalid_timeout"));
    }
    Ok(Instant::now() + timeout)
}
fn remaining(end: Instant) -> Result<u32> {
    let remaining = end
        .checked_duration_since(Instant::now())
        .ok_or_else(|| PeerError::new("timeout"))?;
    Ok(remaining.as_millis().clamp(1, 5000) as u32)
}
#[derive(Debug)]
struct Pipe {
    handle: Handle,
    cancel: Option<CancelToken>,
}
impl Pipe {
    fn check_cancel(&self) -> Result<()> {
        if self.cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
            return Err(PeerError::new("peer_cancelled"));
        }
        Ok(())
    }
    fn operation(&self, buf: &mut [u8], write: bool, end: Instant) -> Result<usize> {
        loop {
            self.check_cancel()?;
            remaining(end)?;
            let mut transferred = 0;
            // Both pipe endpoints are synchronous PIPE_NOWAIT byte handles.
            // No OVERLAPPED or pending operation outlives this call.
            let ok = unsafe {
                if write {
                    WriteFile(
                        self.handle.0,
                        buf.as_ptr(),
                        buf.len() as u32,
                        &mut transferred,
                        null_mut(),
                    )
                } else {
                    ReadFile(
                        self.handle.0,
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                        &mut transferred,
                        null_mut(),
                    )
                }
            };
            if ok != 0 && transferred > 0 {
                self.check_cancel()?;
                return Ok(transferred as usize);
            }
            if ok == 0 && unsafe { GetLastError() } != ERROR_NO_DATA {
                return Err(PeerError::io());
            }
            // ERROR_NO_DATA or a successful zero-byte operation may describe
            // an empty/full buffer. Poll only until the absolute deadline.
            // Do not call PeekNamedPipe: on synchronous multi-threaded handles
            // it can itself block regardless of PIPE_NOWAIT.
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn all(&self, buf: &mut [u8], write: bool, end: Instant) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            offset += self.operation(&mut buf[offset..], write, end)?;
        }
        Ok(())
    }
    fn frame(&self, bytes: &[u8], end: Instant) -> Result<()> {
        self.check_cancel()?;
        if bytes.is_empty() || bytes.len() > MAX_PEER_MESSAGE {
            return Err(PeerError::new("message_too_large"));
        }
        self.all(&mut (bytes.len() as u32).to_le_bytes(), true, end)?;
        self.all(&mut bytes.to_vec(), true, end)
    }
    fn read(&self, end: Instant) -> Result<Vec<u8>> {
        self.check_cancel()?;
        let mut head = [0; 4];
        self.all(&mut head, false, end)?;
        let n = u32::from_le_bytes(head) as usize;
        if n == 0 || n > MAX_PEER_MESSAGE {
            return Err(PeerError::new("message_too_large"));
        }
        let mut body = vec![0; n];
        self.all(&mut body, false, end)?;
        self.check_cancel()?;
        Ok(body)
    }
}

fn check_process(
    pipe: &Pipe,
    expected: &PinnedProcess,
    policy: &TestPeerPolicy,
    client: bool,
) -> Result<()> {
    pipe.check_cancel()?;
    expected.alive()?;
    let mut id = 0;
    let ok = unsafe {
        if client {
            GetNamedPipeClientProcessId(pipe.handle.0, &mut id)
        } else {
            GetNamedPipeServerProcessId(pipe.handle.0, &mut id)
        }
    };
    if ok == 0 {
        return Err(PeerError::os("process_identity_unavailable"));
    }
    if id != expected.id {
        return Err(PeerError::new("process_identity_mismatch"));
    }
    let observed = PinnedProcess::open_test_peer(id, expected.created)?;
    if observed.token.sid != expected.token.sid || !policy.accepts(&observed.token) {
        return Err(PeerError::new("peer_identity_denied"));
    }
    expected.alive()?;
    pipe.check_cancel()
}

#[derive(Debug)]
pub struct TestPipeServer {
    name: PipeName,
    pipe: Pipe,
}
impl TestPipeServer {
    pub fn bind() -> Result<Self> {
        Self::bind_name(PipeName::random()?)
    }
    pub fn bind_name(name: PipeName) -> Result<Self> {
        let policy = TestPeerPolicy::current()?;
        let mut sid_string = null_mut();
        if unsafe { ConvertSidToStringSidW(policy.sid.as_ptr().cast_mut().cast(), &mut sid_string) }
            == 0
        {
            return Err(PeerError::os("dacl_failed"));
        }
        let sid_alloc = LocalAllocation(sid_string.cast());
        let mut len = 0;
        while len < 184 && unsafe { *sid_string.add(len) } != 0 {
            len += 1;
        }
        if len == 184 {
            return Err(PeerError::new("dacl_failed"));
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, len) })
            .map_err(|_| PeerError::new("dacl_failed"))?;
        let sddl = format!("D:P(A;;0x{CLIENT_RIGHTS:08x};;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut sd = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                null_mut(),
            )
        } == 0
        {
            return Err(PeerError::os("dacl_failed"));
        }
        let sd_alloc = LocalAllocation(sd);
        let attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let h = unsafe {
            CreateNamedPipeW(
                name.wide().as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                MAX_PEER_MESSAGE as u32,
                MAX_PEER_MESSAGE as u32,
                0,
                &attrs,
            )
        };
        let pipe = Pipe {
            handle: Handle::checked(h, "pipe_name_unavailable")?,
            cancel: None,
        };
        drop(sd_alloc);
        drop(sid_alloc);
        Ok(Self { name, pipe })
    }
    pub fn name(&self) -> &PipeName {
        &self.name
    }
    pub fn raw_handle_for_test(&self) -> HANDLE {
        self.pipe.handle.0
    }
    pub fn local_only(&self) -> bool {
        true
    }
    pub fn first_instance_only(&self) -> bool {
        true
    }
    pub fn accept<'a>(
        self,
        expected: &'a PinnedProcess,
        policy: &TestPeerPolicy,
        timeout: Duration,
    ) -> Result<PeerSession<'a>> {
        self.accept_inner(expected, policy, timeout, None)
    }
    /// Test-only authentication with the caller's existing R2 cancellation state.
    /// On observed cancellation this consumes/closes the pipe and returns an error.
    pub fn accept_cancellable<'a>(
        self,
        expected: &'a PinnedProcess,
        policy: &TestPeerPolicy,
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Result<PeerSession<'a>> {
        self.accept_inner(expected, policy, timeout, Some(cancel.clone()))
    }
    fn accept_inner<'a>(
        mut self,
        expected: &'a PinnedProcess,
        policy: &TestPeerPolicy,
        timeout: Duration,
        cancel: Option<CancelToken>,
    ) -> Result<PeerSession<'a>> {
        self.pipe.cancel = cancel;
        let end = deadline(timeout)?;
        loop {
            self.pipe.check_cancel()?;
            expected.alive()?;
            remaining(end)?;
            let ok = unsafe { ConnectNamedPipe(self.pipe.handle.0, null_mut()) };
            if ok == 0 {
                match unsafe { GetLastError() } {
                    ERROR_PIPE_CONNECTED => break,
                    ERROR_PIPE_LISTENING => (),
                    ERROR_NO_DATA => return Err(PeerError::new("pipe_disconnected")),
                    _ => return Err(PeerError::io()),
                }
            }
            // TRUE in NOWAIT mode means listening, not a completed connection.
            thread::sleep(Duration::from_millis(2));
        }
        if self.pipe.read(end)? != HELLO {
            return Err(PeerError::new("invalid_message"));
        }
        let token = impersonated_token(self.pipe.handle.0)?;
        if !policy.accepts(&token) || token.sid != expected.token.sid {
            return Err(PeerError::new("peer_identity_denied"));
        }
        check_process(&self.pipe, expected, policy, true)?;
        self.pipe.check_cancel()?;
        Ok(PeerSession {
            pipe: Some(self.pipe),
            expected,
            policy: policy.clone(),
            end,
            session: random()?,
            challenge: None,
            consumed: false,
            integrity: token.integrity,
            elevated: token.elevated,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub version: u32,
    pub purpose: String,
    pub session: [u8; 32],
    pub nonce: [u8; 32],
}
#[derive(Debug)]
pub struct PeerReceipt {
    pub token_user_matched: bool,
    pub process_handle_matched: bool,
    pub creation_time_matched: bool,
    pub challenge_consumed: bool,
    pub integrity_rid: u32,
    pub elevated: bool,
    pub production_service_identity: bool,
}
#[derive(Debug)]
pub struct PeerSession<'a> {
    pipe: Option<Pipe>,
    expected: &'a PinnedProcess,
    policy: TestPeerPolicy,
    end: Instant,
    session: [u8; 32],
    challenge: Option<(Challenge, Instant)>,
    consumed: bool,
    integrity: u32,
    elevated: bool,
}
impl PeerSession<'_> {
    pub fn issue_challenge(&mut self, ttl: Duration) -> Result<()> {
        let result = (|| {
            self.pipe
                .as_ref()
                .ok_or_else(|| PeerError::new("session_closed"))?
                .check_cancel()?;
            if self.challenge.is_some() {
                return Err(PeerError::new("challenge_already_issued"));
            }
            if !(Duration::from_millis(10)..=Duration::from_secs(2)).contains(&ttl) {
                return Err(PeerError::new("invalid_challenge_ttl"));
            }
            self.expected.alive()?;
            let challenge = Challenge {
                version: 1,
                purpose: PURPOSE.into(),
                session: self.session,
                nonce: random()?,
            };
            let bytes =
                serde_json::to_vec(&challenge).map_err(|_| PeerError::new("invalid_message"))?;
            self.pipe
                .as_ref()
                .ok_or_else(|| PeerError::new("session_closed"))?
                .frame(&bytes, self.end)?;
            self.challenge = Some((challenge, Instant::now() + ttl));
            self.pipe.as_ref().unwrap().check_cancel()?;
            Ok(())
        })();
        if result.is_err() {
            self.pipe = None;
            self.challenge = None;
        }
        result
    }
    pub fn verify_response(&mut self) -> Result<PeerReceipt> {
        let result = (|| {
            self.pipe
                .as_ref()
                .ok_or_else(|| PeerError::new("session_closed"))?
                .check_cancel()?;
            if self.consumed {
                return Err(PeerError::new("challenge_consumed"));
            }
            let (challenge, expires) = self
                .challenge
                .as_ref()
                .ok_or_else(|| PeerError::new("challenge_not_issued"))?;
            let pipe = self
                .pipe
                .as_ref()
                .ok_or_else(|| PeerError::new("session_closed"))?;
            check_process(pipe, self.expected, &self.policy, true)?;
            let bytes = pipe.read(self.end.min(*expires)).map_err(|e| {
                if e.code() == "timeout" && Instant::now() >= *expires {
                    PeerError::new("challenge_expired")
                } else {
                    e
                }
            })?;
            self.expected.alive()?;
            if Instant::now() >= *expires {
                return Err(PeerError::new("challenge_expired"));
            }
            let response: Challenge =
                serde_json::from_slice(&bytes).map_err(|_| PeerError::new("invalid_message"))?;
            if response != *challenge {
                return Err(PeerError::new("challenge_mismatch"));
            }
            let token = impersonated_token(pipe.handle.0)?;
            if !self.policy.accepts(&token) || token.sid != self.expected.token.sid {
                return Err(PeerError::new("peer_identity_denied"));
            }
            check_process(pipe, self.expected, &self.policy, true)?;
            self.consumed = true;
            pipe.frame(ACK, self.end)?;
            // This final load is the receipt's cancellation linearization point.
            // A later cancel cannot retroactively revoke a completed receipt;
            // the next operation still observes it and closes this session.
            pipe.check_cancel()?;
            Ok(PeerReceipt {
                token_user_matched: true,
                process_handle_matched: true,
                creation_time_matched: true,
                challenge_consumed: true,
                integrity_rid: self.integrity,
                elevated: self.elevated,
                production_service_identity: false,
            })
        })();
        if result.is_err() {
            self.pipe = None;
            self.challenge = None;
        }
        result
    }
}

#[derive(Clone, Copy)]
pub enum ClientTokenQuality {
    Anonymous,
    Impersonation,
}
pub struct TestPipeClient<'a> {
    pipe: Option<Pipe>,
    expected: &'a PinnedProcess,
    policy: TestPeerPolicy,
    end: Instant,
}
impl<'a> TestPipeClient<'a> {
    pub fn connect(
        name: &PipeName,
        expected: &'a PinnedProcess,
        quality: ClientTokenQuality,
        timeout: Duration,
    ) -> Result<Self> {
        Self::connect_inner(name, expected, quality, timeout, None)
    }
    /// Uses only the existing token's shared state. Cancellation during connect,
    /// framed I/O or ACK waits fails closed and releases this client's pipe.
    pub fn connect_cancellable(
        name: &PipeName,
        expected: &'a PinnedProcess,
        quality: ClientTokenQuality,
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Result<Self> {
        Self::connect_inner(name, expected, quality, timeout, Some(cancel.clone()))
    }
    fn connect_inner(
        name: &PipeName,
        expected: &'a PinnedProcess,
        quality: ClientTokenQuality,
        timeout: Duration,
        cancel: Option<CancelToken>,
    ) -> Result<Self> {
        let end = deadline(timeout)?;
        if cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
            return Err(PeerError::new("peer_cancelled"));
        }
        let policy = TestPeerPolicy::current()?;
        let flags = SECURITY_SQOS_PRESENT
            | match quality {
                ClientTokenQuality::Anonymous => SECURITY_ANONYMOUS,
                ClientTokenQuality::Impersonation => SECURITY_IMPERSONATION,
            };
        let pipe = loop {
            if cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
                return Err(PeerError::new("peer_cancelled"));
            }
            expected.alive()?;
            remaining(end)?;
            let h = unsafe {
                CreateFileW(
                    name.wide().as_ptr(),
                    CLIENT_RIGHTS,
                    0,
                    null(),
                    OPEN_EXISTING,
                    flags,
                    null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                break Pipe {
                    handle: Handle::checked(h, "pipe_connect_failed")?,
                    cancel,
                };
            }
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND {
                return Err(PeerError {
                    code: "pipe_connect_failed",
                    native_code: Some(error),
                });
            }
            thread::sleep(Duration::from_millis(5));
        };
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        if unsafe { SetNamedPipeHandleState(pipe.handle.0, &mode, null(), null()) } == 0 {
            return Err(PeerError::os("pipe_mode_failed"));
        }
        check_process(&pipe, expected, &policy, false)?;
        pipe.frame(HELLO, end)?;
        Ok(Self {
            pipe: Some(pipe),
            expected,
            policy,
            end,
        })
    }
    fn with_pipe<T>(&mut self, operation: impl FnOnce(&Self, &Pipe) -> Result<T>) -> Result<T> {
        let result = (|| {
            let pipe = self
                .pipe
                .as_ref()
                .ok_or_else(|| PeerError::new("session_closed"))?;
            pipe.check_cancel()?;
            let result = operation(self, pipe)?;
            pipe.check_cancel()?;
            Ok(result)
        })();
        if result.is_err() {
            self.pipe = None;
        }
        result
    }
    pub fn challenge(&mut self) -> Result<Challenge> {
        self.with_pipe(|client, pipe| {
            check_process(pipe, client.expected, &client.policy, false)?;
            let bytes = pipe.read(client.end)?;
            let c: Challenge =
                serde_json::from_slice(&bytes).map_err(|_| PeerError::new("invalid_message"))?;
            if c.version != 1 || c.purpose != PURPOSE {
                return Err(PeerError::new("invalid_message"));
            }
            Ok(c)
        })
    }
    pub fn respond(&mut self, c: &Challenge) -> Result<()> {
        self.with_pipe(|client, pipe| {
            check_process(pipe, client.expected, &client.policy, false)?;
            pipe.frame(
                &serde_json::to_vec(c).map_err(|_| PeerError::new("invalid_message"))?,
                client.end,
            )?;
            if pipe.read(client.end)? != ACK {
                return Err(PeerError::new("invalid_message"));
            }
            check_process(pipe, client.expected, &client.policy, false)
        })
    }
    /// Adversarial synthetic clients only; this endpoint has no service commands.
    pub fn send_test_length(&mut self, len: u32) -> Result<()> {
        self.with_pipe(|client, pipe| pipe.all(&mut len.to_le_bytes(), true, client.end))
    }
    pub fn send_test_frame(&mut self, bytes: &[u8]) -> Result<()> {
        self.with_pipe(|client, pipe| pipe.frame(bytes, client.end))
    }
    pub fn wait_for_close(&mut self) -> Result<()> {
        self.with_pipe(|client, pipe| pipe.read(client.end).map(|_| ()))
    }
}

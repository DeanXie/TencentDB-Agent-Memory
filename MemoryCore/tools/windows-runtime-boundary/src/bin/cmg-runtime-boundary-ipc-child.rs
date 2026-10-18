//! Fixed offline IPC client only. No service, Gateway, command or plugin mode.
fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("IPC_CHILD_REJECTED code=arguments_forbidden");
        std::process::exit(2);
    }
    if let Err(error) = windows_runtime_boundary::service::standalone_ipc_child_entry() {
        eprintln!("IPC_CHILD_REJECTED code={}", error.code());
        std::process::exit(2);
    }
}

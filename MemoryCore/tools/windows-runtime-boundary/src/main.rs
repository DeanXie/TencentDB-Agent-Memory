fn main() {
    if let Err(error) =
        windows_runtime_boundary::service::run_service_host(std::env::args_os().collect())
    {
        eprintln!(
            "R4A_SERVICE_REJECTED code={} native={:?}",
            error.code(),
            error.native_code
        );
        std::process::exit(2);
    }
}

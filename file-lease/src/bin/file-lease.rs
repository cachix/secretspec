fn main() {
    if let Some(code) = file_lease::maybe_run_keeper() {
        std::process::exit(code);
    }
    eprintln!("file-lease is an internal storage helper; use the file_lease Rust library");
    std::process::exit(2);
}

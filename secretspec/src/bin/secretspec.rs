use miette::Result;

fn main() -> Result<()> {
    // Rust's runtime ignores SIGPIPE by default, turning a closed pipe (e.g.
    // `secretspec check | head`) into an EPIPE error instead of a quiet exit.
    // Restore the default disposition so a broken pipe just terminates us,
    // matching standard Unix CLI behavior.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    secretspec::cli::main()
}

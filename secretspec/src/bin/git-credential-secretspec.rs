use miette::Result;

fn main() -> Result<()> {
    // Match the primary CLI's standard Unix pipe behavior.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    secretspec::integration::git::main()
}

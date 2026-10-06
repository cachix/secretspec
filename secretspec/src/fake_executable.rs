//! Installs executable stand-ins for provider CLIs in tests.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Writes `script` to `path` and marks it owner-executable.
///
/// libtest runs this crate's tests as threads of one process, and many of them
/// spawn subprocesses. `fork` copies the descriptor table, so a child forked by
/// another thread while this process held a write descriptor to `path` keeps
/// that descriptor until its own `exec`. Linux refuses to `execve` an inode that
/// any process has open for writing (`ETXTBSY`, "Text file busy"). Writing to a
/// scratch file and renaming it does not help: the rename keeps the inode.
///
/// So the file is written by a short-lived `sh` child instead. Only that child
/// ever opens it for writing, and it has exited before this returns, so no
/// descriptor to the script can leak into any process this one forks.
pub(crate) fn install(path: &Path, script: &str) {
    let mut child = Command::new("/bin/sh")
        .args(["-c", r#"cat > "$1" && chmod 700 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn sh to install fake executable");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())
        .expect("write fake executable script");
    let status = child.wait().expect("wait for fake executable install");
    assert!(status.success(), "installing {} failed", path.display());
}

//! Bounded waits for the macOS volume tools, also tested on Linux.

use std::{
    io,
    os::unix::process::CommandExt,
    process::{Child, Command},
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

pub(super) fn terminate(mut child: Child) {
    // Each tool has its own process group. Kill descendants too, so a shell or
    // system helper cannot keep an inherited setup lock alive after timeout.
    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    let _ = child.kill();
    // Do not turn a timeout into an unbounded wait for an unresponsive child.
    super::platform::reap_when_exited(child);
}

pub(super) fn run(command: &mut Command, timeout: Duration) -> io::Result<()> {
    wait(command.process_group(0).spawn()?, timeout)
}

/// Share one deadline across several commands, without starting more work once
/// the budget is exhausted.
pub(super) fn run_until(command: &mut Command, deadline: Instant) -> io::Result<()> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Cleanup deadline expired"))?;
    run(command, timeout)
}

pub(super) fn wait(mut child: Child, timeout: Duration) -> io::Result<()> {
    match child.wait_timeout(timeout) {
        Ok(Some(status)) if status.success() => Ok(()),
        Ok(Some(status)) => Err(io::Error::other(format!(
            "Volume tool exited with {status}"
        ))),
        Ok(None) => {
            terminate(child);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Volume tool timed out",
            ))
        }
        Err(error) => {
            terminate(child);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::Stdio, time::Instant};

    #[test]
    fn hung_commands_are_terminated_without_waiting_for_their_exit() {
        let start = Instant::now();
        let result = run(
            Command::new("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            Duration::from_millis(25),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn timeout_also_terminates_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("survived");
        let result = run(
            Command::new("sh")
                .args(["-c", "(sleep 0.5; touch \"$1\") & wait", "timeout-test"])
                .arg(&marker)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            Duration::from_millis(25),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        std::thread::sleep(Duration::from_millis(650));
        assert!(
            !marker.exists(),
            "a descendant survived its command timeout"
        );
    }

    #[test]
    fn nonzero_exit_is_reported_as_failure() {
        assert!(run(&mut Command::new("false"), Duration::from_secs(2)).is_err());
    }

    #[test]
    fn commands_share_a_deadline_and_expired_budgets_do_not_spawn() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("should-not-run");
        let deadline = Instant::now() + Duration::from_millis(200);
        run_until(Command::new("sleep").arg("0.05"), deadline).unwrap();
        let error = run_until(Command::new("sleep").arg("60"), deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(Instant::now() < deadline + Duration::from_secs(2));
        let error = run_until(Command::new("touch").arg(&marker), deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!marker.exists());
    }
}

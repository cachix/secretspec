//! Guard the Console backend, which returns unknown keys without blocking
//! when its output stream (stderr) is not a terminal.

use std::fmt::Display;
use std::io::{self, IsTerminal};

use inquire::error::InquireResult;

fn ensure_terminal() -> InquireResult<()> {
    if io::stderr().is_terminal() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "interactive prompt requires stderr to be a terminal; run without redirecting stderr",
        )
        .into())
    }
}

/// Use this instead of Inquire's unchecked `prompt()` at every prompt site.
pub(crate) trait CheckedPrompt {
    type Output;

    fn prompt_checked(self) -> InquireResult<Self::Output>;
}

impl CheckedPrompt for inquire::Text<'_, '_> {
    type Output = String;

    fn prompt_checked(self) -> InquireResult<Self::Output> {
        ensure_terminal()?;
        self.prompt()
    }
}

impl CheckedPrompt for inquire::Password<'_> {
    type Output = String;

    fn prompt_checked(self) -> InquireResult<Self::Output> {
        ensure_terminal()?;
        self.prompt()
    }
}

impl CheckedPrompt for inquire::Confirm<'_> {
    type Output = bool;

    fn prompt_checked(self) -> InquireResult<Self::Output> {
        ensure_terminal()?;
        self.prompt()
    }
}

impl<T: Display> CheckedPrompt for inquire::Select<'_, T> {
    type Output = T;

    fn prompt_checked(self) -> InquireResult<Self::Output> {
        ensure_terminal()?;
        self.prompt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    // Run real prompts in a child so a regression cannot hang the test runner.
    #[test]
    #[ignore = "subprocess helper"]
    fn prompt_child() {
        let kind = std::env::var("SECRETSPEC_TEST_PROMPT_KIND").unwrap();
        let result = match kind.as_str() {
            "text" => inquire::Text::new("Value?").prompt_checked().map(|_| ()),
            "password" => inquire::Password::new("Value?")
                .without_confirmation()
                .prompt_checked()
                .map(|_| ()),
            "confirm" => inquire::Confirm::new("Continue?")
                .with_default(true)
                .prompt_checked()
                .map(|_| ()),
            "select" => inquire::Select::new("Value?", vec!["value"])
                .prompt_checked()
                .map(|_| ()),
            _ => panic!("unknown prompt type"),
        };
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("requires stderr to be a terminal"),
            "{message}"
        );
    }

    fn check_redirected_stderr(stdin: impl Fn() -> Stdio) {
        for kind in ["text", "password", "confirm", "select"] {
            for stderr_file in [false, true] {
                let file = tempfile::tempfile().unwrap();
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "prompt::tests::prompt_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("SECRETSPEC_TEST_PROMPT_KIND", kind)
                    .stdin(stdin())
                    .stdout(Stdio::piped())
                    .stderr(if stderr_file {
                        Stdio::from(file.try_clone().unwrap())
                    } else {
                        Stdio::piped()
                    })
                    .spawn()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if child.try_wait().unwrap().is_some() {
                        break;
                    }
                    if Instant::now() >= deadline {
                        child.kill().unwrap();
                        child.wait().unwrap();
                        panic!("{kind} prompt hung with redirected stderr");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let output = child.wait_with_output().unwrap();
                assert!(output.status.success(), "{kind}: {output:?}");
            }
        }
    }

    #[test]
    fn redirected_stderr_without_terminal_input_returns_error() {
        check_redirected_stderr(Stdio::null);
    }

    #[cfg(unix)]
    #[test]
    fn redirected_stderr_with_terminal_input_returns_error() {
        use std::os::fd::FromRawFd;

        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty writes two descriptors to valid pointers; null
        // optional arguments request the default terminal configuration.
        let result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
        // SAFETY: a successful openpty returned owned, distinct descriptors.
        let (_master, slave) = unsafe {
            (
                std::fs::File::from_raw_fd(master),
                std::fs::File::from_raw_fd(slave),
            )
        };
        assert!(slave.is_terminal());
        check_redirected_stderr(|| slave.try_clone().unwrap().into());
    }
}

//! Trusted local prompts, decoupled from the calling process's stdio.
//!
//! When an orchestrator (a CI job, a coding agent) invokes secretspec, it
//! controls the child's stdin/stdout — so a value read from stdin, or an
//! approval answered on stdin, is visible to (and forgeable by) that
//! orchestrator. These helpers instead route through trusted prompts that the
//! orchestrator does not sit between:
//!
//! 1. `pinentry` (GnuPG's prompt helper): a dialog that runs in its own process.
//!    A **GUI** pinentry (pinentry-gnome, pinentry-mac) reads from a display the
//!    caller does not sit between — the strong path. A **curses/tty** pinentry,
//!    by contrast, reads the *controlling terminal*, so it is only as strong as
//!    that terminal is trusted (see below).
//! 2. A `/dev/tty` fallback (via `rpassword` for values) when no pinentry
//!    binary is installed: reads from the controlling terminal rather than
//!    stdin. An orchestrator that owns the pty can observe or drive it, which is
//!    why, for *approval*, a detected agent is refused any terminal-bound
//!    channel (fallback or curses pinentry) and required to use a GUI prompt.
//!
//! The value is still handled in-process by secretspec before it reaches the
//! provider, so the guarantee is "the calling agent never sees it", not "only
//! the vault ever sees it".

use crate::{Result, SecretSpecError};
use secrecy::SecretString;

/// Maps a pinentry failure. Cancelling the dialog becomes `on_cancel`, whose
/// meaning depends on the prompt: a cancelled value entry is a user abort
/// ([`SecretSpecError::PromptCancelled`]) — *not* an approval denial, since no
/// approval was involved — while a cancelled approval dialog is a denial
/// ([`SecretSpecError::ApprovalDenied`]). Anything else is a prompt failure.
fn prompt_err(e: pinentry::Error, on_cancel: SecretSpecError) -> SecretSpecError {
    match e {
        pinentry::Error::Cancelled => on_cancel,
        other => SecretSpecError::PromptFailed(other.to_string()),
    }
}

/// Collects a secret value from a trusted local prompt.
///
/// `description` is the context line explaining what is being set; the input
/// label itself is always "Value:".
pub(crate) fn trusted_secret(description: &str) -> Result<SecretString> {
    #[cfg(test)]
    if let Some(canned) = test_hooks::take_secret_override() {
        return canned;
    }
    if let Some(mut input) = pinentry::PassphraseInput::with_default_binary() {
        input.with_description(description).with_prompt("Value:");
        return input
            .interact()
            .map_err(|e| prompt_err(e, SecretSpecError::PromptCancelled));
    }
    tty_secret(description)
}

/// Asks the user to approve or deny an action at a trusted local prompt.
///
/// Returns `Ok(())` on approval and [`SecretSpecError::ApprovalDenied`] on
/// denial (or [`SecretSpecError::PromptFailed`] when no trusted channel is
/// available).
///
/// `is_agent` is whether the *caller* is a detected agent. When it is, any
/// terminal-bound channel is untrusted: an agent that owns the controlling
/// terminal can forge the answer, and that includes both the `/dev/tty` fallback
/// and a *curses* pinentry (which reads the same terminal). So for an agent we
/// require an out-of-band GUI channel and refuse if none is evident, rather than
/// trusting a prompt the agent could drive.
pub(crate) fn trusted_approve(body: &str, is_agent: bool) -> Result<()> {
    #[cfg(test)]
    if let Some(approved) = test_hooks::approve_override() {
        return if approved {
            Ok(())
        } else {
            Err(SecretSpecError::ApprovalDenied)
        };
    }
    // For a detected agent, only an out-of-band GUI prompt is trustworthy. Refuse
    // before even trying pinentry, because with no display pinentry falls back to
    // curses on the controlling terminal — which the agent may own.
    if is_agent && !gui_channel_available() {
        return Err(SecretSpecError::PromptFailed(
            "approval requires a GUI pinentry when running as an agent (no display detected); \
             install a GUI pinentry or approve from a human session"
                .to_string(),
        ));
    }
    if let Some(mut dialog) = pinentry::ConfirmationDialog::with_default_binary() {
        dialog
            .with_title("secretspec: approve secret access")
            .with_ok("Approve")
            .with_cancel("Deny");
        return match dialog.confirm(body) {
            Ok(true) => Ok(()),
            Ok(false) => Err(SecretSpecError::ApprovalDenied),
            Err(e) => Err(prompt_err(e, SecretSpecError::ApprovalDenied)),
        };
    }
    tty_approve(body, is_agent)
}

/// Whether an out-of-band GUI prompt channel is plausibly available — one a
/// process that merely owns our controlling terminal cannot drive. Heuristic: a
/// display server on Linux/BSD, or macOS (where pinentry-mac is a GUI app). It
/// can be fooled by a spoofed `DISPLAY`, but it raises the bar from "trivially
/// forgeable terminal" to "must impersonate a display server".
fn gui_channel_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

/// `/dev/tty` fallback for [`trusted_secret`]: reads from the controlling
/// terminal (never stdin) with echo disabled.
fn tty_secret(description: &str) -> Result<SecretString> {
    let value = rpassword::prompt_password(format!("{description}\nValue: "))
        .map_err(|e| SecretSpecError::PromptFailed(e.to_string()))?;
    Ok(SecretString::new(value.into()))
}

/// `/dev/tty` fallback for [`trusted_approve`]: prints the prompt to, and reads
/// the answer from, the controlling terminal. Any answer other than an explicit
/// yes (including EOF or an empty line) is treated as a denial.
#[cfg(unix)]
fn tty_approve(body: &str, is_agent: bool) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};

    // A detected agent may own this very terminal, so /dev/tty is not a channel
    // it cannot forge — refuse rather than trust it (the GUI-required check in
    // `trusted_approve` normally catches this earlier, but guard here too).
    if is_agent {
        return Err(SecretSpecError::PromptFailed(
            "no trusted approval channel available for an agent; install a GUI pinentry"
                .to_string(),
        ));
    }

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| SecretSpecError::PromptFailed(format!("cannot open /dev/tty: {e}")))?;
    write!(tty, "{body} [y/N]: ")
        .and_then(|()| tty.flush())
        .map_err(|e| SecretSpecError::PromptFailed(e.to_string()))?;

    let mut line = String::new();
    BufReader::new(&tty)
        .read_line(&mut line)
        .map_err(|e| SecretSpecError::PromptFailed(e.to_string()))?;

    if is_affirmative(&line) {
        Ok(())
    } else {
        Err(SecretSpecError::ApprovalDenied)
    }
}

/// On non-unix platforms without pinentry we have no non-stdin channel, so we
/// refuse rather than trust an orchestrator-controlled stdin.
#[cfg(not(unix))]
fn tty_approve(_body: &str, _is_agent: bool) -> Result<()> {
    Err(SecretSpecError::PromptFailed(
        "no trusted approval channel available; install pinentry".to_string(),
    ))
}

/// Whether a typed line is an explicit yes. Defaults to no on anything else, so
/// an empty answer or EOF denies.
fn is_affirmative(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Test-only seam: lets tests drive the interactive prompts deterministically —
/// a canned value for [`trusted_secret`], a fixed approve/deny verdict for
/// [`trusted_approve`] — without spawning pinentry or touching a terminal, which
/// would hang the suite. Thread-local so parallel tests never interfere.
#[cfg(test)]
pub(crate) mod test_hooks {
    use super::{Result, SecretSpecError, SecretString};
    use std::cell::RefCell;

    thread_local! {
        static SECRET_OVERRIDE: RefCell<Option<Result<SecretString>>> = const { RefCell::new(None) };
        static APPROVE_OVERRIDE: RefCell<Option<bool>> = const { RefCell::new(None) };
    }

    /// Queue a value returned by the next [`super::trusted_secret`] call (consumed once).
    pub(crate) fn set_secret_override(value: SecretString) {
        SECRET_OVERRIDE.with(|c| *c.borrow_mut() = Some(Ok(value)));
    }

    /// Queue an error returned by the next [`super::trusted_secret`] call, so tests
    /// can exercise the prompt-failure path (e.g. a cancelled value entry).
    pub(crate) fn set_secret_override_err(err: SecretSpecError) {
        SECRET_OVERRIDE.with(|c| *c.borrow_mut() = Some(Err(err)));
    }

    pub(crate) fn take_secret_override() -> Option<Result<SecretString>> {
        SECRET_OVERRIDE.with(|c| c.borrow_mut().take())
    }

    /// Force [`super::trusted_approve`] to approve (`Some(true)`), deny
    /// (`Some(false)`), or fall through to the real prompt (`None`).
    pub(crate) fn set_approve_override(verdict: Option<bool>) {
        APPROVE_OVERRIDE.with(|c| *c.borrow_mut() = verdict);
    }

    pub(crate) fn approve_override() -> Option<bool> {
        APPROVE_OVERRIDE.with(|c| *c.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affirmative_only_on_explicit_yes() {
        for yes in ["y", "Y", "yes", "YES", " yes ", "Yes\n"] {
            assert!(is_affirmative(yes), "{yes:?} should be affirmative");
        }
        for no in ["", "  ", "n", "no", "\n", "nope", "1", "true", "sure"] {
            assert!(!is_affirmative(no), "{no:?} should not be affirmative");
        }
    }

    #[test]
    fn cancel_maps_to_the_prompts_meaning_and_other_errors_fail() {
        // Cancelling a value entry must not surface as "approval denied" — no
        // approval was involved — while cancelling an approval dialog is one.
        assert!(matches!(
            prompt_err(pinentry::Error::Cancelled, SecretSpecError::PromptCancelled),
            SecretSpecError::PromptCancelled
        ));
        assert!(matches!(
            prompt_err(pinentry::Error::Cancelled, SecretSpecError::ApprovalDenied),
            SecretSpecError::ApprovalDenied
        ));
        assert!(matches!(
            prompt_err(pinentry::Error::Timeout, SecretSpecError::PromptCancelled),
            SecretSpecError::PromptFailed(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn tty_approve_refuses_agent_without_touching_tty() {
        // A detected agent may own the controlling terminal, so the /dev/tty
        // fallback must refuse *before* opening it rather than trust an answer the
        // agent could forge. (Returns immediately, so it never blocks on a tty.)
        assert!(matches!(
            tty_approve("release TOKEN", true),
            Err(SecretSpecError::PromptFailed(_))
        ));
    }
}

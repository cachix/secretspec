//! GUI prompts, decoupled from the calling process's stdio.
//!
//! When an orchestrator (a CI job, a coding agent) invokes secretspec, it
//! controls the child's stdin/stdout — so a value read from stdin, or an
//! approval answered on stdin, is visible to (and forgeable by) that
//! orchestrator. These helpers instead prompt in a GUI window the orchestrator
//! does not sit between:
//!
//! 1. A **GUI dialog** that reads from the display, a channel the caller does
//!    not sit between. With the `gui-prompt` feature (enabled by `cli`) this is
//!    the built-in `egui-pinentry` dialog, which needs no external program and,
//!    on X11, grabs the keyboard. Without that feature it is a GnuPG `pinentry`
//!    binary, when one is installed.
//! 2. A `/dev/tty` fallback (via `rpassword` for values) when no display is
//!    available: reads from the controlling terminal rather than stdin. An
//!    orchestrator that owns the pty can observe or drive it, which is why, for
//!    *approval*, a detected agent is refused any terminal-bound channel and
//!    required to use the GUI prompt.
//!
//! Value entry is not opt-in: [`gui_prompt_available`] detects whether this
//! machine can show a GUI prompt at all, and `set`/`check` prefer it over their
//! own stdin whenever it can.
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
#[cfg(not(feature = "gui-prompt"))]
fn prompt_err(e: pinentry::Error, on_cancel: SecretSpecError) -> SecretSpecError {
    match e {
        pinentry::Error::Cancelled => on_cancel,
        other => SecretSpecError::PromptFailed(other.to_string()),
    }
}

/// Collects a secret value from the GUI prompt (with a `/dev/tty` fallback).
///
/// `description` is the context line explaining what is being set; the input
/// label itself is always "Value:".
pub(crate) fn gui_prompt_secret(description: &str) -> Result<SecretString> {
    #[cfg(test)]
    if let Some(canned) = test_hooks::take_secret_override() {
        return canned;
    }
    match try_gui_secret(description)? {
        Some(value) => Ok(value),
        None => tty_secret(description),
    }
}

/// Attempts the GUI dialog for a value: `Ok(Some(v))` on entry, `Ok(None)` when
/// no display is available (the caller then falls back to `/dev/tty`), and `Err`
/// on cancel or failure.
///
/// With the `gui-prompt` feature this is the built-in [`egui_pinentry`] dialog,
/// which needs no external program.
#[cfg(feature = "gui-prompt")]
fn try_gui_secret(description: &str) -> Result<Option<SecretString>> {
    use egui_pinentry::{Error, PassphraseInput};
    let mut input = PassphraseInput::new();
    input
        .with_title("secretspec")
        .with_description(description)
        .with_prompt("Value:");
    match input.interact() {
        Ok(value) => Ok(Some(value)),
        Err(Error::NoDisplay(_)) => Ok(None),
        Err(Error::Cancelled) => Err(SecretSpecError::PromptCancelled),
        Err(Error::Failed(msg)) => Err(SecretSpecError::PromptFailed(msg)),
    }
}

/// Without the `gui-prompt` feature, use a GnuPG `pinentry` binary when one is
/// installed, else `Ok(None)` to fall through to `/dev/tty`.
#[cfg(not(feature = "gui-prompt"))]
fn try_gui_secret(description: &str) -> Result<Option<SecretString>> {
    let Some(mut input) = pinentry::PassphraseInput::with_default_binary() else {
        return Ok(None);
    };
    input.with_description(description).with_prompt("Value:");
    input
        .interact()
        .map(Some)
        .map_err(|e| prompt_err(e, SecretSpecError::PromptCancelled))
}

/// Asks the user to approve or deny an action at the GUI prompt.
///
/// Returns `Ok(())` on approval and [`SecretSpecError::ApprovalDenied`] on
/// denial (or [`SecretSpecError::PromptFailed`] when no prompt channel is
/// available).
///
/// `is_agent` is whether the *caller* is a detected agent. When it is, any
/// terminal-bound channel is untrusted: an agent that owns the controlling
/// terminal can forge the answer, and that includes both the `/dev/tty` fallback
/// and a *curses* pinentry (which reads the same terminal). So for an agent we
/// require the out-of-band GUI prompt and refuse if none is evident, rather than
/// trusting a prompt the agent could drive.
pub(crate) fn gui_prompt_approve(body: &str, is_agent: bool) -> Result<()> {
    #[cfg(test)]
    if let Some(approved) = test_hooks::approve_override() {
        return if approved {
            Ok(())
        } else {
            Err(SecretSpecError::ApprovalDenied)
        };
    }
    // For a detected agent, only the out-of-band GUI prompt is trustworthy. Refuse
    // before even trying, because with no display the prompt falls back to the
    // controlling terminal, which the agent may own.
    if is_agent && !display_available() {
        return Err(SecretSpecError::PromptFailed(
            "approval requires a GUI prompt when running as an agent (no display detected); \
             run from a human session or provide a display"
                .to_string(),
        ));
    }
    match try_gui_approve(body)? {
        Some(true) => Ok(()),
        Some(false) => Err(SecretSpecError::ApprovalDenied),
        None => tty_approve(body, is_agent),
    }
}

/// Attempts the GUI approval dialog: `Ok(Some(bool))` for an explicit
/// approve/deny, `Ok(None)` when no display is available (fall back to
/// `/dev/tty`), and `Err` on failure. A cancelled dialog counts as a denial.
#[cfg(feature = "gui-prompt")]
fn try_gui_approve(body: &str) -> Result<Option<bool>> {
    use egui_pinentry::{ConfirmationDialog, Error};
    let mut dialog = ConfirmationDialog::new();
    dialog
        .with_title("secretspec: approve secret access")
        .with_ok("Approve")
        .with_cancel("Deny");
    match dialog.confirm(body) {
        Ok(approved) => Ok(Some(approved)),
        Err(Error::NoDisplay(_)) => Ok(None),
        Err(Error::Cancelled) => Ok(Some(false)),
        Err(Error::Failed(msg)) => Err(SecretSpecError::PromptFailed(msg)),
    }
}

/// Without the `gui-prompt` feature, use a GnuPG `pinentry` binary when one is
/// installed, else `Ok(None)` to fall through to `/dev/tty`.
#[cfg(not(feature = "gui-prompt"))]
fn try_gui_approve(body: &str) -> Result<Option<bool>> {
    let Some(mut dialog) = pinentry::ConfirmationDialog::with_default_binary() else {
        return Ok(None);
    };
    dialog
        .with_title("secretspec: approve secret access")
        .with_ok("Approve")
        .with_cancel("Deny");
    match dialog.confirm(body) {
        Ok(approved) => Ok(Some(approved)),
        Err(pinentry::Error::Cancelled) => Ok(Some(false)),
        Err(other) => Err(SecretSpecError::PromptFailed(other.to_string())),
    }
}

/// Whether a display server the GUI prompt can open a window on is plausibly
/// present — one a process that merely owns our controlling terminal cannot
/// drive. Heuristic: a display server on Linux/BSD, or a platform whose window
/// server is always present. It can be fooled by a spoofed `DISPLAY`, but it
/// raises the bar from "trivially forgeable terminal" to "must impersonate a
/// display server".
fn display_available() -> bool {
    // macOS always has a window server, and pinentry-mac is a GUI app either way.
    if cfg!(target_os = "macos") {
        return true;
    }
    // Windows has one too, but only the built-in dialog opens its own window
    // there; a GnuPG `pinentry` binary on Windows is a console program, which an
    // orchestrator owning that console could drive.
    if cfg!(all(windows, feature = "gui-prompt")) {
        return true;
    }
    std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

/// Whether a GUI prompt can be shown on this machine, i.e. whether a value typed
/// at one would stay off the calling process's stdin. `set` and the `check` fill
/// loop consult this to route value entry automatically: when a GUI prompt is
/// available they prompt on it, otherwise they fall back to their own stdin (a
/// terminal prompt, or a piped value).
///
/// This needs both a display ([`display_available`]) and a backend able to draw
/// on it: the built-in dialog is always there, an external `pinentry` binary has
/// to be installed.
pub(crate) fn gui_prompt_available() -> bool {
    // Never probe the real environment under test. A developer's `DISPLAY` would
    // otherwise route `set`/`check` into a real dialog and hang the suite; tests
    // opt in explicitly via `test_hooks::set_channel_override`.
    #[cfg(test)]
    {
        test_hooks::channel_override().unwrap_or(false)
    }
    #[cfg(not(test))]
    {
        display_available() && gui_backend_present()
    }
}

/// The built-in dialog is compiled in, so there is nothing to look for on `PATH`.
#[cfg(all(not(test), feature = "gui-prompt"))]
fn gui_backend_present() -> bool {
    true
}

/// Without the built-in dialog we need a GnuPG `pinentry` binary to draw with.
#[cfg(all(not(test), not(feature = "gui-prompt")))]
fn gui_backend_present() -> bool {
    pinentry::PassphraseInput::with_default_binary().is_some()
}

/// `/dev/tty` fallback for [`gui_prompt_secret`]: reads from the controlling
/// terminal (never stdin) with echo disabled.
///
/// Reached when [`gui_prompt_available`] saw a display but the dialog could not
/// open on it (a stale `DISPLAY`, a sandboxed session). With no terminal either
/// we fail rather than fall back to stdin, since stdin is the one channel the
/// caller controls, so the error names the way out.
fn tty_secret(description: &str) -> Result<SecretString> {
    let value = rpassword::prompt_password(format!("{description}\nValue: ")).map_err(|e| {
        SecretSpecError::PromptFailed(format!(
            "cannot prompt on the terminal ({e}); with no GUI prompt and no terminal, \
             pass the value inline instead"
        ))
    })?;
    Ok(SecretString::new(value.into()))
}

/// `/dev/tty` fallback for [`gui_prompt_approve`]: prints the prompt to, and
/// reads the answer from, the controlling terminal. Any answer other than an
/// explicit yes (including EOF or an empty line) is treated as a denial.
#[cfg(unix)]
fn tty_approve(body: &str, is_agent: bool) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};

    // A detected agent may own this very terminal, so /dev/tty is not a channel
    // it cannot forge — refuse rather than trust it (the GUI-required check in
    // `gui_prompt_approve` normally catches this earlier, but guard here too).
    if is_agent {
        return Err(SecretSpecError::PromptFailed(
            "no GUI approval prompt available for an agent; install a GUI pinentry".to_string(),
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
        "no GUI approval prompt available; install pinentry".to_string(),
    ))
}

/// Whether a typed line is an explicit yes. Defaults to no on anything else, so
/// an empty answer or EOF denies.
fn is_affirmative(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Test-only seam: lets tests drive the interactive prompts deterministically —
/// a canned value for [`gui_prompt_secret`], a fixed approve/deny verdict for
/// [`gui_prompt_approve`], a fixed answer for [`gui_prompt_available`] — without
/// spawning pinentry or touching a terminal, which would hang the suite.
/// Thread-local so parallel tests never interfere.
#[cfg(test)]
pub(crate) mod test_hooks {
    use super::{Result, SecretSpecError, SecretString};
    use std::cell::RefCell;

    thread_local! {
        static SECRET_OVERRIDE: RefCell<Option<Result<SecretString>>> = const { RefCell::new(None) };
        static APPROVE_OVERRIDE: RefCell<Option<bool>> = const { RefCell::new(None) };
        static CHANNEL_OVERRIDE: RefCell<Option<bool>> = const { RefCell::new(None) };
    }

    /// Declare whether a GUI prompt is available, so a test can exercise the
    /// routing in `set`/`check` without a display. Unset (`None`) reads as "no
    /// GUI prompt", which keeps every other test on the stdin path.
    pub(crate) fn set_channel_override(available: Option<bool>) {
        CHANNEL_OVERRIDE.with(|c| *c.borrow_mut() = available);
    }

    pub(crate) fn channel_override() -> Option<bool> {
        CHANNEL_OVERRIDE.with(|c| *c.borrow())
    }

    /// Queue a value returned by the next [`super::gui_prompt_secret`] call (consumed once).
    pub(crate) fn set_secret_override(value: SecretString) {
        SECRET_OVERRIDE.with(|c| *c.borrow_mut() = Some(Ok(value)));
    }

    /// Queue an error returned by the next [`super::gui_prompt_secret`] call, so tests
    /// can exercise the prompt-failure path (e.g. a cancelled value entry).
    pub(crate) fn set_secret_override_err(err: SecretSpecError) {
        SECRET_OVERRIDE.with(|c| *c.borrow_mut() = Some(Err(err)));
    }

    pub(crate) fn take_secret_override() -> Option<Result<SecretString>> {
        SECRET_OVERRIDE.with(|c| c.borrow_mut().take())
    }

    /// Force [`super::gui_prompt_approve`] to approve (`Some(true)`), deny
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

    // Exercises the pinentry-binary fallback's error mapping, which only exists
    // when the built-in GUI prompt is not compiled in.
    #[cfg(not(feature = "gui-prompt"))]
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

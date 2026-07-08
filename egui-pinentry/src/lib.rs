//! A trusted local passphrase and confirmation dialog.
//!
//! This crate shows a small modal dialog to collect a passphrase, or to ask a
//! yes/no approval question, on a channel a calling process cannot sit between.
//! It is a self-contained alternative to shelling out to a `pinentry` binary:
//! the dialog is drawn with [`egui`] rasterized on the CPU (no GPU, and no
//! OpenGL/Vulkan in the dependency tree) and presented with `softbuffer`.
//!
//! On X11 the dialog grabs the keyboard ([`XGrabKeyboard`]) for the duration of
//! the prompt so other X clients on the same display cannot snoop keystrokes.
//! On Wayland, macOS, and Windows the compositor already isolates input between
//! clients, so there is no separate grab to perform.
//!
//! The API mirrors the [`pinentry`](https://docs.rs/pinentry) crate so it can be
//! swapped in with minimal changes:
//!
//! ```no_run
//! # fn main() -> egui_pinentry::Result<()> {
//! use egui_pinentry::PassphraseInput;
//!
//! let mut input = PassphraseInput::new();
//! input
//!     .with_description("Set DATABASE_URL (profile: production)")
//!     .with_prompt("Value:");
//! let secret = input.interact()?;
//! # let _ = secret;
//! # Ok(())
//! # }
//! ```
//!
//! [`egui`]: https://docs.rs/egui
//! [`XGrabKeyboard`]: https://www.x.org/releases/current/doc/man/man3/XGrabKeyboard.3.xhtml

use secrecy::SecretString;

mod error;
mod grab;
mod render;

pub use error::{Error, Result};

/// A modal passphrase entry dialog.
///
/// Configure it with the `with_*` builder methods, then call [`interact`] to
/// show the dialog and collect the value.
///
/// [`interact`]: PassphraseInput::interact
#[derive(Debug, Default, Clone)]
pub struct PassphraseInput<'a> {
    title: Option<&'a str>,
    description: Option<&'a str>,
    prompt: Option<&'a str>,
    grab: Option<bool>,
}

impl<'a> PassphraseInput<'a> {
    /// Creates a new passphrase dialog with default text.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the window title.
    pub fn with_title(&mut self, title: &'a str) -> &mut Self {
        self.title = Some(title);
        self
    }

    /// Sets the descriptive line shown above the input, explaining what is being
    /// entered (for example which secret and profile).
    pub fn with_description(&mut self, description: &'a str) -> &mut Self {
        self.description = Some(description);
        self
    }

    /// Sets the label immediately before the input field (default: `Value:`).
    pub fn with_prompt(&mut self, prompt: &'a str) -> &mut Self {
        self.prompt = Some(prompt);
        self
    }

    /// Whether to grab the keyboard while the dialog is open. Defaults to `true`.
    /// Only affects X11; on Wayland, macOS, and Windows it is a no-op because the
    /// compositor already isolates input between clients.
    pub fn with_grab(&mut self, grab: bool) -> &mut Self {
        self.grab = Some(grab);
        self
    }

    /// Shows the dialog and returns the entered value.
    ///
    /// Returns [`Error::Cancelled`] if the user dismisses the dialog, and
    /// [`Error::NoDisplay`] if no windowing system is available.
    pub fn interact(&self) -> Result<SecretString> {
        let spec = render::DialogSpec {
            title: self.title.unwrap_or("Passphrase required").to_string(),
            description: self.description.map(str::to_string),
            kind: render::DialogKind::Passphrase {
                prompt: self.prompt.unwrap_or("Value:").to_string(),
            },
            grab: self.grab.unwrap_or(true),
        };
        match render::run(spec)? {
            render::Outcome::Passphrase(secret) => Ok(secret),
            render::Outcome::Cancelled => Err(Error::Cancelled),
            render::Outcome::Confirmed(_) => {
                Err(Error::Failed("unexpected confirmation outcome".to_string()))
            }
        }
    }
}

/// A modal yes/no confirmation dialog, used to approve or deny an action.
#[derive(Debug, Default, Clone)]
pub struct ConfirmationDialog<'a> {
    title: Option<&'a str>,
    description: Option<&'a str>,
    ok: Option<&'a str>,
    cancel: Option<&'a str>,
    grab: Option<bool>,
}

impl<'a> ConfirmationDialog<'a> {
    /// Creates a new confirmation dialog with default button labels.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the window title.
    pub fn with_title(&mut self, title: &'a str) -> &mut Self {
        self.title = Some(title);
        self
    }

    /// Sets the descriptive body shown above the buttons.
    pub fn with_description(&mut self, description: &'a str) -> &mut Self {
        self.description = Some(description);
        self
    }

    /// Sets the label of the confirming button (default: `OK`).
    pub fn with_ok(&mut self, ok: &'a str) -> &mut Self {
        self.ok = Some(ok);
        self
    }

    /// Sets the label of the denying button (default: `Cancel`).
    pub fn with_cancel(&mut self, cancel: &'a str) -> &mut Self {
        self.cancel = Some(cancel);
        self
    }

    /// Whether to grab the keyboard while the dialog is open. Defaults to `true`.
    /// Only affects X11 (see [`PassphraseInput::with_grab`]).
    pub fn with_grab(&mut self, grab: bool) -> &mut Self {
        self.grab = Some(grab);
        self
    }

    /// Shows the dialog and returns `true` if confirmed, `false` if denied.
    ///
    /// Returns [`Error::Cancelled`] if the user dismisses the dialog without
    /// choosing (Escape or closing the window), and [`Error::NoDisplay`] if no
    /// windowing system is available.
    pub fn confirm(&self, query: &str) -> Result<bool> {
        let description = match (self.description, query.is_empty()) {
            (Some(desc), false) => Some(format!("{desc}\n\n{query}")),
            (Some(desc), true) => Some(desc.to_string()),
            (None, false) => Some(query.to_string()),
            (None, true) => None,
        };
        let spec = render::DialogSpec {
            title: self.title.unwrap_or("Confirm").to_string(),
            description,
            kind: render::DialogKind::Confirm {
                ok: self.ok.unwrap_or("OK").to_string(),
                cancel: self.cancel.unwrap_or("Cancel").to_string(),
            },
            grab: self.grab.unwrap_or(true),
        };
        match render::run(spec)? {
            render::Outcome::Confirmed(confirmed) => Ok(confirmed),
            render::Outcome::Cancelled => Err(Error::Cancelled),
            render::Outcome::Passphrase(_) => {
                Err(Error::Failed("unexpected passphrase outcome".to_string()))
            }
        }
    }
}

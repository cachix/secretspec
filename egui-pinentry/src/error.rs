//! Error type for [`crate`] prompts.

/// Something that went wrong while showing a trusted prompt.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The user dismissed the dialog without answering: pressed Escape, clicked
    /// Cancel, or closed the window. For a passphrase prompt this means no value
    /// was entered; it is *not* an approval decision.
    #[error("prompt cancelled by user")]
    Cancelled,

    /// No windowing system was available to display the prompt (for example a
    /// headless session with neither an X11 display nor a Wayland compositor).
    /// The caller is expected to fall back to another channel.
    #[error("no graphical display available for a trusted prompt: {0}")]
    NoDisplay(String),

    /// The prompt could not be shown or driven for some other reason (a
    /// windowing or rendering failure). The string carries the underlying cause.
    #[error("trusted prompt failed: {0}")]
    Failed(String),
}

/// Result alias for prompt operations.
pub type Result<T> = std::result::Result<T, Error>;

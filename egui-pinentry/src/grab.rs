//! Keyboard grab for the dialog window.
//!
//! On X11, [`try_grab`] calls `XGrabKeyboard` so that every `KeyPress`/`KeyRelease`
//! is delivered exclusively to the dialog while it is open, defeating other X
//! clients that would otherwise snoop keystrokes through the normal event path.
//! The returned [`KeyboardGrab`] releases the grab in its `Drop`, so the ungrab
//! runs on every exit path (normal return, early return, panic unwind); the X
//! server also auto-releases if the connection closes.
//!
//! On Wayland, macOS, and Windows the compositor already isolates input between
//! clients and offers no equivalent client-side global grab, so [`try_grab`]
//! reports [`GrabAttempt::NotApplicable`] and the dialog runs ungrabbed.
//!
//! This is not a complete anti-keylogger: a privileged local process can still
//! read the input devices directly or use raw-input extensions. It defeats
//! ordinary event-based snoopers on a shared X display.

/// Outcome of a single attempt to grab the keyboard.
pub(crate) enum GrabAttempt {
    /// The grab succeeded. Hold the guard for the dialog's lifetime. Boxed
    /// because the guard keeps the whole libX11 function table alive.
    Grabbed(Box<KeyboardGrab>),
    /// No grab applies here (Wayland, a non-Linux platform, or libX11 missing).
    /// Stop trying.
    NotApplicable,
    /// This is an X11 window but the grab did not take yet — typically because
    /// the window is not viewable at the moment. Retry on a later frame.
    Retry,
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{KeyboardGrab, try_grab};

#[cfg(not(target_os = "linux"))]
pub(crate) use other::{KeyboardGrab, try_grab};

#[cfg(target_os = "linux")]
mod linux {
    use super::GrabAttempt;
    use winit::raw_window_handle::{
        HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle,
    };
    use winit::window::Window;
    use x11_dl::xlib;

    /// An active X11 keyboard grab. Releasing happens in [`Drop`].
    pub(crate) struct KeyboardGrab {
        xlib: xlib::Xlib,
        display: *mut xlib::Display,
    }

    impl Drop for KeyboardGrab {
        fn drop(&mut self) {
            // Safety: `display` is winit's live Xlib connection for the window we
            // grabbed, used only here on the event-loop (main) thread.
            unsafe {
                (self.xlib.XUngrabKeyboard)(self.display, xlib::CurrentTime);
                (self.xlib.XFlush)(self.display);
            }
        }
    }

    pub(crate) fn try_grab(window: &Window) -> GrabAttempt {
        // Only an X11 (Xlib) window has a display+window we can grab. winit's X11
        // backend hands out Xlib handles; Wayland yields Wayland handles (no grab).
        let (display, xid) = match (
            window.display_handle().map(|h| h.as_raw()),
            window.window_handle().map(|h| h.as_raw()),
        ) {
            (Ok(RawDisplayHandle::Xlib(d)), Ok(RawWindowHandle::Xlib(w))) => match d.display {
                Some(ptr) => (ptr.as_ptr().cast::<xlib::Display>(), w.window),
                None => return GrabAttempt::NotApplicable,
            },
            _ => return GrabAttempt::NotApplicable,
        };

        // dlopen libX11 to get the function table; the grab targets winit's own
        // connection (`display`), so it applies to the real dialog window.
        let xlib = match xlib::Xlib::open() {
            Ok(x) => x,
            Err(_) => return GrabAttempt::NotApplicable,
        };

        // Safety: FFI into libX11 with winit's valid Display pointer and window id.
        let result = unsafe {
            let r = (xlib.XGrabKeyboard)(
                display,
                xid,
                xlib::True,          // owner_events: deliver normally to our window
                xlib::GrabModeAsync, // pointer_mode
                xlib::GrabModeAsync, // keyboard_mode
                xlib::CurrentTime,
            );
            (xlib.XFlush)(display);
            r
        };

        if result == xlib::GrabSuccess {
            GrabAttempt::Grabbed(Box::new(KeyboardGrab { xlib, display }))
        } else {
            // GrabNotViewable (window not mapped yet), AlreadyGrabbed, etc.
            GrabAttempt::Retry
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod other {
    use super::GrabAttempt;
    use winit::window::Window;

    /// Placeholder grab guard on platforms without an X11 keyboard grab.
    pub(crate) struct KeyboardGrab;

    pub(crate) fn try_grab(_window: &Window) -> GrabAttempt {
        GrabAttempt::NotApplicable
    }
}

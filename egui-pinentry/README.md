# egui-pinentry

A trusted local passphrase and confirmation dialog for Rust, drawn with
[egui](https://github.com/emilk/egui) rasterized **on the CPU** (no GPU, and no
OpenGL/Vulkan in the dependency tree) and presented with
[softbuffer](https://github.com/rust-windowing/softbuffer). On X11 it grabs the
keyboard while the dialog is open to resist keystroke snooping.

It is a self contained alternative to shelling out to a `pinentry` binary: the
prompt runs in your own process on a channel the *calling* process cannot sit
between, and needs no external program installed.

## Why

When an orchestrator (a CI job, a coding agent, a parent process) runs your
program, it controls that program's stdin and stdout. A secret typed on stdin,
or an approval answered on stdin, is therefore visible to and forgeable by that
orchestrator. This crate collects the value on a windowing channel the
orchestrator does not control, so:

- the value is entered by a human at the display, not piped in by the caller, and
- an approval cannot be self answered by the tool that triggered it.

## Features

- **Passphrase entry** and **yes/no confirmation** dialogs.
- **Pure CPU rendering.** No `wgpu`, `glow`, `libGL`, or `libvulkan`. The UI is
  rasterized by [`egui_software_backend`](https://github.com/DGriffin91/egui_software_backend)
  and blitted with `softbuffer`.
- **X11 keyboard grab** (`XGrabKeyboard`), released on every exit path via a
  `Drop` guard. No op on Wayland, macOS, and Windows, where the compositor
  already isolates input between clients.
- **Secret hygiene.** Keystrokes go straight into a `zeroize::Zeroizing` buffer,
  never through an egui `TextEdit`, so the plaintext is not copied into egui's
  retained widget state or undo history, and is wiped from memory when the
  dialog ends. The result is returned as a `secrecy::SecretString`.
- **Reusable across dialogs** in one process (via winit's `run_app_on_demand`).

## Usage

```rust
use egui_pinentry::{PassphraseInput, ConfirmationDialog, Error};

// Collect a secret value.
let mut input = PassphraseInput::new();
input
    .with_title("secretspec")
    .with_description("Set DATABASE_URL (profile: production)")
    .with_prompt("Value:");

match input.interact() {
    Ok(secret) => { /* secret: secrecy::SecretString */ }
    Err(Error::Cancelled) => { /* user dismissed the dialog */ }
    Err(Error::NoDisplay(_)) => { /* headless: fall back to another channel */ }
    Err(Error::Failed(_)) => { /* windowing or rendering failure */ }
}

// Ask for approval.
let mut confirm = ConfirmationDialog::new();
confirm.with_description("Release secrets to the command?");
match confirm.confirm("secretspec run -- deploy") {
    Ok(true) => { /* approved */ }
    Ok(false) => { /* denied */ }
    Err(_) => { /* cancelled or unavailable */ }
}
```

The keyboard grab is on by default; disable it per dialog with
`with_grab(false)`.

The API mirrors the [`pinentry`](https://docs.rs/pinentry) crate so it is a small
change to swap in.

## Requirements

The windowing libraries are opened at runtime by soname (`dlopen`), so they are
never hard link dependencies and the binary starts fine on a headless machine
(it just returns `Error::NoDisplay` when you try to prompt). Only the backend for
the session in use is loaded:

- **Wayland**: `libwayland-client`, `libxkbcommon`
- **X11**: `libX11`, `libX11-xcb`, `libxcb`, `libXcursor`, `libXi`, `libxkbcommon`

These are present on any Linux desktop with a graphical session. There are **no
GPU libraries** in that set. On NixOS the libraries are not on the default loader
path, so put them on `LD_LIBRARY_PATH` (or use an `rpath`/`autoPatchelf` wrapper).

`interact()` and `confirm()` must be called from the **main thread**, because
that is where winit requires its event loop to run.

## Security notes

The X11 grab redirects keyboard event *delivery* so other X clients cannot
receive your keystrokes through the normal event path. It is **not** a complete
anti keylogger: a privileged local process can still read the input devices
directly or use raw input extensions. It defeats ordinary event based snoopers on
a shared X display.

The value is handled in your process before it reaches the caller, so the
guarantee is "the calling orchestrator never sees it", not "only a vault ever
sees it".

## Testing

The dialog layout is a plain function (`dialog_ui`) driven headlessly in tests
with [`egui_kittest`](https://docs.rs/egui_kittest): the suite feeds synthetic
input events and asserts on the resulting state, so it runs in CI with no display.

```
cargo test -p egui-pinentry
```

## Prior art

GnuPG's `pinentry` is the standard passphrase helper but requires the external
binary and has known problems on pure Wayland compositors. The
[`pinentry-egui`](https://github.com/dsociative/pinentry-egui) project is a
related, independent egui based gpg-agent pinentry; it differs in that it renders
on the GPU (glow/OpenGL), is a standalone Assuan binary rather than a library,
and does not grab the keyboard.

## License

Apache-2.0.

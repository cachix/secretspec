//! The modal event loop.
//!
//! A single [`run`] call opens one small, non-resizable window, builds the
//! dialog UI with egui, rasterizes it on the CPU with
//! [`egui_software_backend`], and presents it with `softbuffer` — no GPU. On X11
//! it grabs the keyboard for the dialog's lifetime (see [`crate::grab`]).
//!
//! Note: winit allows only one event loop per process on some platforms, so a
//! process should call [`run`] at most once. Driving several dialogs from one
//! loop is a later refinement.

use std::cell::RefCell;
use std::num::NonZeroU32;
use std::rc::Rc;

use egui_software_backend::{BufferMutRef, ColorFieldOrder, EguiSoftwareRender};
use secrecy::SecretString;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::platform::run_on_demand::EventLoopExtRunOnDemand;
use winit::window::{Window, WindowId};
use zeroize::Zeroizing;

use crate::grab::{self, GrabAttempt, KeyboardGrab};
use crate::{Error, Result};

/// What to show and how.
pub(crate) struct DialogSpec {
    pub title: String,
    pub description: Option<String>,
    pub kind: DialogKind,
    pub grab: bool,
}

/// Which flavor of dialog to show.
pub(crate) enum DialogKind {
    /// Collect a masked value, with a prompt label before the field.
    Passphrase { prompt: String },
    /// Ask a yes/no question, with the two button labels.
    Confirm { ok: String, cancel: String },
}

/// The result of showing a dialog.
pub(crate) enum Outcome {
    Passphrase(SecretString),
    Confirmed(bool),
    Cancelled,
}

/// What the user did in a single built frame.
enum FrameAction {
    /// Confirming button, or Enter: submit the value / approve.
    Submit,
    /// The denying button of a confirmation: an explicit "no".
    Deny,
    /// Escape, the cancel button, or the window close: abandon the dialog.
    Cancel,
}

type SbSurface = softbuffer::Surface<Rc<Window>, Rc<Window>>;

thread_local! {
    /// winit permits only one event loop per process (and a *failed* creation
    /// still counts), so we keep one alive per thread and reuse it across
    /// dialogs. Access only from the thread that first created it — in practice
    /// the main thread, which is where winit requires the loop to run.
    static EVENT_LOOP: RefCell<Option<EventLoop<()>>> = const { RefCell::new(None) };
}

/// Shows the dialog described by `spec` and returns its outcome.
///
/// Reuses one process-wide event loop via `run_app_on_demand`, so it can be
/// called repeatedly (e.g. once per missing secret). Must be called from the
/// main thread.
pub(crate) fn run(spec: DialogSpec) -> Result<Outcome> {
    EVENT_LOOP.with_borrow_mut(|slot| {
        if slot.is_none() {
            *slot = Some(EventLoop::new().map_err(|e| Error::NoDisplay(e.to_string()))?);
        }
        let event_loop = slot.as_mut().expect("event loop initialized above");

        let mut app = App::new(spec);
        event_loop
            .run_app_on_demand(&mut app)
            .map_err(|e| Error::Failed(e.to_string()))?;

        if let Some(err) = app.error.take() {
            return Err(err);
        }
        // The grab guard drops with `app` here, releasing the keyboard.
        Ok(app.outcome.unwrap_or(Outcome::Cancelled))
    })
}

struct App {
    spec: DialogSpec,
    egui_ctx: egui::Context,
    sw_render: EguiSoftwareRender,

    window: Option<Rc<Window>>,
    surface: Option<SbSurface>,
    egui_state: Option<egui_winit::State>,

    /// Backing store for the passphrase field. Keystrokes are appended here
    /// directly (never through an egui `TextEdit`), and it is zeroized on drop,
    /// so the secret is not copied into egui's retained widget/undo state and is
    /// wiped from memory when the dialog ends. Emptied into the result on submit.
    value: Zeroizing<String>,

    grab: Option<Box<KeyboardGrab>>,
    grab_done: bool,

    outcome: Option<Outcome>,
    error: Option<Error>,
}

impl App {
    fn new(spec: DialogSpec) -> Self {
        App {
            spec,
            egui_ctx: egui::Context::default(),
            // softbuffer wants 0x00RRGGBB (BGRA byte order on little-endian).
            sw_render: EguiSoftwareRender::new(ColorFieldOrder::Bgra),
            window: None,
            surface: None,
            egui_state: None,
            // Reserve up front so ordinary typing does not reallocate (which
            // would leave un-zeroized copies of the partial secret behind).
            value: Zeroizing::new(String::with_capacity(256)),
            grab: None,
            grab_done: false,
            outcome: None,
            error: None,
        }
    }

    fn fail(&mut self, elwt: &ActiveEventLoop, err: Error) {
        self.error = Some(err);
        elwt.exit();
    }

    fn redraw(&mut self, elwt: &ActiveEventLoop, window: &Rc<Window>) {
        // Grab the keyboard once the window is viewable (X11 only), retrying on
        // later frames until it succeeds or is determined not to apply.
        if self.spec.grab && !self.grab_done {
            match grab::try_grab(window) {
                GrabAttempt::Grabbed(g) => {
                    self.grab = Some(g);
                    self.grab_done = true;
                }
                GrabAttempt::NotApplicable => self.grab_done = true,
                GrabAttempt::Retry => window.request_redraw(),
            }
        }

        let Some(state) = self.egui_state.as_mut() else {
            return;
        };
        let raw_input = state.take_egui_input(window);

        let mut action: Option<FrameAction> = None;
        let full = build_frame(
            &self.egui_ctx,
            raw_input,
            &self.spec,
            &mut self.value,
            &mut action,
        );
        state.handle_platform_output(window, full.platform_output);

        if let Some(action) = action {
            self.outcome = Some(match action {
                FrameAction::Submit => match &self.spec.kind {
                    // Move the inner String out (leaving the Zeroizing wrapper
                    // holding an empty one) into the secret, which zeroizes it in
                    // turn.
                    DialogKind::Passphrase { .. } => Outcome::Passphrase(SecretString::new(
                        std::mem::take(&mut *self.value).into(),
                    )),
                    DialogKind::Confirm { .. } => Outcome::Confirmed(true),
                },
                FrameAction::Deny => Outcome::Confirmed(false),
                FrameAction::Cancel => Outcome::Cancelled,
            });
            elwt.exit();
            return;
        }

        let clipped = self.egui_ctx.tessellate(full.shapes, full.pixels_per_point);
        if let Err(e) = self.present_frame(
            &clipped,
            &full.textures_delta,
            full.pixels_per_point,
            window,
        ) {
            self.fail(elwt, e);
        }
    }

    /// Rasterizes `clipped` into the softbuffer surface and presents it.
    fn present_frame(
        &mut self,
        clipped: &[egui::ClippedPrimitive],
        textures_delta: &egui::TexturesDelta,
        pixels_per_point: f32,
        window: &Rc<Window>,
    ) -> Result<()> {
        let size = window.inner_size();
        let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) else {
            return Ok(());
        };
        let surface = self
            .surface
            .as_mut()
            .ok_or_else(|| Error::Failed("surface not initialized".to_string()))?;
        surface
            .resize(w, h)
            .map_err(|e| Error::Failed(e.to_string()))?;
        let mut buffer = surface
            .buffer_mut()
            .map_err(|e| Error::Failed(e.to_string()))?;
        buffer.fill(0);
        {
            let pixels: &mut [[u8; 4]] = bytemuck::cast_slice_mut(&mut buffer);
            let mut bref = BufferMutRef::new(pixels, size.width as usize, size.height as usize);
            self.sw_render
                .render(&mut bref, clipped, textures_delta, pixels_per_point);
        }
        buffer.present().map_err(|e| Error::Failed(e.to_string()))?;
        Ok(())
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, elwt: &ActiveEventLoop) {
        // Modal: only redraw in response to input, not continuously.
        elwt.set_control_flow(ControlFlow::Wait);
        if self.window.is_some() {
            return;
        }
        let attrs = Window::default_attributes()
            .with_title(&self.spec.title)
            .with_inner_size(winit::dpi::LogicalSize::new(480.0, 200.0))
            .with_resizable(false);
        let window = match elwt.create_window(attrs) {
            Ok(w) => Rc::new(w),
            Err(e) => {
                self.fail(elwt, Error::NoDisplay(e.to_string()));
                return;
            }
        };

        let context = match softbuffer::Context::new(window.clone()) {
            Ok(c) => c,
            Err(e) => {
                self.fail(elwt, Error::Failed(e.to_string()));
                return;
            }
        };
        let surface = match softbuffer::Surface::new(&context, window.clone()) {
            Ok(s) => s,
            Err(e) => {
                self.fail(elwt, Error::Failed(e.to_string()));
                return;
            }
        };

        let egui_state = egui_winit::State::new(
            self.egui_ctx.clone(),
            egui::ViewportId::ROOT,
            &*window,
            Some(window.scale_factor() as f32),
            None,
            None,
        );

        self.surface = Some(surface);
        self.egui_state = Some(egui_state);
        self.window = Some(window.clone());
        window.request_redraw();
    }

    fn window_event(&mut self, elwt: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let Some(window) = self.window.clone() else {
            return;
        };

        if let Some(state) = self.egui_state.as_mut() {
            let response = state.on_window_event(&window, &event);
            if response.repaint {
                window.request_redraw();
            }
        }

        match event {
            WindowEvent::CloseRequested => {
                self.outcome = Some(Outcome::Cancelled);
                elwt.exit();
            }
            WindowEvent::RedrawRequested => self.redraw(elwt, &window),
            _ => {}
        }
    }
}

/// Builds one egui frame and records the user's action, if any.
///
/// `run` is used rather than the newer `run_ui` for API stability across the
/// egui 0.34 line; the deprecation is intentional.
#[allow(deprecated)]
fn build_frame(
    egui_ctx: &egui::Context,
    raw_input: egui::RawInput,
    spec: &DialogSpec,
    value: &mut Zeroizing<String>,
    action: &mut Option<FrameAction>,
) -> egui::FullOutput {
    egui_ctx.run(raw_input, |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            dialog_ui(ui, spec, value, action);
        });
    })
}

/// Lays out the dialog's widgets into `ui` and records the user's action.
///
/// Kept separate from the event loop so it can be driven headlessly in tests
/// (via egui_kittest): feed input events, run a frame, and read back the
/// resulting `value` / `action` without opening a window.
fn dialog_ui(
    ui: &mut egui::Ui,
    spec: &DialogSpec,
    value: &mut Zeroizing<String>,
    action: &mut Option<FrameAction>,
) {
    ui.add_space(8.0);
    if let Some(description) = &spec.description {
        ui.label(description);
        ui.add_space(8.0);
    }

    match &spec.kind {
        DialogKind::Passphrase { prompt } => {
            // Feed keystrokes straight into our zeroizing buffer instead of an
            // egui `TextEdit`, so the plaintext never enters egui's retained
            // widget state or undo history. Only a masked view is drawn.
            ui.input(|input| {
                for event in &input.events {
                    match event {
                        egui::Event::Text(text) | egui::Event::Paste(text) => {
                            value.push_str(text);
                        }
                        egui::Event::Key {
                            key: egui::Key::Backspace,
                            pressed: true,
                            ..
                        } => {
                            value.pop();
                        }
                        _ => {}
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label(prompt);
                let dots = "\u{2022}".repeat(value.chars().count());
                egui::Frame::group(ui.style())
                    .inner_margin(egui::Margin::symmetric(6, 4))
                    .show(ui, |ui| {
                        ui.set_min_width(240.0);
                        ui.add(
                            egui::Label::new(egui::RichText::new(dots).monospace())
                                .selectable(false),
                        );
                    });
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("OK").clicked() {
                    *action = Some(FrameAction::Submit);
                }
                if ui.button("Cancel").clicked() {
                    *action = Some(FrameAction::Cancel);
                }
            });
        }
        DialogKind::Confirm { ok, cancel } => {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button(ok).clicked() {
                    *action = Some(FrameAction::Submit);
                }
                if ui.button(cancel).clicked() {
                    *action = Some(FrameAction::Deny);
                }
            });
        }
    }

    if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
        *action = Some(FrameAction::Submit);
    }
    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
        *action = Some(FrameAction::Cancel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    struct TestState {
        spec: DialogSpec,
        value: Zeroizing<String>,
        action: Option<FrameAction>,
    }

    /// A kittest harness that drives [`dialog_ui`] for `spec`, with an empty
    /// value and no action to start.
    fn harness(spec: DialogSpec) -> Harness<'static, TestState> {
        Harness::new_ui_state(
            |ui, state| dialog_ui(ui, &state.spec, &mut state.value, &mut state.action),
            TestState {
                spec,
                value: Zeroizing::new(String::new()),
                action: None,
            },
        )
    }

    fn passphrase_spec() -> DialogSpec {
        DialogSpec {
            title: "test".into(),
            description: Some("Set SECRET".into()),
            kind: DialogKind::Passphrase {
                prompt: "Value:".into(),
            },
            grab: false,
        }
    }

    fn confirm_spec() -> DialogSpec {
        DialogSpec {
            title: "test".into(),
            description: Some("Release secrets?".into()),
            kind: DialogKind::Confirm {
                ok: "Approve".into(),
                cancel: "Deny".into(),
            },
            grab: false,
        }
    }

    #[test]
    fn typing_appends_to_the_buffer() {
        let mut h = harness(passphrase_spec());
        h.run();
        h.event(egui::Event::Text("hunter2".into()));
        h.run();
        assert_eq!(h.state().value.as_str(), "hunter2");
        // Nothing submitted just by typing.
        assert!(h.state().action.is_none());
    }

    #[test]
    fn backspace_removes_the_last_character() {
        let mut h = harness(passphrase_spec());
        h.run();
        h.event(egui::Event::Text("abc".into()));
        h.run();
        h.key_press(egui::Key::Backspace);
        h.run();
        assert_eq!(h.state().value.as_str(), "ab");
    }

    #[test]
    fn enter_submits_the_passphrase() {
        let mut h = harness(passphrase_spec());
        h.run();
        h.event(egui::Event::Text("pw".into()));
        h.run();
        h.key_press(egui::Key::Enter);
        h.run();
        assert!(matches!(h.state().action, Some(FrameAction::Submit)));
        // The typed value is preserved for the caller to take.
        assert_eq!(h.state().value.as_str(), "pw");
    }

    #[test]
    fn escape_cancels() {
        let mut h = harness(passphrase_spec());
        h.run();
        h.key_press(egui::Key::Escape);
        h.run();
        assert!(matches!(h.state().action, Some(FrameAction::Cancel)));
    }

    #[test]
    fn ok_button_submits_and_cancel_button_cancels() {
        let mut h = harness(passphrase_spec());
        h.run();
        h.get_by_label("OK").click();
        h.run();
        assert!(matches!(h.state().action, Some(FrameAction::Submit)));

        let mut h = harness(passphrase_spec());
        h.run();
        h.get_by_label("Cancel").click();
        h.run();
        assert!(matches!(h.state().action, Some(FrameAction::Cancel)));
    }

    #[test]
    fn confirm_buttons_map_to_submit_and_deny() {
        let mut h = harness(confirm_spec());
        h.run();
        h.get_by_label("Approve").click();
        h.run();
        assert!(matches!(h.state().action, Some(FrameAction::Submit)));

        let mut h = harness(confirm_spec());
        h.run();
        h.get_by_label("Deny").click();
        h.run();
        assert!(matches!(h.state().action, Some(FrameAction::Deny)));
    }
}

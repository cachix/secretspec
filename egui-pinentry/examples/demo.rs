//! Manual smoke test: `cargo run -p egui-pinentry --example demo`.
//!
//! Opens the passphrase dialog, then a confirmation dialog, printing what came
//! back without ever revealing the entered value. Requires a display (X11 or
//! Wayland); on X11 the keyboard is grabbed while each dialog is open.

fn main() {
    let mut input = egui_pinentry::PassphraseInput::new();
    input
        .with_title("egui-pinentry demo")
        .with_description("Enter a value (this is only a demo)")
        .with_prompt("Value:");

    match input.interact() {
        Ok(secret) => {
            use secrecy::ExposeSecret;
            println!(
                "received a value of {} characters",
                secret.expose_secret().len()
            );
        }
        Err(e) => println!("passphrase dialog: {e}"),
    }

    let mut confirm = egui_pinentry::ConfirmationDialog::new();
    confirm
        .with_title("egui-pinentry demo")
        .with_description("Release secrets to the command?")
        .with_ok("Approve")
        .with_cancel("Deny");

    match confirm.confirm("secretspec run -- deploy") {
        Ok(true) => println!("approved"),
        Ok(false) => println!("denied"),
        Err(e) => println!("confirmation dialog: {e}"),
    }
}

//! `secretspec nixos` commands.

use super::TypedArgs;
use crate::CallerContext;
use crate::nixos::{self, LinkReport, RefreshReport};
use clap::Subcommand;
use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::PathBuf;

#[derive(Subcommand)]
pub(super) enum NixosAction {
    /// Seal the provider credentials declared for this host (0.22+)
    ///
    /// Finds provider aliases whose credentials source is
    /// `systemd-credential://`, prompts with hidden input, and encrypts each
    /// credential with `systemd-creds`. Run this once on a fresh machine before
    /// the first `nixos-rebuild switch`.
    Link {
        /// Directory receiving the sealed `<credential>.cred` files
        #[arg(long, value_name = "DIR", default_value = nixos::DEFAULT_CREDENTIALS)]
        store: PathBuf,
        /// Replace credentials that are already linked
        #[arg(long)]
        force: bool,
        /// `systemd-creds` binary to use
        #[arg(long, value_name = "FILE")]
        systemd_creds: Option<PathBuf>,
    },
    /// Resolve the installed NixOS plan into runtime files (0.22+)
    ///
    /// This is the same operation the NixOS module runs at boot and from its
    /// timer. It uses the encrypted last-known-good cache when a provider is
    /// unreachable.
    Refresh {
        /// Value-free plan installed by the NixOS module
        #[arg(long, value_name = "FILE", default_value = nixos::DEFAULT_PLAN)]
        plan: PathBuf,
        /// Resolve and report without writing or restarting anything
        #[arg(long)]
        check: bool,
        /// Write files but do not restart consumer units
        #[arg(long)]
        no_restart: bool,
    },
    /// Run a command with the installed plan's credentials and provider tools (0.22+)
    ///
    /// This uses the same sealed provider credentials and `extraPackages` PATH
    /// as `secretspec.service`, so commands such as
    /// `secretspec set NAME --from-file -` work without installing a provider
    /// CLI or exporting its token globally.
    Exec {
        /// Value-free plan installed by the NixOS module
        #[arg(long, value_name = "FILE", default_value = nixos::DEFAULT_PLAN)]
        plan: PathBuf,
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true, value_hint = clap::ValueHint::CommandWithArguments)]
        command: Vec<String>,
    },
}

pub(super) fn run(
    action: NixosAction,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
    _typed: TypedArgs,
) -> Result<()> {
    match action {
        NixosAction::Link {
            store,
            force,
            systemd_creds,
        } => {
            let report = nixos::link(
                file.as_deref(),
                Some(&store),
                force,
                systemd_creds.as_deref(),
            )
            .into_diagnostic()
            .wrap_err("Failed to link NixOS provider credentials")?;
            print_link_report(&store, &report);
            Ok(())
        }
        NixosAction::Refresh {
            plan,
            check,
            no_restart,
        } => {
            let report =
                nixos::refresh(&plan, check, no_restart, reason.as_deref(), caller.as_ref())
                    .into_diagnostic()
                    .wrap_err("Failed to refresh NixOS secrets")?;
            print_refresh_report(&report, check);
            Ok(())
        }
        NixosAction::Exec { plan, command } => nixos::exec(&plan, &command)
            .into_diagnostic()
            .wrap_err("Failed to run command with NixOS secrets"),
    }
}

fn print_link_report(store: &std::path::Path, report: &LinkReport) {
    for item in &report.sealed {
        println!("✓ sealed {item}");
    }
    for item in &report.skipped {
        println!("• {item} already linked; use --force to rotate");
    }
    if !report.sealed.is_empty() {
        println!(
            "Linked {} credential(s) in {}",
            report.sealed.len(),
            store.display()
        );
    }
}

fn print_refresh_report(report: &RefreshReport, check: bool) {
    let verb = if check { "would change" } else { "changed" };
    println!(
        "Secrets: {} resolved, {} cached",
        report.resolved, report.cached
    );
    println!(
        "Generation: {} {verb}, {} unchanged",
        report.changed, report.unchanged
    );
    if report.templates > 0 {
        println!("Templates: {}", report.templates);
    }
    if !report.restarted_units.is_empty() {
        println!("Restarted: {}", report.restarted_units.join(", "));
    }
}

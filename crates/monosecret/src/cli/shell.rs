//! Emit resolved secrets as environment declarations for a target shell or CI
//! environment. Backs the `monosecret env` command.
//!
//! `monosecret env` resolves the active profile's secrets (the same resolution
//! path as `monosecret run`) and prints them in a form the surrounding shell
//! can evaluate, so a single command can load every secret into the current
//! shell session. Each shell gets its own declaration syntax:
//!
//! | Shell | Output | Apply with |
//! |-------|--------|------------|
//! | bash / sh / zsh | `export KEY='value';` | `eval "$(monosecret env --shell bash)"` |
//! | fish | `set -gx KEY 'value';` | `monosecret env --shell fish \| source` |
//! | PowerShell | `$env:KEY='value';` | `monosecret env --shell powershell \| iex` |
//! | Nushell | `load-env { KEY: "value" }` | `monosecret env --shell nushell --output env.nu && nu -c "source env.nu"` |
//! | GitHub Actions | appends to `$GITHUB_ENV` | run inside a workflow step |
//! | GitLab / dotenv | `KEY="value"` | `monosecret env --shell gitlab --output deploy.env` |
//!
//! Secret values are quoted per the target's rules so a value containing
//! spaces, quotes, `$`, backslashes, or newlines cannot break out of the
//! declaration or inject commands. Keys are validated identifiers upstream, so
//! they are emitted bare.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use clap::ValueEnum;

use crate::MonosecretError;
use crate::Result;

/// The shell or CI environment to emit environment declarations for.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Shell {
	/// POSIX shells — bash, sh, zsh. Emits `export KEY='value';`.
	#[value(alias("sh"), alias("zsh"))]
	Bash,
	/// fish. Emits `set -gx KEY 'value';`.
	Fish,
	/// PowerShell (pwsh). Emits `$env:KEY='value';`.
	#[value(alias("pwsh"))]
	Powershell,
	/// Nushell. Emits `load-env { KEY: "value", ... }`.
	#[value(alias("nu"))]
	Nushell,
	/// GitHub Actions. Appends `KEY<<DELIM` heredoc blocks to `$GITHUB_ENV`.
	Github,
	/// GitLab CI. Emits `KEY="value"` dotenv for `artifacts:reports:dotenv`.
	Gitlab,
	/// Generic dotenv — `KEY="value"`, same shape as GitLab.
	Dotenv,
}

impl Shell {
	/// The display name used in messages.
	pub fn as_str(self) -> &'static str {
		match self {
			Shell::Bash => "bash",
			Shell::Fish => "fish",
			Shell::Powershell => "powershell",
			Shell::Nushell => "nushell",
			Shell::Github => "github",
			Shell::Gitlab => "gitlab",
			Shell::Dotenv => "dotenv",
		}
	}
}

/// Emits `pairs` for `shell` to the appropriate sink.
///
/// - `github`: appends the GitHub `$GITHUB_ENV` heredoc blocks to the file at
///   `$GITHUB_ENV` (or `output` when given) and prints `::add-mask::` workflow
///   commands to stdout so the values are masked in the run log. Errors if
///   neither `output` nor `$GITHUB_ENV` is available.
/// - all others: writes the shell-native declarations to stdout, or to `output`
///   when given.
///
/// Pairs are assumed already sorted by key by the caller.
pub fn emit(shell: Shell, pairs: &[(String, String)], output: Option<&Path>) -> Result<()> {
	if shell == Shell::Github {
		return emit_github(pairs, output);
	}

	let rendered = render(shell, pairs);
	if let Some(path) = output {
		let mut file = std::fs::File::create(path).map_err(|e| {
			MonosecretError::EnvEmit(format!("Failed to create {}: {e}", path.display()))
		})?;
		file.write_all(rendered.as_bytes()).map_err(|e| {
			MonosecretError::EnvEmit(format!("Failed to write {}: {e}", path.display()))
		})?;
	} else {
		let stdout = std::io::stdout();
		let mut lock = stdout.lock();
		lock.write_all(rendered.as_bytes())
			.map_err(|e| MonosecretError::EnvEmit(format!("Failed to write to stdout: {e}")))?;
	}
	Ok(())
}

/// Renders `pairs` as declarations for `shell` (including the GitHub `$GITHUB_ENV`
/// file format). Pure: no I/O, so it is unit-testable.
pub fn render(shell: Shell, pairs: &[(String, String)]) -> String {
	let mut out = String::new();
	for (key, value) in pairs {
		match shell {
			Shell::Bash => {
				let _ = writeln!(&mut out, "export {}={};", key, bash_quote(value));
			}
			Shell::Fish => {
				let _ = writeln!(&mut out, "set -gx {} {};", key, fish_quote(value));
			}
			Shell::Powershell => {
				let _ = writeln!(&mut out, "$env:{}={};", key, ps_quote(value));
			}
			Shell::Nushell => {} // handled below as a single record
			Shell::Github => {
				let delim = github_delimiter(value);
				let _ = write!(&mut out, "{key}<<{delim}\n{value}\n{delim}\n");
			}
			Shell::Gitlab | Shell::Dotenv => {
				let _ = writeln!(&mut out, "{}={}", key, dotenv_quote(value));
			}
		}
	}
	if shell == Shell::Nushell {
		out.push_str("load-env {\n");
		for (key, value) in pairs {
			let _ = writeln!(&mut out, "    {key}: {}", nu_quote(value));
		}
		out.push_str("}\n");
	}
	out
}

/// Appends the GitHub `$GITHUB_ENV` heredoc blocks for `pairs` to the target
/// file (printing `::add-mask::` lines to stdout so the values are masked).
fn emit_github(pairs: &[(String, String)], output: Option<&Path>) -> Result<()> {
	let path = match output {
		Some(p) => p.to_path_buf(),
		None => {
			std::env::var_os("GITHUB_ENV")
				.map(std::path::PathBuf::from)
				.ok_or_else(|| {
					MonosecretError::EnvEmit(
						"Not running inside GitHub Actions (no $GITHUB_ENV). \
					 Pass --output <path> to write the GitHub env file elsewhere, \
					 or use --shell dotenv for portable KEY=value output."
							.to_string(),
					)
				})?
		}
	};

	let rendered = render(Shell::Github, pairs);
	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(&path)
		.map_err(|e| MonosecretError::EnvEmit(format!("Failed to open {}: {e}", path.display())))?;
	file.write_all(rendered.as_bytes()).map_err(|e| {
		MonosecretError::EnvEmit(format!("Failed to append to {}: {e}", path.display()))
	})?;

	// Mask each value in the run log. `::add-mask::` is a workflow command
	// consumed by the runner, so the literal value is not echoed.
	let stdout = std::io::stdout();
	let mut lock = stdout.lock();
	for (_, value) in pairs {
		let _ = writeln!(lock, "::add-mask::{value}");
	}
	Ok(())
}

/// Picks a `$GITHUB_ENV` heredoc delimiter that does not occur in `value`, so a
/// value cannot prematurely close its own block.
fn github_delimiter(value: &str) -> String {
	const BASE: &str = "__MONOSECRET_ENV_EOF__";
	if !value.contains(BASE) {
		return BASE.to_string();
	}
	let mut n = 1;
	loop {
		let candidate = format!("{BASE}_{n}_");
		if !value.contains(&candidate) {
			return candidate;
		}
		n += 1;
	}
}

/// Single-quote `value` for POSIX shells, escaping embedded single quotes as
/// `'\''` (close, escaped quote, reopen).
fn bash_quote(value: &str) -> String {
	let s = value.replace('\'', "'\\''");
	format!("'{s}'")
}

/// Single-quote `value` for fish. Inside fish single quotes, `\` only escapes
/// `\` and `'`, so escape `\` first, then `'` as `\'`.
fn fish_quote(value: &str) -> String {
	let s = value.replace('\\', "\\\\").replace('\'', "\\'");
	format!("'{s}'")
}

/// Single-quote `value` for PowerShell, doubling embedded single quotes.
fn ps_quote(value: &str) -> String {
	let s = value.replace('\'', "''");
	format!("'{s}'")
}

/// Double-quote `value` for Nushell, escaping `\` and `"`.
fn nu_quote(value: &str) -> String {
	let s = value.replace('\\', "\\\\").replace('"', "\\\"");
	format!("\"{s}\"")
}

/// Double-quote `value` for dotenv / GitLab, escaping `\`, `"`, and newlines
/// (`\n`, `\r`) so the value survives a dotenv parse.
fn dotenv_quote(value: &str) -> String {
	let s = value
		.replace('\\', "\\\\")
		.replace('"', "\\\"")
		.replace('\n', "\\n")
		.replace('\r', "\\r");
	format!("\"{s}\"")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn bash_quotes_single_quotes() {
		let snapshot = format!(
			"plain => {}\na'b => {}\nwith $ and `cmd` => {}",
			bash_quote("plain"),
			bash_quote("a'b"),
			bash_quote("with $ and `cmd`")
		);
		insta::assert_snapshot!(snapshot);
	}

	#[test]
	fn fish_escapes_backslash_and_single_quote() {
		let snapshot = format!(
			"plain => {}\na'b => {}\na\\b => {}",
			fish_quote("plain"),
			fish_quote("a'b"),
			fish_quote("a\\b")
		);
		insta::assert_snapshot!(snapshot);
	}

	#[test]
	fn powershell_doubles_single_quotes() {
		let snapshot = format!("plain => {}\na'b => {}", ps_quote("plain"), ps_quote("a'b"));
		insta::assert_snapshot!(snapshot);
	}

	#[test]
	fn nushell_escapes_backslash_and_double_quote() {
		let snapshot = format!(
			"plain => {}\na\"b => {}\na\\b => {}",
			nu_quote("plain"),
			nu_quote("a\"b"),
			nu_quote("a\\b")
		);
		insta::assert_snapshot!(snapshot);
	}

	#[test]
	fn dotenv_escapes_special_characters() {
		let snapshot = format!(
			"plain => {}\na\"b => {}\na\\b => {}\nmulti-line => {}\ncrlf => {}",
			dotenv_quote("plain"),
			dotenv_quote("a\"b"),
			dotenv_quote("a\\b"),
			dotenv_quote("multi\nline"),
			dotenv_quote("crlf\r\n")
		);
		insta::assert_snapshot!(snapshot);
	}

	#[test]
	fn render_bash_emits_exports() {
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		insta::assert_snapshot!(render(Shell::Bash, &pairs));
	}

	#[test]
	fn render_fish_emits_set_gx() {
		let pairs = [("API_KEY".to_string(), "secret value".to_string())];
		insta::assert_snapshot!(render(Shell::Fish, &pairs));
	}

	#[test]
	fn render_powershell_emits_env_assignments() {
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		insta::assert_snapshot!(render(Shell::Powershell, &pairs));
	}

	#[test]
	fn render_nushell_emits_load_env_record() {
		let pairs = [
			("API_KEY".to_string(), "secret".to_string()),
			("DB_URL".to_string(), "postgres://localhost".to_string()),
		];
		insta::assert_snapshot!(render(Shell::Nushell, &pairs));
	}

	#[test]
	fn render_dotenv_and_gitlab_match() {
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		insta::assert_snapshot!("render_dotenv", render(Shell::Dotenv, &pairs));
		insta::assert_snapshot!("render_gitlab", render(Shell::Gitlab, &pairs));
	}

	#[test]
	fn render_github_uses_heredoc_blocks() {
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		insta::assert_snapshot!(render(Shell::Github, &pairs));
	}

	#[test]
	fn github_delimiter_avoids_value_collisions() {
		assert_eq!(github_delimiter("plain"), "__MONOSECRET_ENV_EOF__");
		let collision = "__MONOSECRET_ENV_EOF__";
		let d = github_delimiter(collision);
		assert!(!collision.contains(&d));
		assert!(!d.is_empty());
	}

	#[test]
	fn github_multiline_value_uses_heredoc() {
		let pairs = [("KEY".to_string(), "line1\nline2".to_string())];
		insta::assert_snapshot!(render(Shell::Github, &pairs));
	}

	#[test]
	fn emit_to_output_file_writes_render() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("env.sh");
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		emit(Shell::Bash, &pairs, Some(&path)).unwrap();
		insta::assert_snapshot!(std::fs::read_to_string(&path).unwrap());
	}

	#[test]
	fn emit_github_without_env_or_output_errors() {
		unsafe {
			std::env::remove_var("GITHUB_ENV");
		}
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		let err = emit(Shell::Github, &pairs, None).unwrap_err();
		assert!(err.to_string().contains("$GITHUB_ENV"));
	}

	#[test]
	fn emit_github_appends_to_output_and_masks() {
		// Use --output so this does not depend on a real $GITHUB_ENV.
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("gh_env");
		let pairs = [
			("API_KEY".to_string(), "secret".to_string()),
			("DB".to_string(), "multi\nline".to_string()),
		];
		emit(Shell::Github, &pairs, Some(&path)).unwrap();
		insta::assert_snapshot!(std::fs::read_to_string(&path).unwrap());
	}

	#[test]
	fn emit_to_stdout_writes_rendered_dotenv() {
		// Exercises the stdout branch of `emit` (the else path when no --output is
		// given). We can't capture stdout in a unit test, but executing the code
		// path is enough for line coverage; the rendered output is already verified
		// by `render_dotenv_and_gitlab_match`.
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		emit(Shell::Dotenv, &pairs, None).unwrap();
	}

	#[test]
	fn emit_to_output_file_errors_when_parent_dir_missing() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("nonexistent_dir").join("env.sh");
		let pairs = [("API_KEY".to_string(), "secret".to_string())];
		let err = emit(Shell::Bash, &pairs, Some(&path)).unwrap_err();
		assert!(err.to_string().contains("Failed to create"), "{err}");
	}
}

//! Validates TOML snippets embedded in the documentation so the reference
//! examples can't silently drift from the `Config`/`GlobalConfig` schemas.
//!
//! Opt in a fenced snippet by placing an HTML-comment marker on the line
//! immediately above the fence:
//!
//! ````markdown
//! <!-- monosecret-test: validate -->
//! ```toml
//! [project]
//! name = "myapp"
//! revision = "1.0"
//! ...
//! ```
//! ````
//!
//! The marker is invisible in rendered docs (HTML comments are stripped) and
//! doesn't pollute copied snippets. Supported kinds:
//!
//! - `full` (default) — snippet parses as a complete [`Config`].
//! - `validate` — snippet parses as a [`Config`] and passes [`Config::validate`]
//!   (use for complete configs with `[project]` and at least one profile).
//! - `providers` — snippet is a `[providers]`-only block; it is wrapped with a
//!   minimal `[project]` table and parsed as a [`Config`]. Use this for
//!   provider-reference snippets that omit the project/profile boilerplate.
//! - `project` — snippet is a `[project]`-only block; parsed as a [`Project`].
//! - `global` — snippet parses as a [`GlobalConfig`]
//!   (`~/.config/monosecret/config.toml` shape).
//!
//! Unmarked fences are not tested, which keeps partial/illustrative snippets
//! from producing false positives. The harness reports the file path, line
//! number, and parse error for every failure.

// The module docs contain markdown fence examples with backticks that clippy's
// doc-markdown lint mis-parses as unbalanced.
#![allow(clippy::doc_markdown)]

use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use monosecret::Config;
use monosecret::GlobalConfig;
use monosecret::Project;
use serde::Deserialize;

/// Wrapper for the `project` marker: a snippet that is a single `[project]` table.
#[derive(Deserialize)]
#[allow(dead_code)]
struct ProjectWrapper {
	project: Project,
}

/// Root of the docs content tree, relative to this crate's manifest dir.
const DOCS_REL: &str = "../../docs/src/content/docs";

#[derive(Debug)]
struct Snippet {
	file: PathBuf,
	line: usize, // 1-based line of the opening fence
	kind: Kind,
	body: String,
}

#[derive(Debug, Clone, Copy)]
enum Kind {
	Full,
	Validate,
	Providers,
	Project,
	Global,
}

fn docs_root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join(DOCS_REL)
}

fn walk(root: &Path, out: &mut Vec<PathBuf>) {
	let Ok(entries) = std::fs::read_dir(root) else {
		return;
	};
	for entry in entries.flatten() {
		let path = entry.path();
		if path.is_dir() {
			walk(&path, out);
		} else if path
			.extension()
			.is_some_and(|ext| ext == "md" || ext == "mdx")
		{
			out.push(path);
		}
	}
}

/// Parse a `<!-- monosecret-test: <kind> -->` marker. Returns `None` for any
/// line that isn't such a marker.
fn marker_kind(line: &str) -> Option<Kind> {
	let trimmed = line.trim();
	let inner = trimmed.strip_prefix("<!--")?.strip_suffix("-->")?.trim();
	let rest = inner.strip_prefix("monosecret-test")?;
	let kind = rest.trim().trim_start_matches(':').trim();
	match kind {
		"" | "full" => Some(Kind::Full),
		"validate" => Some(Kind::Validate),
		"providers" => Some(Kind::Providers),
		"project" => Some(Kind::Project),
		"global" => Some(Kind::Global),
		_ => None,
	}
}

/// Extract every ```toml fenced block that has a `monosecret-test` marker on the
/// line immediately above it.
fn extract_snippets(file: &Path) -> Vec<Snippet> {
	let Ok(content) = std::fs::read_to_string(file) else {
		return Vec::new();
	};
	let lines: Vec<&str> = content.lines().collect();
	let mut snippets = Vec::new();
	for (i, line) in lines.iter().enumerate() {
		let trimmed = line.trim_start();
		if !trimmed.starts_with("```") {
			continue;
		}
		let info = trimmed.trim_start_matches('`').trim();
		if !info.starts_with("toml") {
			continue;
		}
		// Look at the closest preceding non-empty line for the marker.
		let mut marker = None;
		for prev in lines.get(..i).unwrap_or(&[]).iter().rev() {
			if prev.trim().is_empty() {
				continue;
			}
			marker = marker_kind(prev);
			break;
		}
		let Some(kind) = marker else {
			continue;
		};

		let start_line = i + 1;
		let mut body = String::new();
		let mut closed = false;
		for body_line in lines.get(i + 1..).unwrap_or(&[]) {
			if body_line.trim_start().starts_with("```") {
				closed = true;
				break;
			}
			body.push_str(body_line);
			body.push('\n');
		}
		if !closed {
			continue;
		}
		snippets.push(Snippet {
			file: file.to_path_buf(),
			line: start_line,
			kind,
			body,
		});
	}
	snippets
}

fn validate_snippet(snippet: &Snippet) -> Result<(), String> {
	match snippet.kind {
		Kind::Full => {
			Config::from_str(&snippet.body)
				.map(|_| ())
				.map_err(|e| format!("parse Config: {e}"))
		}
		Kind::Validate => {
			Config::from_str(&snippet.body)
				.map_err(|e| format!("parse Config: {e}"))
				.and_then(|c| c.validate().map_err(|e| format!("validate: {e}")))
		}
		Kind::Providers => {
			let wrapped =
				"[project]\nname = \"docs\"\nrevision = \"1.0\"\n\n".to_string() + &snippet.body;
			Config::from_str(&wrapped)
				.map(|_| ())
				.map_err(|e| format!("parse Config (wrapped): {e}"))
		}
		Kind::Project => {
			toml::from_str::<ProjectWrapper>(&snippet.body)
				.map(|_| ())
				.map_err(|e| format!("parse Project: {e}"))
		}
		Kind::Global => {
			toml::from_str::<GlobalConfig>(&snippet.body)
				.map(|_| ())
				.map_err(|e| format!("parse GlobalConfig: {e}"))
		}
	}
}

#[test]
fn docs_toml_snippets_are_valid() {
	let root = docs_root();
	if !root.exists() {
		// The crate can be built outside the monorepo (e.g. from crates.io);
		// skip rather than fail when the docs tree isn't present.
		eprintln!("docs tree not found at {}, skipping", root.display());
		return;
	}

	let mut files = Vec::new();
	walk(&root, &mut files);
	files.sort();

	let mut tested = 0usize;
	let mut failures: Vec<String> = Vec::new();
	for file in &files {
		for snippet in extract_snippets(file) {
			tested += 1;
			if let Err(err) = validate_snippet(&snippet) {
				failures.push(format!(
					"{}:{} ({}) — {}",
					snippet
						.file
						.strip_prefix(&root)
						.unwrap_or(&snippet.file)
						.display(),
					snippet.line,
					match snippet.kind {
						Kind::Full => "full",
						Kind::Validate => "validate",
						Kind::Providers => "providers",
						Kind::Project => "project",
						Kind::Global => "global",
					},
					err
				));
			}
		}
	}

	assert!(
		tested > 0,
		"no `<!-- monosecret-test: ... -->`-marked TOML snippets were found under {}; \
		 the docs test harness is a no-op. Mark at least one snippet with a preceding \
		 `<!-- monosecret-test: full|validate|providers|project|global -->` line.",
		root.display()
	);

	assert!(
		failures.is_empty(),
		"{} docs TOML snippet(s) failed to parse/validate:\n{}\n\
		 Fix the snippet or adjust its `monosecret-test` marker. See the module docs in \
		 `crates/monosecret/tests/docs_snippets.rs` for the marker syntax.",
		failures.len(),
		failures
			.iter()
			.map(|f| format!("  - {f}"))
			.collect::<Vec<_>>()
			.join("\n")
	);
}

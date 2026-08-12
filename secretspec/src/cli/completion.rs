use super::{Cli, CompletionShell};
use crate::provider::providers as registered_providers;
use crate::{Config, GlobalConfig};
use clap::CommandFactory;
use clap::builder::StyledStr;
use clap_complete::engine::{CompletionCandidate, PathCompleter, ValueCompleter};
use clap_complete::env::{Bash, Elvish, EnvCompleter, Fish, Powershell, Shells, Zsh};
use is_executable::IsExecutable;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const COMPLETE_VAR: &str = "SECRETSPEC_COMPLETE";
static CONTEXT: OnceLock<CompletionContext> = OnceLock::new();

struct CompletionContext {
    config: Option<Config>,
    global: Option<GlobalConfig>,
    profile: String,
}

impl CompletionContext {
    fn load(args: &[OsString], current_dir: &Path) -> Self {
        let words = completion_words(args);
        let explicit_file = argument_value(words, "--file", "-f").map(PathBuf::from);
        let env_file = std::env::var_os("SECRETSPEC_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let path = explicit_file
            .or(env_file)
            .map(|path| {
                if path.is_relative() {
                    current_dir.join(path)
                } else {
                    path
                }
            })
            .or_else(|| find_manifest(current_dir));
        let config = path
            .as_deref()
            .and_then(|path| Config::try_from(path).ok())
            .filter(|config| config.validate().is_ok());
        let global = GlobalConfig::load().ok().flatten();
        let profile = argument_value(words, "--profile", "-P")
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                std::env::var("SECRETSPEC_PROFILE")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            })
            .or_else(|| {
                global
                    .as_ref()
                    .and_then(|config| config.defaults.profile.clone())
            })
            .unwrap_or_else(|| "default".to_string());

        Self {
            config,
            global,
            profile,
        }
    }
}

fn completion_words(args: &[OsString]) -> &[OsString] {
    args.iter()
        .position(|word| word == "--")
        .map_or(args, |index| &args[index + 1..])
}

fn argument_value(args: &[OsString], long: &str, short: &str) -> Option<OsString> {
    let mut value = None;
    let mut words = args.iter().skip(1);
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        if word == long || word == short {
            value = words.next().cloned();
            continue;
        }
        if let Some(word) = word.to_str() {
            if let Some(attached) = word.strip_prefix(&format!("{long}=")) {
                value = Some(attached.into());
            } else if let Some(attached) = word.strip_prefix(short)
                && !attached.is_empty()
            {
                value = Some(attached.into());
            }
        }
    }
    value
}

fn find_manifest(start: &Path) -> Option<PathBuf> {
    let mut directory = start.to_path_buf();
    loop {
        let candidate = directory.join("secretspec.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !directory.pop() {
            return None;
        }
    }
}

fn candidate(value: impl Into<OsString>, help: impl Into<String>) -> CompletionCandidate {
    let help = help.into().split_whitespace().collect::<Vec<_>>().join(" ");
    CompletionCandidate::new(value).help((!help.is_empty()).then(|| StyledStr::from(help)))
}

fn matching(
    current: &OsStr,
    candidates: impl IntoIterator<Item = CompletionCandidate>,
) -> Vec<CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
    candidates
        .into_iter()
        .filter(|candidate| candidate.get_value().to_string_lossy().starts_with(current))
        .collect()
}

pub(super) struct RunCompleter;

impl ValueCompleter for RunCompleter {
    fn complete(&self, current: &OsStr) -> Vec<CompletionCandidate> {
        self.complete_at(0, current)
    }

    fn complete_at(&self, arg_index: usize, current: &OsStr) -> Vec<CompletionCandidate> {
        if arg_index == 0 {
            command_candidates(current, std::env::var_os("PATH").as_deref())
        } else {
            PathCompleter::any().complete(current)
        }
    }
}

fn command_candidates(current: &OsStr, path: Option<&OsStr>) -> Vec<CompletionCandidate> {
    let current_path = Path::new(current);
    if current_path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return PathCompleter::any()
            .filter(|path| path.is_executable())
            .complete(current);
    }

    let mut commands = BTreeMap::new();
    for directory in path.into_iter().flat_map(std::env::split_paths) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_executable() {
                commands
                    .entry(entry.file_name())
                    .or_insert_with(|| path.display().to_string());
            }
        }
    }
    matching(
        current,
        commands
            .into_iter()
            .map(|(name, path)| candidate(name, path)),
    )
}

pub(super) fn profiles(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, profile_candidates(CONTEXT.get(), false))
}

pub(super) fn profiles_or_none(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, profile_candidates(CONTEXT.get(), true))
}

fn profile_candidates(
    context: Option<&CompletionContext>,
    include_none: bool,
) -> Vec<CompletionCandidate> {
    let mut candidates = BTreeMap::new();
    if include_none {
        candidates.insert("none", "Clear the configured default profile");
    }
    if let Some(config) = context.and_then(|context| context.config.as_ref()) {
        for name in config.profiles.keys() {
            candidates.insert(name, "Manifest profile");
        }
    }
    candidates
        .into_iter()
        .map(|(name, help)| candidate(name, help))
        .collect()
}

pub(super) fn scopes(current: &OsStr) -> Vec<CompletionCandidate> {
    let mut candidates: Vec<_> = CONTEXT
        .get()
        .and_then(|context| context.config.as_ref())
        .and_then(|config| config.scopes.as_ref())
        .into_iter()
        .flat_map(|scopes| scopes.keys())
        .map(|name| candidate(name, "Manifest scope"))
        .collect();
    candidates.sort();
    matching(current, candidates)
}

pub(super) fn secrets(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, secret_candidates(CONTEXT.get()))
}

fn secret_candidates(context: Option<&CompletionContext>) -> Vec<CompletionCandidate> {
    let Some(context) = context else {
        return Vec::new();
    };
    let Some(config) = &context.config else {
        return Vec::new();
    };
    let Some(profile) = config.profiles.get(&context.profile) else {
        return Vec::new();
    };

    let mut secrets = BTreeMap::new();
    if context.profile != "default"
        && profile.inherits_default()
        && let Some(default) = config.profiles.get("default")
    {
        secrets.extend(&default.secrets);
    }
    secrets.extend(&profile.secrets);
    secrets
        .into_iter()
        .map(|(name, config)| candidate(name, config.description.as_deref().unwrap_or("Secret")))
        .collect()
}

pub(super) fn providers(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, provider_candidates(CONTEXT.get(), true))
}

pub(super) fn provider_aliases(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, provider_candidates(CONTEXT.get(), false))
}

fn provider_candidates(
    context: Option<&CompletionContext>,
    include_registered: bool,
) -> Vec<CompletionCandidate> {
    let mut candidates = BTreeMap::new();
    if include_registered {
        for provider in registered_providers() {
            candidates.insert(provider.name.to_string(), provider.description.to_string());
        }
    }
    if let Some(context) = context {
        if let Some(aliases) = context
            .global
            .as_ref()
            .and_then(|global| global.defaults.providers.as_ref())
        {
            for name in aliases.keys() {
                candidates.insert(name.clone(), "User provider alias".to_string());
            }
        }
        if let Some(aliases) = context
            .config
            .as_ref()
            .and_then(|config| config.providers.as_ref())
        {
            for name in aliases.keys() {
                candidates.insert(name.clone(), "Project provider alias".to_string());
            }
        }
    }
    candidates
        .into_iter()
        .map(|(name, help)| candidate(name, help))
        .collect()
}

pub(super) fn complete() {
    let Some(shell) = std::env::var_os(COMPLETE_VAR) else {
        return;
    };
    if shell.is_empty() || shell == "0" {
        return;
    }
    let args: Vec<OsString> = std::env::args_os().collect();
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let _ = CONTEXT.set(CompletionContext::load(&args, &current_dir));
    let nushell = Nushell;
    let shells: [&dyn EnvCompleter; 6] = [&Bash, &Elvish, &Fish, &nushell, &Powershell, &Zsh];
    clap_complete::CompleteEnv::with_factory(Cli::command)
        .var(COMPLETE_VAR)
        .shells(Shells(&shells))
        .complete();
}

pub(super) fn generate(shell: CompletionShell, output: &mut dyn io::Write) -> io::Result<()> {
    match shell {
        CompletionShell::Bash => registration(&Bash, output),
        CompletionShell::Elvish => registration(&Elvish, output),
        CompletionShell::Fish => registration(&Fish, output),
        CompletionShell::Nushell => generate_nushell(output),
        CompletionShell::PowerShell => registration(&Powershell, output),
        CompletionShell::Zsh => registration(&Zsh, output),
    }
}

fn registration(shell: &dyn EnvCompleter, output: &mut dyn io::Write) -> io::Result<()> {
    shell.write_registration(
        COMPLETE_VAR,
        "secretspec",
        "secretspec",
        "secretspec",
        output,
    )
}

fn generate_nushell(output: &mut dyn io::Write) -> io::Result<()> {
    let mut command = Cli::command();
    let mut generated = Vec::new();
    clap_complete::generate(
        clap_complete_nushell::Nushell,
        &mut command,
        "secretspec",
        &mut generated,
    );
    let generated = String::from_utf8(generated).map_err(io::Error::other)?;
    let completer = r#"module completions {

  def "nu-complete secretspec" [spans: list<string>] {
    with-env { SECRETSPEC_COMPLETE: nushell } {
      ^secretspec -- ...$spans
    } | from json
  }
"#;
    let generated = generated
        .replacen("module completions {\n", completer, 1)
        .replace(
            "  export extern ",
            "  @complete 'nu-complete secretspec'\n  export extern ",
        );
    output.write_all(generated.as_bytes())
}

struct Nushell;

impl EnvCompleter for Nushell {
    fn name(&self) -> &'static str {
        "nushell"
    }

    fn is(&self, name: &str) -> bool {
        matches!(name, "nu" | "nushell")
    }

    fn write_registration(
        &self,
        _var: &str,
        _name: &str,
        _bin: &str,
        _completer: &str,
        _buf: &mut dyn io::Write,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "Nushell registration is generated as a module",
        ))
    }

    fn write_complete(
        &self,
        command: &mut clap::Command,
        mut args: Vec<OsString>,
        current_dir: Option<&Path>,
        output: &mut dyn io::Write,
    ) -> io::Result<()> {
        if args.is_empty() {
            args.push(OsString::new());
        }
        let index = args.len() - 1;
        let completions = clap_complete::engine::complete(command, args, index, current_dir)?;
        let completions: Vec<_> = completions
            .into_iter()
            .map(|candidate| {
                serde_json::json!({
                    "value": candidate.get_value().to_string_lossy(),
                    "description": candidate.get_help().map(ToString::to_string).unwrap_or_default(),
                })
            })
            .collect();
        serde_json::to_writer(output, &completions).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, CompletionContext) {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("secretspec.toml"),
            r#"
[project]
name = "completion-test"
revision = "1.0"

[providers]
team = "keyring://"

[scopes.api]
secrets = ["API_KEY"]

[profiles.default]
API_KEY = { description = "API token" }

[profiles.production]
DATABASE_URL = { description = "Production database" }
"#,
        )
        .unwrap();
        let args = [
            OsString::from("secretspec"),
            OsString::from("get"),
            OsString::from("--profile"),
            OsString::from("production"),
        ];
        let context = CompletionContext::load(&args, directory.path());
        (directory, context)
    }

    fn values(candidates: Vec<CompletionCandidate>) -> Vec<String> {
        candidates
            .into_iter()
            .map(|candidate| candidate.get_value().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn context_reads_the_nearest_manifest_and_explicit_profile() {
        let (_directory, context) = fixture();
        assert_eq!(context.profile, "production");
        assert!(context.config.is_some());
    }

    #[test]
    fn secret_candidates_include_inherited_declarations_and_descriptions() {
        let (_directory, context) = fixture();
        let candidates = secret_candidates(Some(&context));
        assert_eq!(values(candidates), ["API_KEY", "DATABASE_URL"]);
    }

    #[test]
    fn profile_candidates_are_sorted_and_can_include_the_clear_value() {
        let (_directory, context) = fixture();
        assert_eq!(
            values(profile_candidates(Some(&context), true)),
            ["default", "none", "production"]
        );
    }

    #[test]
    fn provider_candidates_combine_registered_and_project_aliases() {
        let (_directory, context) = fixture();
        let candidates = values(provider_candidates(Some(&context), true));
        assert!(candidates.contains(&"keyring".to_string()));
        assert!(candidates.contains(&"team".to_string()));
    }

    #[test]
    fn malformed_or_missing_manifests_produce_no_project_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let context = CompletionContext::load(&[OsString::from("secretspec")], directory.path());
        assert!(context.config.is_none());
        assert!(secret_candidates(Some(&context)).is_empty());
    }

    #[test]
    fn generated_nushell_module_delegates_to_the_dynamic_engine() {
        let mut output = Vec::new();
        generate_nushell(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("SECRETSPEC_COMPLETE: nushell"));
        assert!(output.contains("@complete 'nu-complete secretspec'"));
        assert!(output.contains("export extern secretspec"));
    }

    #[test]
    fn dynamic_engine_keeps_command_descriptions() {
        let mut command = Cli::command();
        let candidates = clap_complete::engine::complete(
            &mut command,
            vec![OsString::from("secretspec"), OsString::from("c")],
            1,
            None,
        )
        .unwrap();
        let config = candidates
            .iter()
            .find(|candidate| candidate.get_value() == "config")
            .unwrap();
        assert_eq!(
            config.get_help().map(ToString::to_string).as_deref(),
            Some("Manage SecretSpec configuration")
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_completer_finds_executables_on_path() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("deploy-tool");
        let regular_file = directory.path().join("deploy-notes");
        fs::write(&executable, "").unwrap();
        fs::write(&regular_file, "").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            values(command_candidates(
                OsStr::new("deploy-"),
                Some(directory.path().as_os_str())
            )),
            ["deploy-tool"]
        );
    }
}

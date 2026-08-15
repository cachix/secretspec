use super::{Cli, CompletionShell};
use crate::manifest::CompiledManifest;
use crate::provider::providers as registered_providers;
use crate::{Config, GlobalConfig};
use clap::builder::StyledStr;
use clap::{ArgMatches, CommandFactory};
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
    manifest: Option<CompiledManifest>,
    global: Option<GlobalConfig>,
    profile: String,
}

impl CompletionContext {
    fn load(args: &[OsString], current_dir: &Path) -> Self {
        let words = completion_words(args);
        let matches = Cli::command()
            .ignore_errors(true)
            .try_get_matches_from(words)
            .ok();
        let path = matches
            .as_ref()
            .and_then(|matches| {
                matches
                    .try_get_one::<PathBuf>("file")
                    .ok()
                    .flatten()
                    .cloned()
            })
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| {
                if path.is_relative() {
                    current_dir.join(path)
                } else {
                    path
                }
            })
            .or_else(|| find_manifest(current_dir));
        let loaded = path
            .as_deref()
            .and_then(|path| Config::try_from(path).ok())
            .and_then(|config| {
                config
                    .validate_and_compile()
                    .ok()
                    .map(|manifest| (config, manifest))
            });
        let (config, manifest) = loaded.unzip();
        let global = load_global_config();
        let profile = matches
            .as_ref()
            .and_then(profile_value)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                global
                    .as_ref()
                    .and_then(|config| config.defaults.profile.clone())
            })
            .unwrap_or_else(|| "default".to_string());

        Self {
            config,
            manifest,
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

fn profile_value(matches: &ArgMatches) -> Option<String> {
    matches
        .try_get_one::<String>("profile")
        .ok()
        .flatten()
        .cloned()
        .or_else(|| {
            matches
                .subcommand()
                .and_then(|(_, matches)| profile_value(matches))
        })
}

fn load_global_config() -> Option<GlobalConfig> {
    let path = GlobalConfig::path().ok()?;
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
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
        commands.into_iter().map(|(name, path)| {
            let hidden = name.as_os_str().as_encoded_bytes().starts_with(b".");
            candidate(name, path).hide(hidden)
        }),
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
    matching(current, scope_candidates(CONTEXT.get()))
}

fn scope_candidates(context: Option<&CompletionContext>) -> Vec<CompletionCandidate> {
    let mut candidates: Vec<_> = context
        .and_then(|context| context.config.as_ref())
        .and_then(|config| config.scopes.as_ref())
        .into_iter()
        .flat_map(|scopes| scopes.keys())
        .map(|name| candidate(name, "Manifest scope"))
        .collect();
    candidates.sort();
    candidates
}

pub(super) fn secrets(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, secret_candidates(CONTEXT.get()))
}

fn secret_candidates(context: Option<&CompletionContext>) -> Vec<CompletionCandidate> {
    let Some(context) = context else {
        return Vec::new();
    };
    let Some(manifest) = &context.manifest else {
        return Vec::new();
    };
    let Some(profile) = manifest.profiles.get(&context.profile) else {
        return Vec::new();
    };

    profile
        .secrets
        .iter()
        .map(|(name, secret)| {
            candidate(
                name,
                secret.config.description.as_deref().unwrap_or("Secret"),
            )
        })
        .collect()
}

pub(super) fn providers(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, provider_candidates(CONTEXT.get()))
}

pub(super) fn provider_aliases(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, provider_alias_candidates(CONTEXT.get(), true))
}

pub(super) fn global_provider_aliases(current: &OsStr) -> Vec<CompletionCandidate> {
    matching(current, provider_alias_candidates(CONTEXT.get(), false))
}

fn provider_candidates(context: Option<&CompletionContext>) -> Vec<CompletionCandidate> {
    let mut candidates = BTreeMap::new();
    for provider in registered_providers() {
        candidates.insert(provider.name.to_string(), provider.description.to_string());
    }
    candidates.extend(provider_alias_map(context, true));
    candidates
        .into_iter()
        .map(|(name, help)| candidate(name, help))
        .collect()
}

fn provider_alias_candidates(
    context: Option<&CompletionContext>,
    include_project: bool,
) -> Vec<CompletionCandidate> {
    provider_alias_map(context, include_project)
        .into_iter()
        .map(|(name, help)| candidate(name, help))
        .collect()
}

fn provider_alias_map(
    context: Option<&CompletionContext>,
    include_project: bool,
) -> BTreeMap<String, String> {
    let mut candidates = BTreeMap::new();
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
        if include_project
            && let Some(aliases) = context
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

[scopes.worker]
secrets = ["API_KEY"]

[profiles.default]
API_KEY = { description = "API token" }

[profiles.production]
API_KEY = { required = false }
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

    fn help(candidates: &[CompletionCandidate], value: &str) -> Option<String> {
        candidates
            .iter()
            .find(|candidate| candidate.get_value() == value)
            .and_then(CompletionCandidate::get_help)
            .map(ToString::to_string)
    }

    #[test]
    fn context_reads_the_nearest_manifest_and_explicit_profile() {
        let (_directory, context) = fixture();
        assert_eq!(context.profile, "production");
        assert!(context.config.is_some());
        assert!(context.manifest.is_some());
    }

    #[test]
    fn context_resolves_an_explicit_manifest_from_the_current_directory() {
        let (directory, _) = fixture();
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let selected = fs::read_to_string(directory.path().join("secretspec.toml"))
            .unwrap()
            .replace("completion-test", "selected-manifest");
        fs::write(directory.path().join("selected.toml"), selected).unwrap();
        let args = [
            OsString::from("secretspec"),
            OsString::from("--file"),
            OsString::from("../selected.toml"),
            OsString::from("get"),
            OsString::from("API_KEY"),
        ];
        let context = CompletionContext::load(&args, &nested);
        assert_eq!(
            context
                .config
                .as_ref()
                .map(|config| config.project.name.as_str()),
            Some("selected-manifest")
        );
    }

    #[test]
    fn secret_candidates_include_inherited_declarations_and_descriptions() {
        let (_directory, context) = fixture();
        let candidates = secret_candidates(Some(&context));
        assert_eq!(help(&candidates, "API_KEY").as_deref(), Some("API token"));
        assert_eq!(values(candidates), ["API_KEY", "DATABASE_URL"]);
    }

    #[test]
    fn context_does_not_parse_child_command_options() {
        let (directory, _) = fixture();
        let args = [
            OsString::from("secretspec"),
            OsString::from("run"),
            OsString::from("--profile"),
            OsString::from("production"),
            OsString::from("deploy"),
            OsString::from("--profile"),
            OsString::from("child-profile"),
        ];
        let context = CompletionContext::load(&args, directory.path());
        assert_eq!(context.profile, "production");
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
    fn provider_candidates_combine_registered_and_both_alias_scopes() {
        let (_directory, mut context) = fixture();
        context.global = Some(
            toml::from_str(
                r#"
[defaults.providers]
personal = "keyring://"
"#,
            )
            .unwrap(),
        );
        let candidates = values(provider_candidates(Some(&context)));
        assert!(candidates.contains(&"keyring".to_string()));
        assert!(candidates.contains(&"personal".to_string()));
        assert!(candidates.contains(&"team".to_string()));

        assert_eq!(
            values(provider_alias_candidates(Some(&context), false)),
            ["personal"]
        );
        assert_eq!(
            values(provider_alias_candidates(Some(&context), true)),
            ["personal", "team"]
        );
    }

    #[test]
    fn malformed_or_missing_manifests_produce_no_project_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let args = [OsString::from("secretspec")];
        let missing = CompletionContext::load(&args, directory.path());
        assert!(missing.config.is_none());
        assert!(secret_candidates(Some(&missing)).is_empty());

        fs::write(directory.path().join("secretspec.toml"), "not = [valid").unwrap();
        let malformed = CompletionContext::load(&args, directory.path());
        assert!(malformed.config.is_none());
        assert!(secret_candidates(Some(&malformed)).is_empty());
    }

    #[test]
    fn scope_candidates_are_sorted_and_prefix_filtered() {
        let (_directory, context) = fixture();
        assert_eq!(values(scope_candidates(Some(&context))), ["api", "worker"]);
        assert_eq!(
            values(matching(OsStr::new("w"), scope_candidates(Some(&context)))),
            ["worker"]
        );
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
    fn nushell_dynamic_output_preserves_values_and_descriptions() {
        let mut command = Cli::command();
        let mut output = Vec::new();
        Nushell
            .write_complete(
                &mut command,
                vec![OsString::from("secretspec"), OsString::from("c")],
                None,
                &mut output,
            )
            .unwrap();
        let candidates: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let config = candidates
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["value"] == "config")
            .unwrap();
        assert_eq!(config["description"], "Manage SecretSpec configuration");
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
        let hidden = directory.path().join(".deploy-wrapper");
        let regular_file = directory.path().join("deploy-notes");
        fs::write(&executable, "").unwrap();
        fs::write(&hidden, "").unwrap();
        fs::write(&regular_file, "").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&hidden, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            values(command_candidates(
                OsStr::new("deploy-"),
                Some(directory.path().as_os_str())
            )),
            ["deploy-tool"]
        );
        let hidden = command_candidates(OsStr::new(".deploy-"), Some(directory.path().as_os_str()));
        assert_eq!(hidden.len(), 1);
        assert!(hidden[0].is_hide_set());
    }
}

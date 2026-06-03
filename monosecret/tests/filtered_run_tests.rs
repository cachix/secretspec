use std::fs;
use std::process::Command;

use monosecret::Config;
use tempfile::TempDir;

fn bin() -> &'static str {
	env!("CARGO_BIN_EXE_monosecret")
}

fn write_config(dir: &TempDir, content: &str) {
	fs::write(dir.path().join("monosecret.toml"), content).unwrap();
}

fn base_config(dotenv_path: &str) -> String {
	format!(
		r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[groups]
web = "Web application secrets"
worker = "Worker secrets"
admin = "Admin secrets"

[providers]
local = "dotenv://{}"

[profiles.default]
WEB_TOKEN = {{ description = "web token", groups = ["web"], providers = ["local"] }}
WORKER_TOKEN = {{ description = "worker token", groups = ["worker"], providers = ["local"] }}
SHARED_TOKEN = {{ description = "shared token", groups = ["web", "worker"], providers = ["local"] }}
MISSING_REQUIRED = {{ description = "missing", providers = ["local"] }}
"#,
		dotenv_path
	)
}

#[test]
fn run_include_injects_only_selected_secret() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"WEB_TOKEN=web\nWORKER_TOKEN=worker\nSHARED_TOKEN=shared\n",
	)
	.unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"run",
			"--include",
			"WEB_TOKEN",
			"--",
			"sh",
			"-c",
			"printf '%s:%s:%s' \"$WEB_TOKEN\" \"${WORKER_TOKEN-unset}\" \"${MISSING_REQUIRED-unset}\"",
		])
		.output()
		.unwrap();

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "web:unset:unset");
}

#[test]
fn run_group_selects_group_union_and_skips_unselected_required() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"WEB_TOKEN=web\nWORKER_TOKEN=worker\nSHARED_TOKEN=shared\n",
	)
	.unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = Command::new(bin())
        .current_dir(dir.path())
        .args([
            "run",
            "--group",
            "web",
            "--",
            "sh",
            "-c",
            "printf '%s:%s:%s:%s' \"$WEB_TOKEN\" \"$SHARED_TOKEN\" \"${WORKER_TOKEN-unset}\" \"${MISSING_REQUIRED-unset}\"",
        ])
        .output()
        .unwrap();

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"web:shared:unset:unset"
	);
}

#[test]
fn run_include_and_group_are_union_and_comma_aware() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"WEB_TOKEN=web\nWORKER_TOKEN=worker\nSHARED_TOKEN=shared\n",
	)
	.unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = Command::new(bin())
		.current_dir(dir.path())
		.args([
			"run",
			"--include",
			"WORKER_TOKEN,SHARED_TOKEN",
			"--group",
			"web",
			"--",
			"sh",
			"-c",
			"printf '%s:%s:%s' \"$WEB_TOKEN\" \"$WORKER_TOKEN\" \"$SHARED_TOKEN\"",
		])
		.output()
		.unwrap();

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "web:worker:shared");
}

#[test]
fn undeclared_secret_group_is_config_validation_error() {
	let dir = TempDir::new().unwrap();
	write_config(
		&dir,
		r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[groups]
web = "Web application secrets"

[profiles.default]
TOKEN = { description = "token", groups = ["missing"], default = "value" }
"#,
	);

	let config = Config::try_from(dir.path().join("monosecret.toml").as_path()).unwrap();
	let err = config.validate().unwrap_err();
	assert!(
		err.to_string().contains("undeclared group 'missing'"),
		"{err}"
	);
}

#[test]
fn group_membership_inherits_and_profile_groups_replace_default_groups() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "TOKEN=inherited\nOVERRIDE=override\n").unwrap();
	write_config(
		&dir,
		&format!(
			r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[groups]
web = "Web secrets"
worker = "Worker secrets"

[providers]
local = "dotenv://{}"

[profiles.default]
TOKEN = {{ description = "inherited", groups = ["web"], providers = ["local"] }}
OVERRIDE = {{ description = "override", groups = ["web"], providers = ["local"] }}

[profiles.production]
OVERRIDE = {{ groups = ["worker"] }}
"#,
			dotenv.display()
		),
	);

	let output = Command::new(bin())
		.current_dir(dir.path())
		.env("MONOSECRET_PROFILE", "production")
		.args([
			"run",
			"--group",
			"web",
			"--",
			"sh",
			"-c",
			"printf '%s:%s' \"$TOKEN\" \"${OVERRIDE-unset}\"",
		])
		.output()
		.unwrap();

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "inherited:unset");
}

#[test]
fn missing_group_filter_errors() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "WEB_TOKEN=web\n").unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = Command::new(bin())
		.current_dir(dir.path())
		.args(["run", "--group", "admin", "--", "sh", "-c", "true"])
		.output()
		.unwrap();

	assert!(!output.status.success());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(stderr.contains("does not match any secrets"), "{stderr}");
}

fn run_capture(dir: &TempDir, args: &[&str]) -> std::process::Output {
	Command::new(bin())
		.current_dir(dir.path())
		.args(args)
		.output()
		.unwrap()
}

#[test]
fn no_filters_injects_all_defined_secrets() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"WEB_TOKEN=web\nWORKER_TOKEN=worker\nSHARED_TOKEN=shared\nMISSING_REQUIRED=present\n",
	)
	.unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = run_capture(
		&dir,
		&[
			"run",
			"--",
			"sh",
			"-c",
			"printf '%s:%s:%s:%s' \"$WEB_TOKEN\" \"$WORKER_TOKEN\" \"$SHARED_TOKEN\" \"$MISSING_REQUIRED\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"web:worker:shared:present"
	);
}

#[test]
fn repeated_include_and_group_flags_are_union_based() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"WEB_TOKEN=web\nWORKER_TOKEN=worker\nSHARED_TOKEN=shared\n",
	)
	.unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = run_capture(
		&dir,
		&[
			"run",
			"--include",
			"WEB_TOKEN",
			"--include",
			"WORKER_TOKEN",
			"--group",
			"worker",
			"--group",
			"web",
			"--",
			"sh",
			"-c",
			"printf '%s:%s:%s:%s' \"$WEB_TOKEN\" \"$WORKER_TOKEN\" \"$SHARED_TOKEN\" \"${MISSING_REQUIRED-unset}\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"web:worker:shared:unset"
	);
}

#[test]
fn group_flag_accepts_comma_separated_values() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"WEB_TOKEN=web\nWORKER_TOKEN=worker\nSHARED_TOKEN=shared\n",
	)
	.unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = run_capture(
		&dir,
		&[
			"run",
			"--group",
			"web,worker",
			"--",
			"sh",
			"-c",
			"printf '%s:%s:%s' \"$WEB_TOKEN\" \"$WORKER_TOKEN\" \"$SHARED_TOKEN\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "web:worker:shared");
}

#[test]
fn include_unknown_secret_errors_before_running_command() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "WEB_TOKEN=web\n").unwrap();
	write_config(&dir, &base_config(&dotenv.display().to_string()));

	let output = run_capture(
		&dir,
		&[
			"run",
			"--include",
			"DOES_NOT_EXIST",
			"--",
			"sh",
			"-c",
			"echo should-not-run",
		],
	);

	assert!(!output.status.success());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("Included secret 'DOES_NOT_EXIST'"),
		"{stderr}"
	);
	assert!(!String::from_utf8_lossy(&output.stdout).contains("should-not-run"));
}

#[test]
fn group_filter_without_top_level_declaration_errors() {
	let dir = TempDir::new().unwrap();
	write_config(
		&dir,
		r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[profiles.default]
TOKEN = { description = "token", groups = ["web"], default = "value" }
"#,
	);

	let output = run_capture(&dir, &["run", "--group", "web", "--", "sh", "-c", "true"]);

	assert!(!output.status.success());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("top-level [groups] table") || stderr.contains("is not declared"),
		"{stderr}"
	);
}

#[test]
fn selected_optional_missing_secret_does_not_fail_or_inject() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "WEB_TOKEN=web\n").unwrap();
	write_config(
		&dir,
		&format!(
			r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[groups]
optional = "Optional secrets"

[providers]
local = "dotenv://{}"

[profiles.default]
OPTIONAL_TOKEN = {{ description = "optional", required = false, groups = ["optional"], providers = ["local"] }}
REQUIRED_TOKEN = {{ description = "required", providers = ["local"] }}
"#,
			dotenv.display()
		),
	);

	let output = run_capture(
		&dir,
		&[
			"run",
			"--group",
			"optional",
			"--",
			"sh",
			"-c",
			"printf '%s:%s' \"${OPTIONAL_TOKEN-unset}\" \"${REQUIRED_TOKEN-unset}\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "unset:unset");
}

#[test]
fn filtered_run_does_not_evaluate_unselected_broken_provider() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "WEB_TOKEN=web\n").unwrap();
	let missing = dir.path().join("missing.env");
	write_config(
		&dir,
		&format!(
			r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[providers]
local = "dotenv://{}"
broken = "dotenv://{}"

[profiles.default]
WEB_TOKEN = {{ description = "web", providers = ["local"] }}
BROKEN_TOKEN = {{ description = "broken", providers = ["broken"] }}
"#,
			dotenv.display(),
			missing.display()
		),
	);

	let output = run_capture(
		&dir,
		&[
			"run",
			"--include",
			"WEB_TOKEN",
			"--",
			"sh",
			"-c",
			"printf '%s:%s' \"$WEB_TOKEN\" \"${BROKEN_TOKEN-unset}\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "web:unset");
}

#[test]
fn provider_dependencies_are_resolved_but_not_injected_when_unselected() {
	let dir = TempDir::new().unwrap();
	let app_dotenv = dir.path().join("app.env");
	let auth_dotenv = dir.path().join("auth.env");
	fs::write(&app_dotenv, "APP_SECRET=app\n").unwrap();
	fs::write(&auth_dotenv, "PROVIDER_TOKEN=provider-token\n").unwrap();
	write_config(
		&dir,
		&format!(
			r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[providers]
bootstrap = "dotenv://{auth}"

[providers.needs_dep]
uri = "dotenv://{app}"
[[providers.needs_dep.depends_on]]
secret = "PROVIDER_TOKEN"
as = "UPSTREAM_TOKEN"

[profiles.default]
APP_SECRET = {{ description = "app", providers = ["needs_dep"] }}
PROVIDER_TOKEN = {{ description = "provider auth", providers = ["bootstrap"] }}
"#,
			auth = auth_dotenv.display(),
			app = app_dotenv.display()
		),
	);

	let output = run_capture(
		&dir,
		&[
			"run",
			"--include",
			"APP_SECRET",
			"--",
			"sh",
			"-c",
			"printf '%s:%s:%s' \"$APP_SECRET\" \"${PROVIDER_TOKEN-unset}\" \"${UPSTREAM_TOKEN-unset}\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "app:unset:unset");
}

#[test]
fn selected_provider_dependency_secret_is_injected_when_explicitly_included() {
	let dir = TempDir::new().unwrap();
	let app_dotenv = dir.path().join("app.env");
	let auth_dotenv = dir.path().join("auth.env");
	fs::write(&app_dotenv, "APP_SECRET=app\n").unwrap();
	fs::write(&auth_dotenv, "PROVIDER_TOKEN=provider-token\n").unwrap();
	write_config(
		&dir,
		&format!(
			r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[providers]
bootstrap = "dotenv://{auth}"

[providers.needs_dep]
uri = "dotenv://{app}"
[[providers.needs_dep.depends_on]]
secret = "PROVIDER_TOKEN"
as = "UPSTREAM_TOKEN"

[profiles.default]
APP_SECRET = {{ description = "app", providers = ["needs_dep"] }}
PROVIDER_TOKEN = {{ description = "provider auth", providers = ["bootstrap"] }}
"#,
			auth = auth_dotenv.display(),
			app = app_dotenv.display()
		),
	);

	let output = run_capture(
		&dir,
		&[
			"run",
			"--include",
			"APP_SECRET,PROVIDER_TOKEN",
			"--",
			"sh",
			"-c",
			"printf '%s:%s:%s' \"$APP_SECRET\" \"$PROVIDER_TOKEN\" \"${UPSTREAM_TOKEN-unset}\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"app:provider-token:unset"
	);
}

#[test]
fn extends_merges_group_declarations_for_filtered_run() {
	let dir = TempDir::new().unwrap();
	let parent_dir = dir.path().join("shared");
	fs::create_dir_all(&parent_dir).unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "CHILD_TOKEN=child\nPARENT_TOKEN=parent\n").unwrap();

	fs::write(
		parent_dir.join("monosecret.toml"),
		r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[groups]
shared = "Shared inherited group"

[profiles.default]
PARENT_TOKEN = { description = "parent", groups = ["shared"], default = "parent" }
"#,
	)
	.unwrap();

	write_config(
		&dir,
		&format!(
			r#"
[project]
name = "filtered-run-tests"
revision = "1.0"
extends = ["shared"]

[groups]
child = "Child group"

[providers]
local = "dotenv://{}"

[profiles.default]
CHILD_TOKEN = {{ description = "child", groups = ["child"], providers = ["local"] }}
"#,
			dotenv.display()
		),
	);

	let output = run_capture(
		&dir,
		&[
			"run",
			"--group",
			"shared,child",
			"--",
			"sh",
			"-c",
			"printf '%s:%s' \"$PARENT_TOKEN\" \"$CHILD_TOKEN\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(String::from_utf8_lossy(&output.stdout), "parent:child");
}

#[test]
fn config_init_from_dotenv_keeps_group_declarations_empty() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env.seed");
	fs::write(&dotenv, "TOKEN=value\n").unwrap();

	let output = run_capture(
		&dir,
		&["init", "--from", &format!("dotenv://{}", dotenv.display())],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let generated = fs::read_to_string(dir.path().join("monosecret.toml")).unwrap();
	assert!(generated.contains("TOKEN"), "{generated}");
	assert!(!generated.contains("[groups]"), "{generated}");
}

#[test]
fn config_validation_rejects_grouped_secret_without_group_declarations() {
	let dir = TempDir::new().unwrap();
	write_config(
		&dir,
		r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[profiles.default]
TOKEN = { description = "token", groups = ["web"], default = "value" }
"#,
	);

	let config = Config::try_from(dir.path().join("monosecret.toml").as_path()).unwrap();
	let err = config.validate().unwrap_err();
	assert!(
		err.to_string().contains("no top-level [groups] table"),
		"{err}"
	);
}

#[test]
fn profile_defaults_provider_applies_when_profile_secret_overrides_default_secret() {
	let dir = TempDir::new().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "TOKEN=from-profile-default\n").unwrap();
	write_config(
		&dir,
		&format!(
			r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[providers]
local = "dotenv://{}"

[profiles.default]
TOKEN = {{ description = "default token", groups = ["default"] }}

[profiles.staging.defaults]
providers = ["local"]

[profiles.staging]
TOKEN = {{ description = "staging token" }}
"#,
			dotenv.display()
		),
	);

	let output = run_capture(
		&dir,
		&[
			"run",
			"--profile",
			"staging",
			"--include",
			"TOKEN",
			"--",
			"sh",
			"-c",
			"printf '%s' \"$TOKEN\"",
		],
	);

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"from-profile-default"
	);
}

#[test]
fn config_validation_accepts_secret_groups_when_declared() {
	let dir = TempDir::new().unwrap();
	write_config(
		&dir,
		r#"
[project]
name = "filtered-run-tests"
revision = "1.0"

[groups]
web = "Web secrets"

[profiles.default]
TOKEN = { description = "token", groups = ["web"], default = "value" }
"#,
	);

	let config = Config::try_from(dir.path().join("monosecret.toml").as_path()).unwrap();
	config.validate().unwrap();
}

use super::*;

#[test]
fn rejects_path_names() {
    assert!(validate_name("secret", "../TOKEN").is_err());
    assert!(validate_name("secret", "a/b").is_err());
    assert!(validate_name("secret", "TOKEN").is_ok());
}

#[test]
fn parses_octal_modes() {
    assert_eq!(parse_mode("0400").unwrap(), 0o400);
    assert_eq!(parse_mode("0o600").unwrap(), 0o600);
    assert_eq!(parse_mode("600").unwrap(), 0o600);
    assert!(parse_mode("0999").is_err());
}

#[test]
fn renders_placeholders_once() {
    let values = BTreeMap::from([(
        "TOKEN".to_string(),
        SecretBytes::from_utf8("@secretspec:OTHER@"),
    )]);
    let rendered = render_template("token=@secretspec:TOKEN@\n", &values).unwrap();
    assert_eq!(rendered, b"token=@secretspec:OTHER@\n");
}

#[test]
fn rejects_unknown_placeholder() {
    let values = BTreeMap::new();
    assert!(render_template("@secretspec:MISSING@", &values).is_err());
}

#[test]
fn plan_rejects_duplicate_names() {
    let plan = Plan {
        schema: PLAN_SCHEMA,
        manifest: PathBuf::from("/tmp/secretspec.toml"),
        profile: "default".to_string(),
        runtime_dir: PathBuf::from("/run/secretspec"),
        cache_dir: PathBuf::from("/var/lib/secretspec/cache"),
        credentials_dir: PathBuf::from("/var/lib/secretspec/credentials"),
        systemd_creds: None,
        systemctl: None,
        path: String::new(),
        restart_units: true,
        secrets: vec![PlanSecret {
            name: "TOKEN".to_string(),
            owner: "root".to_string(),
            group: "root".to_string(),
            mode: "0400".to_string(),
            cache: true,
            required: true,
            units: Vec::new(),
        }],
        templates: vec![PlanTemplate {
            name: "TOKEN".to_string(),
            content: "x".to_string(),
            owner: "root".to_string(),
            group: "root".to_string(),
            mode: "0400".to_string(),
            units: Vec::new(),
        }],
    };
    assert!(plan.validate().is_err());
}

#[test]
fn nixos_exec_passes_plan_environment_and_reason_to_child() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("secretspec.toml");
    let output = temp.path().join("child-env");
    let plan = Plan {
        schema: PLAN_SCHEMA,
        manifest: manifest.clone(),
        profile: "production".to_string(),
        runtime_dir: temp.path().join("run"),
        cache_dir: temp.path().join("cache"),
        credentials_dir: temp.path().join("credentials"),
        systemd_creds: None,
        systemctl: None,
        path: String::new(),
        restart_units: false,
        secrets: Vec::new(),
        templates: Vec::new(),
    };
    let command = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "printf '%s\\n%s\\n%s' \"$SECRETSPEC_FILE\" \"$SECRETSPEC_PROFILE\" \"$SECRETSPEC_REASON\" > \"$1\"".to_string(),
        "sh".to_string(),
        output.to_string_lossy().into_owned(),
    ];

    exec(&plan, &command, Some("rotate production credential")).unwrap();

    assert_eq!(
        std::fs::read_to_string(output).unwrap(),
        format!(
            "{}\nproduction\nrotate production credential",
            manifest.display()
        )
    );
}

#[test]
fn provider_credentials_are_decrypted_into_a_private_directory() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("run");
    let store = temp.path().join("credentials");
    let cache = temp.path().join("cache");
    create_private_dir(&store).unwrap();
    std::fs::write(store.join("vault.token.cred"), b"provider-token").unwrap();
    let fake_creds = temp.path().join("systemd-creds");
    std::fs::write(
        &fake_creds,
        r#"#!/bin/sh
case "$1" in
  decrypt) cat "$4" ;;
  *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&fake_creds, std::fs::Permissions::from_mode(0o755)).unwrap();
    let plan = Plan {
        schema: PLAN_SCHEMA,
        manifest: temp.path().join("secretspec.toml"),
        profile: "default".to_string(),
        runtime_dir: runtime,
        cache_dir: cache,
        credentials_dir: store,
        systemd_creds: Some(fake_creds),
        systemctl: None,
        path: String::new(),
        restart_units: false,
        secrets: Vec::new(),
        templates: Vec::new(),
    };
    let credentials = ProviderCredentials::prepare(&plan).unwrap();
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY").unwrap();
    assert_eq!(
        std::fs::read(std::path::Path::new(&directory).join("vault.token")).unwrap(),
        b"provider-token"
    );
    drop(credentials);
    assert!(std::env::var_os("CREDENTIALS_DIRECTORY").is_none());
}

#[test]
fn seals_and_decrypts_provider_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let fake_creds = temp.path().join("systemd-creds");
    std::fs::write(
        &fake_creds,
        r#"#!/bin/sh
case "$1" in
  encrypt) cat > "$6" ;;
  decrypt) cat "$4" ;;
  *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&fake_creds, std::fs::Permissions::from_mode(0o755)).unwrap();
    let destination = temp.path().join("vault.token.cred");
    let value = SecretBytes::from_utf8("sealed-value");
    seal_credential(&fake_creds, "vault.token", &value, &destination).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"sealed-value");
    assert_eq!(
        decrypt_file(&fake_creds, &destination)
            .unwrap()
            .expose_secret(),
        b"sealed-value"
    );
}

#[test]
fn seals_credentials_with_the_item_name() {
    let temp = tempfile::tempdir().unwrap();
    let fake_creds = temp.path().join("systemd-creds");
    std::fs::write(
        &fake_creds,
        r#"#!/bin/sh
case "$1" in
  encrypt)
    # The embedded name is the item name, without the .cred suffix.
    printf '%s' "$3" > "$6"
    ;;
  *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&fake_creds, std::fs::Permissions::from_mode(0o755)).unwrap();
    let destination = temp.path().join("vault.token.cred");
    seal_credential(
        &fake_creds,
        "vault.token",
        &SecretBytes::from_utf8("value"),
        &destination,
    )
    .unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"vault.token");
}

#[test]
fn decrypts_credentials_by_the_item_name() {
    let temp = tempfile::tempdir().unwrap();
    let fake_creds = temp.path().join("systemd-creds");
    std::fs::write(
        &fake_creds,
        r#"#!/bin/sh
case "$1" in
  decrypt)
    name="$3"
    file="$4"
    embedded="$(cat "$file")"
    if [ "$name" != "$embedded" ]; then
      echo "Embedded credential name '$embedded' does not match filename '$name', refusing." >&2
      exit 1
    fi
    printf 'legacy-value'
    ;;
  *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&fake_creds, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = temp.path().join("vault.token.cred");
    std::fs::write(&path, b"vault.token").unwrap();
    assert_eq!(
        decrypt_file(&fake_creds, &path).unwrap().expose_secret(),
        b"legacy-value"
    );
}

#[test]
fn decrypts_credentials_sealed_with_the_full_file_name() {
    let temp = tempfile::tempdir().unwrap();
    let fake_creds = temp.path().join("systemd-creds");
    std::fs::write(
        &fake_creds,
        r#"#!/bin/sh
case "$1" in
  decrypt)
    name="$3"
    file="$4"
    embedded="$(cat "$file")"
    if [ "$name" != "$embedded" ]; then
      echo "Embedded credential name '$embedded' does not match filename '$name', refusing." >&2
      exit 1
    fi
    printf 'full-name-value'
    ;;
  *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&fake_creds, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = temp.path().join("vault.token.cred");
    std::fs::write(&path, b"vault.token.cred").unwrap();
    assert_eq!(
        decrypt_file(&fake_creds, &path).unwrap().expose_secret(),
        b"full-name-value"
    );
}

#[test]
fn link_discovers_systemd_credential_sources_without_prompting() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("secretspec.toml");
    std::fs::write(
        &manifest,
        r#"[project]
name = "nixos-link-test"
revision = "1.0"
require_reason = false

[providers]
bootstrap = "systemd-credential://"

[providers.vault]
uri = "openbao://bao.example.com:8200/secret"
credentials = { token = { provider = "bootstrap", ref = { item = "vault.token" } } }

[profiles.default]
TOKEN = { description = "test", providers = ["vault"] }
"#,
    )
    .unwrap();
    let store = temp.path().join("credentials");
    create_private_dir(&store).unwrap();
    std::fs::write(store.join("vault.token.cred"), b"already-sealed").unwrap();

    let secrets = Secrets::load_from(&manifest).unwrap();
    let report = link(&secrets, &store, false, None).unwrap();
    assert_eq!(report.skipped, vec!["vault.token".to_string()]);
    assert!(report.sealed.is_empty());
}

#[test]
fn link_deduplicates_shared_credential_items() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("secretspec.toml");
    std::fs::write(
        &manifest,
        r#"[project]
name = "nixos-link-dedupe-test"
revision = "1.0"
require_reason = false

[providers]
bootstrap = "systemd-credential://"

[providers.one]
uri = "bws://project-one"
credentials = { access_token = { provider = "bootstrap", ref = { item = "shared.token" } } }

[providers.two]
uri = "bws://project-two"
credentials = { access_token = { provider = "bootstrap", ref = { item = "shared.token" } } }

[profiles.default]
TOKEN = { description = "test", providers = ["one", "two"] }
"#,
    )
    .unwrap();
    let store = temp.path().join("credentials");
    create_private_dir(&store).unwrap();
    std::fs::write(store.join("shared.token.cred"), b"already-sealed").unwrap();

    let secrets = Secrets::load_from(&manifest).unwrap();
    let report = link(&secrets, &store, false, None).unwrap();
    assert_eq!(report.skipped, vec!["shared.token".to_string()]);
    assert!(report.sealed.is_empty());
}

#[test]
fn restart_requests_run_after_the_new_generation_is_published() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("run");
    let manifest = temp.path().join("secretspec.toml");
    let fake_creds = temp.path().join("systemd-creds");
    let fake_systemctl = temp.path().join("systemctl");
    std::fs::write(
        &manifest,
        r#"[project]
name = "nixos-restart-test"
revision = "1.0"
require_reason = false

[providers]
env = "env://"

[profiles.default]
RESTART_TEST_SECRET = { description = "test", providers = ["env"] }
"#,
    )
    .unwrap();
    std::fs::write(
        &fake_creds,
        r#"#!/bin/sh
case "$1" in
  encrypt) cat > "$6" ;;
  decrypt) cat "$4" ;;
  *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    std::fs::write(
        &fake_systemctl,
        format!(
            "#!/bin/sh\ncat '{}/current/secrets/RESTART_TEST_SECRET' > '{}/restart-observed'\n",
            runtime.display(),
            runtime.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_creds, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&fake_systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let plan = Plan {
        schema: PLAN_SCHEMA,
        manifest,
        profile: "default".to_string(),
        runtime_dir: runtime.clone(),
        cache_dir: temp.path().join("cache"),
        credentials_dir: temp.path().join("credentials"),
        systemd_creds: Some(fake_creds),
        systemctl: Some(fake_systemctl),
        path: String::new(),
        restart_units: true,
        secrets: vec![PlanSecret {
            name: "RESTART_TEST_SECRET".to_string(),
            owner: uid.to_string(),
            group: gid.to_string(),
            mode: "0400".to_string(),
            cache: false,
            required: true,
            units: vec!["demo.service".to_string()],
        }],
        templates: Vec::new(),
    };
    unsafe { std::env::set_var("RESTART_TEST_SECRET", "new-value") };
    let report = refresh(&plan, false, false, None, None).unwrap();
    assert_eq!(report.restarted_units, vec!["demo.service".to_string()]);
    assert_eq!(
        std::fs::read_to_string(runtime.join("restart-observed")).unwrap(),
        "new-value"
    );
}

#[test]
fn refresh_writes_runtime_files_and_falls_back_to_cache() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("run");
    let cache = temp.path().join("cache");
    let credentials = temp.path().join("credentials");
    let manifest = temp.path().join("secretspec.toml");
    let fake_creds = temp.path().join("systemd-creds");
    std::fs::write(
        &manifest,
        r#"[project]
name = "nixos-test"
revision = "1.0"
require_reason = false

[providers]
env = "env://"

[profiles.default]
NIXOS_TEST_SECRET = { description = "test", providers = ["env"] }
"#,
    )
    .unwrap();
    std::fs::write(
        &fake_creds,
        r#"#!/bin/sh
case "$1" in
  encrypt) cat > "$6" ;;
  decrypt) cat "$4" ;;
  *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&fake_creds, std::fs::Permissions::from_mode(0o755)).unwrap();

    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let plan = Plan {
        schema: PLAN_SCHEMA,
        manifest,
        profile: "default".to_string(),
        runtime_dir: runtime.clone(),
        cache_dir: cache,
        credentials_dir: credentials,
        systemd_creds: Some(fake_creds),
        systemctl: None,
        path: String::new(),
        restart_units: false,
        secrets: vec![PlanSecret {
            name: "NIXOS_TEST_SECRET".to_string(),
            owner: uid.to_string(),
            group: gid.to_string(),
            mode: "0400".to_string(),
            cache: true,
            required: true,
            units: Vec::new(),
        }],
        templates: vec![PlanTemplate {
            name: "config".to_string(),
            content: "token=@secretspec:NIXOS_TEST_SECRET@\n".to_string(),
            owner: uid.to_string(),
            group: gid.to_string(),
            mode: "0400".to_string(),
            units: Vec::new(),
        }],
    };

    unsafe { std::env::set_var("NIXOS_TEST_SECRET", "first-value") };
    let report = refresh(&plan, false, true, None, None).unwrap();
    assert_eq!(report.resolved, 1);
    assert_eq!(
        std::fs::read_to_string(runtime.join("current/secrets/NIXOS_TEST_SECRET")).unwrap(),
        "first-value"
    );
    assert_eq!(
        std::fs::read_to_string(runtime.join("current/templates/config")).unwrap(),
        "token=first-value\n"
    );

    unsafe { std::env::remove_var("NIXOS_TEST_SECRET") };
    let report = refresh(&plan, false, true, None, None).unwrap();
    assert_eq!(report.cached, 1);
    assert_eq!(report.changed, 0);
    assert_eq!(
        std::fs::read_to_string(runtime.join("current/secrets/NIXOS_TEST_SECRET")).unwrap(),
        "first-value"
    );
}

//! Exercise generation and fresh provider reads with isolated CLI stand-ins.
#![cfg(unix)]

use secretspec::{SecretBytes, Secrets};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const CHILD_PROVIDER: &str = "SECRETSPEC_WHITESPACE_TEST_PROVIDER";
const FAILURE: &str = "SECRETSPEC_WHITESPACE_TEST_FAILURE";
// Generated values keep their whitespace, but output that is nothing except
// whitespace is refused by the generator, so every value here has content.
const VALUES: &[&[u8]] = &[
    b"value",
    b"value\n",
    b"value\n\n",
    b" \tvalue \t",
    b"\nfirst\nsecond\n\n",
    b"\t \nx\n",
    b"first\r\nsecond\r\n",
    b"\nx",
    "\u{2003}value\u{00a0}\n".as_bytes(),
];

// Model pass's raw output, gopass insert's text entries (a final newline is
// added and CRLF becomes LF), gopass cat's stdin-dependent read/write modes,
// and lpass's removal/addition of one input/output newline. Unexpected command
// shapes fail so a value the text path would alter cannot pass through it.
const SHIM: &str = r#"#!/bin/sh
set -eu
provider=${0##*/}
operation=$1
shift
case "${SECRETSPEC_WHITESPACE_TEST_FAILURE:-}:$provider:$operation" in
    read-error:gopass:show|cat-error:gopass:cat)
        printf 'Error: decrypt failed\n' >&2; exit 11 ;;
    cat-error:gopass:show)
        printf 'Error: no password to display, check the body of the entry instead\n' >&2
        exit 11 ;;
    write-error:gopass:cat)
        cat > /dev/null
        printf 'Error: permission denied\n' >&2; exit 1 ;;
    unchanged-mismatch:gopass:cat)
        cat > /dev/null
        printf 'Error: failed to write secret: meaningless write\n' >&2; exit 1 ;;
esac
write=false
case "$provider:$operation" in
    lpass:status) printf 'Logged in\n'; exit 0 ;;
    pass:show) [ "$#" -eq 1 ]; entry=$1 ;;
    pass:insert) [ "$1" = '-m' ]; [ "$2" = '-f' ]; entry=$3; write=true ;;
    gopass:show)
        [ "$1" = '-y' ]; [ "$2" = '-o' ]; entry=$3
        ;;
    gopass:insert) [ "$1" = '-m' ]; [ "$2" = '-f' ]; entry=$3; write=true ;;
    gopass:cat)
        [ "$#" -eq 1 ]; entry=$1
        if [ ! -c /dev/stdin ]; then write=true; fi
        ;;
    lpass:show)
        [ "$1" = '--sync=now' ]; [ "$2" = '--password' ]; entry=$3
        ;;
    lpass:add|lpass:edit)
        [ "$1" = '--sync=now' ]; entry=$2
        [ "$3" = '--password' ]; [ "$4" = '--non-interactive' ]; write=true
        ;;
    *) printf 'Unexpected command: %s %s\n' "$provider" "$operation" >&2; exit 99 ;;
esac
file="store/$entry"
if [ "$write" = true ]; then
    mkdir -p "${file%/*}"
    if [ "$provider" = lpass ]; then
        if [ "$operation" = add ]; then [ ! -f "$file" ]; else [ -f "$file" ]; fi
        value=$(cat; printf '.')
        value=${value%.}
        newline='
'
        value=${value%"$newline"}
        printf '%s' "$value" > "$file"
    else
        cat > "$file.pending"
        if [ "$provider:$operation" = gopass:insert ]; then
            # A text entry: CRLF becomes LF and a final newline is added.
            tr -d '\r' < "$file.pending" > "$file.text"
            if [ "$(tail -c1 "$file.text"; printf x)" != "$(printf '\nx')" ]; then
                printf '\n' >> "$file.text"
            fi
            mv "$file.text" "$file.pending"
            rm -f "$file.binary"
        fi
        if [ "$provider" = gopass ] && [ -f "$file.binary" ] && cmp -s "$file" "$file.pending"; then
            printf 'Error: Failed to write secret from STDIN: failed to write secret: meaningless write\n' >&2
            exit 1
        fi
        mv "$file.pending" "$file"
        if [ "$provider:$operation" = gopass:cat ]; then touch "$file.binary"; fi
    fi
elif [ -f "$file" ]; then
    if [ "$provider:$operation" = gopass:show ]; then
        if [ -f "$file.binary" ]; then
            printf 'Error: no password to display, check the body of the entry instead\n' >&2
            exit 11
        fi
        IFS= read -r password < "$file" || true
        printf '%s' "$password"
    else
        cat "$file"
    fi
    if [ "$provider" = lpass ]; then printf '\n'; fi
else
    case "$provider" in
        pass) printf 'is not in the password store\n' >&2; exit 1 ;;
        gopass) printf 'is not in the password store\n' >&2; exit 11 ;;
        lpass) printf 'Could not find specified account\n' >&2; exit 1 ;;
    esac
fi
"#;

#[test]
fn password_store_whitespace_child() {
    let Ok(provider_uri) = std::env::var(CHILD_PROVIDER) else {
        return;
    };
    let failure = std::env::var(FAILURE).unwrap_or_default();
    if !failure.is_empty() {
        let spec = Secrets::load().unwrap();
        let error = match failure.as_str() {
            "read-error" | "cat-error" => spec.resolve_bytes().unwrap_err(),
            "write-error" | "unchanged-mismatch" => spec
                .set(
                    "LEGACY",
                    SecretBytes::from_vec(b"existing-value\n".to_vec()),
                )
                .unwrap_err(),
            _ => panic!("unknown failure scenario: {failure}"),
        };
        let expected = match failure.as_str() {
            "write-error" => "permission denied",
            "unchanged-mismatch" => "meaningless write",
            _ => "decrypt failed",
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(
            fs::read("store/secretspec/whitespace/default/LEGACY").unwrap(),
            b" existing-value \nnotes: existing metadata\n"
        );
        return;
    }
    // Loading a new session for each resolution prevents in-memory state from
    // hiding a difference between generation and the stored value.
    for _ in 0..2 {
        let response = Secrets::load().unwrap().resolve_bytes().unwrap();
        if provider_uri == "gopass://" {
            assert_eq!(
                response.secrets["LEGACY"]
                    .value
                    .as_ref()
                    .unwrap()
                    .expose_secret(),
                b"existing-value",
                "legacy gopass passwords must retain password-only, trimmed reads"
            );
        }
        if provider_uri == "pass://" {
            assert_eq!(
                response.secrets["LEGACY"]
                    .value
                    .as_ref()
                    .unwrap()
                    .expose_secret(),
                b"existing-value",
                "entries created with `pass insert` must resolve without their final newline"
            );
        }
        for (index, expected) in VALUES.iter().enumerate() {
            let key = format!("VALUE_{index}");
            assert_eq!(
                response.secrets[&key]
                    .value
                    .as_ref()
                    .unwrap()
                    .expose_secret(),
                *expected,
                "{provider_uri}: {key}"
            );
        }
    }

    // Exercise updates too: LastPass uses separate add and edit paths.
    let updated = SecretBytes::from_vec(b" \tupdated\r\n\n".to_vec());
    for _ in 0..2 {
        Secrets::load()
            .unwrap()
            .set("VALUE_0", updated.clone())
            .unwrap();
        if provider_uri == "gopass://" {
            // Updating an older password entry must migrate it to lossless
            // storage, including when the same update is applied again.
            Secrets::load()
                .unwrap()
                .set("LEGACY", updated.clone())
                .unwrap();
        }
    }
    let response = Secrets::load().unwrap().resolve_bytes().unwrap();
    assert_eq!(
        response.secrets["VALUE_0"]
            .value
            .as_ref()
            .unwrap()
            .expose_secret(),
        updated.expose_secret()
    );
    if provider_uri == "gopass://" {
        assert_eq!(
            response.secrets["LEGACY"]
                .value
                .as_ref()
                .unwrap()
                .expose_secret(),
            updated.expose_secret()
        );
    }
    if provider_uri == "pass://" {
        // Stored entries stay readable by the pass CLI: exactly one newline
        // terminates the value, however many newlines the value itself ends with.
        let mut stored = updated.expose_secret().to_vec();
        stored.push(b'\n');
        assert_eq!(
            fs::read("store/secretspec/whitespace/default/VALUE_0").unwrap(),
            stored
        );
    }
}

fn check_provider(provider: &str, executable: &str) {
    check_provider_scenario(provider, executable, "");
}

fn check_provider_scenario(provider: &str, executable: &str, failure: &str) {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let bin = project.join("bin");
    fs::create_dir(&bin).unwrap();
    let shim = bin.join(executable);
    fs::write(&shim, SHIM).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();

    let mut manifest = String::from(
        "[project]\nname = 'whitespace'\nrevision = '1.0'\nrequire_reason = false\n\n[profiles.default]\n",
    );
    for (index, value) in VALUES.iter().enumerate() {
        fs::write(project.join(format!("input_{index}")), value).unwrap();
        manifest.push_str(&format!(
            "VALUE_{index} = {{ description = 'test', type = 'command', generate = {{ command = 'cat input_{index}' }} }}\n"
        ));
    }
    if provider == "pass://" || provider == "gopass://" {
        manifest.push_str("LEGACY = { description = 'Existing password entry' }\n");
        let store = project.join("store/secretspec/whitespace/default");
        fs::create_dir_all(&store).unwrap();
        let existing: &[u8] = if provider == "gopass://" {
            b" existing-value \nnotes: existing metadata\n"
        } else {
            // `pass insert` stores the password newline-terminated.
            b"existing-value\n"
        };
        fs::write(store.join("LEGACY"), existing).unwrap();
    }
    fs::write(project.join("secretspec.toml"), manifest).unwrap();
    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["password_store_whitespace_child", "--exact", "--nocapture"])
        .current_dir(project)
        .env_clear()
        .env("PATH", path)
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", project.join("config"))
        .env("XDG_STATE_HOME", project.join("state"))
        .env("SECRETSPEC_PROVIDER", provider)
        .env(CHILD_PROVIDER, provider)
        .env(FAILURE, failure)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{provider}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn pass_preserves_generated_whitespace() {
    check_provider("pass://", "pass");
}

#[test]
fn gopass_preserves_generated_whitespace() {
    check_provider("gopass://", "gopass");
}

#[test]
fn lastpass_preserves_generated_whitespace() {
    check_provider("lastpass://", "lpass");
}

#[test]
fn gopass_failures_remain_errors() {
    for failure in [
        "read-error",
        "cat-error",
        "write-error",
        "unchanged-mismatch",
    ] {
        check_provider_scenario("gopass://", "gopass", failure);
    }
}

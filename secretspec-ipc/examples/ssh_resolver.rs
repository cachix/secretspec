//! Resolve through SSH without printing secret values (SecretSpec 0.21+).
//!
//! cargo run -p secretspec-ipc --example ssh_resolver -- HOST /remote/secretspec.toml NAME

use secretspec_ipc::connection::SshOptions;
use secretspec_ipc::lifecycle::ResolverSession;
use secretspec_ipc::protocol::resolver::{
    GetParams, GetResult, InitializeApplication, Manifest, Purpose, Representation,
};
use secretspec_ipc::{Limits, Product, deadline_unix_ms_after};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: ssh_resolver HOST /remote/secretspec.toml NAME".into());
    }
    let session = ResolverSession::launch_ssh(
        SshOptions::new(&args[0]),
        Product {
            name: "ssh-example".into(),
            version: "1".into(),
        },
        Limits {
            max_frame_bytes: 32768,
            max_in_flight: 4,
        },
        InitializeApplication {
            manifest: Manifest::Path {
                path: args[1].clone(),
            },
            provider: None,
            profile: None,
            scope: None,
            reason: Some("resolve from SSH example".into()),
            requested_authorization_duration_ms: None,
        },
        deadline_unix_ms_after(Duration::from_secs(15)),
    )
    .await?;
    let result = session
        .get(
            &GetParams {
                name: args[2].clone(),
                representation: Representation::Auto,
                purpose: Purpose {
                    consumer: "ssh-example".into(),
                    operation: "resolve".into(),
                    host: None,
                    path: None,
                },
            },
            deadline_unix_ms_after(Duration::from_secs(30)),
        )
        .await;
    // Close even after a failed operation. Neither close nor relaunch replays it.
    let closed = session
        .close(deadline_unix_ms_after(Duration::from_secs(5)))
        .await;
    match result? {
        GetResult::Value(_) => println!("Resolved an inline value."),
        GetResult::Missing(_) => println!("Secret is missing."),
        GetResult::Undeclared(_) => println!("Secret is undeclared in this scope."),
        GetResult::Path(_) => unreachable!("SSH defaults to separate filesystems"),
    }
    closed?;
    Ok(())
}

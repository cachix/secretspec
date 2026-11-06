# file-lease

Give a program a file path without first writing the payload to disk.
`file-lease` creates memory-backed files on Linux and macOS, keeps their paths
available while a chosen process needs them, and cleans up when the lease ends.

Use it when a program expects a path to a credential, certificate, or generated
configuration file. The consumer opens the path normally; it needs no library
integration or descriptor-passing protocol. A separate helper holds the storage
and watches the process you select as its owner.

This is currently an **unpublished workspace crate**, with an independent 0.1.0
API. It does not depend on SecretSpec or perform secret resolution. SecretSpec
uses it by default for secret-file delivery in version 0.22+.

## Quick start

Build and install the helper from a checkout of this repository:

```sh
cargo install --path file-lease --locked
```

Deploy that matching `file-lease` executable alongside your application or on
PATH. The helper handshake rejects older, incompatible versions before any
payload is sent; upgrade the library and helper together.
To use the library before publication, add a path dependency pointing to
the `file-lease` directory in your checkout:

```toml
[dependencies]
file-lease = { path = "../secretspec/file-lease" }
```

This example gives `cat` a generated configuration file and keeps the lease
alive until the command finishes. Run it on Linux or macOS with the helper
installed:

```rust,no_run
use file_lease::FileLease;
use std::{io, process::Command};

fn main() -> io::Result<()> {
    let lease = FileLease::new(std::process::id());
    let path = lease.materialize(b"endpoint = 'https://example.com'\n", None)?;

    let status = Command::new("cat").arg(&path).status()?;
    drop(lease); // Request cleanup now that the consumer has finished.

    if !status.success() {
        return Err(io::Error::other("consumer failed"));
    }
    Ok(())
}
```

Keep the lease alive for every read the consumer may make, including later
reopens. A `PathBuf` alone does not retain the file. In this example the owner is
the launcher, so its exit also triggers cleanup even if `cat` is still running.

## Ownership

The owner is the process whose exit should end access, identified by its PID.
Choose the launcher when it waits for its consumers, a shell when files belong
to a shell session, or a detached manager when it must outlive the launcher.
`ProcessInfo` provides metadata for applications that need to identify their
consuming shell or manager.

| Operation | Effect |
| --- | --- |
| `FileLease::new(pid)` | Select an owner. Storage and the helper are allocated lazily on the first `materialize` call. |
| `clone()` | Share the same helper and files. |
| Drop the last clone, before handoff | Request cleanup and wait for the helper to finish. |
| `handoff()` | Keep existing files until the original owner exits, even after every clone is dropped. |
| `handoff_to(pid)` | Transfer existing files to another owner and retain them until that process exits. |

`release(&path)` revokes one file without ending the lease. Owner exit triggers
cleanup whether or not the lease has been handed off.
After handoff, no clone can allocate additional files. Handoff on an empty
lease does nothing; materialize files before handing them off.

### Replacing the launcher with the consumer

Unix `exec` replaces the current executable without changing its PID. Hand off
before `exec` so the helper keeps the files alive after the launcher's Rust
objects disappear. This example replaces the launcher with `cat`:

```rust,no_run
use file_lease::FileLease;
use std::{io, process::Command};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
fn main() -> io::Result<()> {
    let lease = FileLease::new(std::process::id());
    let path = lease.materialize(b"application data\n", None)?;
    lease.handoff()?;
    drop(lease); // The helper now retains the file until this PID exits.

    Err(Command::new("cat").arg(&path).exec())
}
# #[cfg(not(unix))]
# fn main() {}
```

For a detached consumer, call `handoff_to(consumer_pid)` while both the current
owner and consumer are still alive. Complete the handoff before letting the
launcher exit. If a program daemonizes, use the PID of the process that will
actually need the files.

## Helper deployment

By default, the library looks for `file-lease` beside the current executable,
then on PATH. Use `with_keeper_executable` to select an explicit helper path;
configure it before cloning the lease.

Applications can also host the helper in their own executable. Dispatch its
internal invocations before argument parsing:

```rust,no_run
use file_lease::{FileLease, maybe_run_keeper};

fn main() -> std::io::Result<()> {
    if let Some(code) = maybe_run_keeper() {
        std::process::exit(code);
    }

    let lease = FileLease::new(std::process::id())
        .with_keeper_executable(std::env::current_exe()?);
    let path = lease.materialize(b"application data", None)?;
    assert_eq!(std::fs::read(&path)?, b"application data");
    Ok(())
}
```

SecretSpec (0.22+) already hosts the helper, so its users need no additional
executable or application hook.

The helper wire protocol and recovery format are internal. Deploy matching
library and helper versions. They are not a public interoperability contract.

## Alternatives

| Alternative | When it fits | What `file-lease` adds |
| --- | --- | --- |
| [`tempfile`](https://crates.io/crates/tempfile) | Temporary files on a filesystem you choose. | Memory-backed storage without a disk-backed fallback, plus cleanup tied to a selected process. Named temporary files otherwise rely on destructors for cleanup. |
| [`memfd`](https://crates.io/crates/memfd), [`memfile`](https://crates.io/crates/memfile) | Creating and sealing anonymous files on supported systems. | A helper that hosts paths, owner monitoring, handoff, and a macOS backend. |
| [`memfd_path`](https://crates.io/crates/memfd_path) | An in-memory Linux file accessed through `/proc/self/fd/...`. | Paths hosted independently of the launcher, without requiring the consumer to inherit the file descriptor. |
| [`shared_memory`](https://crates.io/crates/shared_memory), [`native-ipc`](https://crates.io/crates/native-ipc) | Sharing mappings between cooperating processes. | File paths that ordinary programs can open without shared-memory integration. |

## Platform behavior and limits

- Linux uses sealed, read-only memfds exposed as `/proc/<helper>/fd/<fd>`.
  A shared read-only mapping is populated and locked with `mlock()` before
  payload bytes are written. It stays locked while the helper retains that
  file, and is excluded from ordinary process core dumps with `MADV_DONTDUMP`.
  Empty files need no mapping. Allocation fails if locking fails, with no
  pageable or disk-backed fallback. The helper inherits `RLIMIT_MEMLOCK`;
  live nonempty files consume their sizes rounded up to whole pages. Configure
  a sufficient memory-lock limit before launching the application. Releasing
  a file reclaims its lock budget. See [`mlock(2)`](https://man7.org/linux/man-pages/man2/mlock.2.html).
  The owner is watched through a pidfd. Suffix hints are accepted but omitted
  from Linux paths. Consumers must open the proc-fd path directly. Software
  that resolves it to the memfd's deleted backing name can reject it; PHP's
  ordinary `fopen()` and `file_get_contents()` are affected. Check the actual
  consumer before relying on this backend.
  Descriptor numbers are not reused within a lease, so a revoked path cannot
  expose a later file. Total allocations per lease are bounded by the helper's
  file-descriptor limit; use a new lease for each resolution or refresh batch.
  The helper's descriptors close even if it is killed. Independent open readers
  can retain file contents after pathname revocation until they close them.
- macOS uses a private 64 MiB HFS RAM disk with read-only files and a kqueue
  process-exit watcher. Allocation and release pin the volume's directory and
  verify its filesystem identity, ownership, private permissions, and
  `noexec,nosuid,nodev,nobrowse` flags before accessing files. A missing or
  replaced mount fails without writing into its disk-backed mount directory.
  Normal cleanup unlinks files, unmounts, and detaches the
  disk. The setup worker stays alive as a guardian in a separate process group
  and cleans up if the helper is killed. Volume commands have 10-second
  deadlines; failed cleanup is retried up to three times with backoff. If both
  processes die, or cleanup keeps failing, a later lease retries recovery.
  Recovery metadata, never payload bytes, lives in
  `~/Library/Application Support/file-lease`. No background service is installed.
  Startup recovery uses a shared five-second budget for scanning and volume-tool
  waits, deferring remaining work to a later lease. Individual OS calls can still
  take longer. Failures before attachment starts remove the unused metadata;
  interrupted attachments and older journals retain conservative recovery rules.
  Persistent cleanup failures are recorded in the lease directory's private
  `cleanup.error` file, which contains only an error description and is removed
  with the recovered lease. Detached helpers do not retain application output
  pipes for diagnostics.
- Other operating systems return `Unsupported` on allocation.
- Payloads are limited to 64 MiB per request. The macOS limit also applies to
  the whole volume, including filesystem overhead. Suffixes are limited to
  80 ASCII letters, digits, dots, underscores, or hyphens.
- The Linux lock covers only the helper's live file pages. Source buffers,
  transport buffers, and consumer copies are not locked. Readers surviving
  revocation can retain bytes after the helper unlocks them. macOS storage has
  no additional memory-lock guarantee. Locking does not protect against
  hibernation images or every diagnostic capture, and pathname revocation
  cannot erase bytes already copied by a reader.

## Development

`cargo test -p file-lease -- --test-threads=1` runs the storage, owner-exit,
ownership-transfer, helper-crash, closed-descriptor, and macOS setup-recovery
tests. CI runs these on Linux and macOS independently of SecretSpec tests.

`cargo run -p file-lease --example lifecycle_timings` measures first-file setup,
additional-file allocation, and cleanup latency with synthetic 256-byte files.
It reports five sequential leases and four parallel leases as CSV. The lifecycle
CI matrix runs it on Linux and macOS. These are diagnostic timings, not performance
thresholds or measurements of the RAM disk's memory footprint.

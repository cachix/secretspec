//! Local SQLite provider (0.22+).
//!
//! Stores each secret as one row in a local SQLite database. Convention
//! addresses are isolated by project and profile at `{project}/{profile}/{key}`;
//! a native `ref` supplies that key directly as `item`.
//!
//! Confidentiality comes entirely from filesystem permissions on the database
//! file: the schema and connection carry no credential of their own. That is
//! what lets identical code serve both an ordinary user-owned store and a
//! privilege-boundary vault file guarded by a `0600` service-user-owned path;
//! the privilege model stays external to the provider.
//!
//! With `?history=true` every write also appends to a hash-chained,
//! append-only ledger inside the same database (see [`capture_history`]).
//! History is off by default: a plain `sqlite:PATH` store has only the
//! `secrets` table.

use super::{Address, Provider, ProviderUrl};
use crate::SecretBytes;
use crate::config::{NativeAddress, expand_tilde};
use crate::{Result, SecretSpecError};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const URI_SHAPE_ERROR: &str =
    "sqlite provider URIs take only a database path and an optional '?history=true' parameter";

/// Configuration for the local SQLite provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliteConfig {
    /// Path to the SQLite database file.
    pub path: PathBuf,
    /// Whether history tracking is enabled.
    #[serde(default)]
    pub history: bool,
}

impl TryFrom<&ProviderUrl> for SqliteConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        if url.scheme() != "sqlite" {
            return Err(operation_error(format!(
                "Invalid scheme '{}' for sqlite provider",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(operation_error(URI_SHAPE_ERROR));
        }
        let mut history = false;
        if url.has_query() {
            let pairs: Vec<_> = url.query_pairs().collect();
            if pairs.len() != 1 || pairs[0].0 != "history" {
                return Err(operation_error(URI_SHAPE_ERROR));
            }
            match pairs[0].1.as_ref() {
                "true" | "1" | "yes" | "on" => history = true,
                "false" | "0" | "no" | "off" => history = false,
                _ => {
                    return Err(operation_error(
                        "invalid value for the sqlite provider's 'history' parameter: expected true or false",
                    ));
                }
            }
        }

        let uri_path = url.path();
        #[cfg(windows)]
        let uri_path = if uri_path.as_bytes().first() == Some(&b'/')
            && uri_path.as_bytes().get(2) == Some(&b':')
            && uri_path
                .as_bytes()
                .get(1)
                .is_some_and(u8::is_ascii_alphabetic)
        {
            uri_path[1..].to_string()
        } else {
            uri_path
        };
        let path = match url.host() {
            Some(host) => format!("{host}{uri_path}"),
            None => uri_path,
        };
        if path.is_empty() || path == "/" {
            return Err(operation_error(
                "No SQLite database path given. Use sqlite:./secrets.db or \
                 sqlite:///absolute/path/secrets.db.",
            ));
        }

        Ok(Self {
            path: PathBuf::from(path),
            history,
        })
    }
}

/// A provider backed by a local SQLite database, one row per secret.
pub struct SqliteProvider {
    config: SqliteConfig,
}

crate::register_provider! {
    struct: SqliteProvider,
    config: SqliteConfig,
    metadata: &super::catalog::SQLITE,
}

impl SqliteProvider {
    pub fn new(mut config: SqliteConfig) -> Self {
        config.path = expand_tilde(config.path);
        Self { config }
    }

    #[cfg(unix)]
    fn create_private_directory(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }

    #[cfg(not(unix))]
    fn create_private_directory(path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }

    #[cfg(unix)]
    fn restrict_file(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
            operation_error(format!(
                "failed to restrict permissions for sqlite database '{}': {error}",
                path.display()
            ))
        })
    }

    #[cfg(not(unix))]
    fn restrict_file(_path: &Path) -> Result<()> {
        Ok(())
    }

    /// Opens the database, creating its parent directory and schema on first
    /// use. Every open re-asserts `0600` permissions on the file, in case it
    /// pre-existed with looser ones.
    fn connection(&self) -> Result<Connection> {
        if let Some(parent) = self.config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            Self::create_private_directory(parent).map_err(|error| {
                operation_error(format!(
                    "failed to create sqlite provider directory '{}': {error}",
                    parent.display()
                ))
            })?;
        }

        let conn = Connection::open(&self.config.path).map_err(|error| {
            operation_error(format!(
                "failed to open sqlite database '{}': {error}",
                self.config.path.display()
            ))
        })?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(|error| {
            operation_error(format!(
                "failed to configure sqlite database '{}': {error}",
                self.config.path.display()
            ))
        })?;
        let mut init_sql = String::from(
            // `foreign_keys` is off by default and is a *per-connection* setting,
            // so without this the REFERENCES clauses on `captured_values` below
            // are documentation rather than a constraint: a tombstone could name
            // a `destroyed_by` sequence no entry has. Every connection this
            // provider hands out comes through here, which is what makes one
            // line sufficient.
            // `secure_delete` is also per-connection and off in most builds of
            // the library. Without it SQLite unlinks a deleted row from the
            // b-tree but leaves its bytes on the freed page, so `delete` leaves
            // the plaintext value recoverable by reading the file. Setting it
            // here makes freed content zeroed on the way out. It is not
            // retroactive: residue already on freelist pages needs a `VACUUM`.
            "PRAGMA foreign_keys=ON;\
             PRAGMA secure_delete=ON;\
             PRAGMA journal_mode=DELETE;\
             PRAGMA synchronous=FULL;\
             PRAGMA trusted_schema=OFF;\
             CREATE TABLE IF NOT EXISTS secrets (\
                 item TEXT PRIMARY KEY,\
                 value BLOB NOT NULL\
             ) STRICT;",
        );
        if self.config.history {
            init_sql.push_str(&history_schema());
        }
        conn.execute_batch(&init_sql).map_err(|error| {
            operation_error(format!(
                "failed to prepare sqlite database '{}': {error}",
                self.config.path.display()
            ))
        })?;
        if self.config.history {
            check_history_version(&conn)?;
            conn.execute_batch(HISTORY_POST_MIGRATION)
                .map_err(|error| {
                    operation_error(format!(
                        "failed to finish history schema on '{}': {error}",
                        self.config.path.display()
                    ))
                })?;
        }
        Self::restrict_file(&self.config.path)?;
        Ok(conn)
    }
}

impl Provider for SqliteProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: format!("{project}/{profile}/{key}"),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let item = super::flat_item(self, addr)?;
        if !self.config.path.exists() {
            return Ok(None);
        }
        let conn = self.connection()?;
        let value: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM secrets WHERE item = ?1",
                params![item.as_ref()],
                value_bytes,
            )
            .optional()
            .map_err(|error| {
                operation_error(format!(
                    "failed to read sqlite provider entry '{item}': {error}"
                ))
            })?;
        Ok(value.map(SecretBytes::from_vec))
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        let item = super::flat_item(self, addr)?;
        Ok(format!("{} (item '{item}')", self.config.path.display()))
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)?;
        let item = super::flat_item(self, addr)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(|error| {
            operation_error(format!("failed to start sqlite transaction: {error}"))
        })?;
        tx.execute(
            "INSERT INTO secrets (item, value) VALUES (?1, ?2) \
             ON CONFLICT(item) DO UPDATE SET value = excluded.value",
            params![item.as_ref(), value.expose_secret()],
        )
        .map_err(|error| {
            operation_error(format!(
                "failed to write sqlite provider entry '{item}': {error}"
            ))
        })?;
        if self.config.history {
            capture_history(&tx, "set")?;
        }
        tx.commit().map_err(|error| {
            operation_error(format!("failed to commit sqlite transaction: {error}"))
        })?;
        Ok(())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let item = super::flat_item(self, addr)?;
        if !self.config.path.exists() {
            return Ok(false);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(|error| {
            operation_error(format!("failed to start sqlite transaction: {error}"))
        })?;
        let changed = tx
            .execute(
                "DELETE FROM secrets WHERE item = ?1",
                params![item.as_ref()],
            )
            .map_err(|error| {
                operation_error(format!(
                    "failed to delete sqlite provider entry '{item}': {error}"
                ))
            })?;
        if changed > 0 && self.config.history {
            capture_history(&tx, "delete")?;
        }
        tx.commit().map_err(|error| {
            operation_error(format!("failed to commit sqlite transaction: {error}"))
        })?;
        Ok(changed > 0)
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let path = ProviderUrl::encode(&self.config.path.display().to_string());
        if self.config.history {
            format!("sqlite:{path}?history=true")
        } else {
            format!("sqlite:{path}")
        }
    }

    fn storage_identity(&self) -> String {
        // History is a write-side policy on the same file, not a different
        // store: a `?history=true` alias and a plain alias naming one path
        // read and write the same rows.
        format!(
            "sqlite:{}",
            ProviderUrl::encode(&self.config.path.display().to_string())
        )
    }

    fn physical_store_path(&self) -> Option<&Path> {
        Some(&self.config.path)
    }

    fn with_base_dir(&mut self, base_dir: &Path) {
        if self.config.path.is_relative() {
            self.config.path = base_dir.join(&self.config.path);
        }
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        // Resolve every address up front so an invalid coordinate is rejected
        // the same way whether or not the database file exists yet.
        let mut items = Vec::with_capacity(requests.len());
        for (name, addr) in requests {
            items.push((*name, super::flat_item(self, *addr)?));
        }
        if !self.config.path.exists() {
            return Ok(HashMap::new());
        }
        let conn = self.connection()?;
        let mut statement = conn
            .prepare("SELECT value FROM secrets WHERE item = ?1")
            .map_err(|error| {
                operation_error(format!("failed to query sqlite database: {error}"))
            })?;

        let mut results = HashMap::new();
        for (name, item) in items {
            let value: Option<Vec<u8>> = statement
                .query_row(params![item.as_ref()], value_bytes)
                .optional()
                .map_err(|error| {
                    operation_error(format!(
                        "failed to read sqlite provider entry '{item}': {error}"
                    ))
                })?;
            if let Some(value) = value {
                results.insert(name.to_string(), SecretBytes::from_vec(value));
            }
        }
        Ok(results)
    }
}

fn operation_error(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

/// Reads the first column as raw bytes whether SQLite holds it as `BLOB` or
/// as `TEXT`, so a row written by another tool as text reads back exactly.
fn value_bytes(row: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<u8>> {
    Ok(row.get_ref(0)?.as_bytes().map(<[u8]>::to_vec)?)
}

// ---------------------------------------------------------------------------
// History capture (opt-in via `?history=true`)
// ---------------------------------------------------------------------------

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Bumped whenever the on-disk history shape changes. Stamped into
/// `PRAGMA user_version`, which starts life at 0 on every SQLite database,
/// so 0 doubles as "pre-versioning": exactly the databases that need
/// migrating.
const SCHEMA_VERSION: i64 = 2;

/// Each distinct value is stored once in `value_blobs` instead of repeating
/// the plaintext in every `captured_values` row.
///
/// `value_blobs` is keyed by `(item, value_sha256)` rather than by the digest
/// alone. Global content-addressing would dedup marginally better, but it
/// lets two *different* names share one blob, and then destroying one name's
/// history has no correct move: keeping the blob leaves the name's plaintext
/// readable, and removing it erases another live name's history. Keying per
/// item means a blob is never shared across names, so destroy-by-name keeps
/// the same meaning it had when every row carried its own copy, and no
/// reference counting is required to get there.
///
/// Version 2 adds a surrogate `blob_id` and makes the liveness invariant
/// structural rather than something every query has to remember.
///
/// `captured_values.blob_id` records which blob a snapshot captured and is
/// never rewritten. `live_blob_id` is generated from it and nulls itself the
/// moment `destroyed_by` is set, and it, not the raw column, carries the
/// foreign key. Three properties fall out of that arrangement:
///
/// * Destroying a captured value stays a single-column write to
///   `destroyed_by`. The reference releases itself, so no query can leave the
///   two out of step.
/// * `ON DELETE RESTRICT` refuses to drop a blob a *live* snapshot still
///   references.
/// * A tombstone cannot be resurrected. Clearing `destroyed_by` re-exposes
///   the old `blob_id`, whose blob is gone, and the foreign key refuses the
///   update. Under a digest-keyed reference this was the one hole a `CHECK`
///   could not close: destroy a name, re-set it to the same value, and the
///   recreated `(item, value_sha256)` row made the tombstone restorable
///   again.
///
/// That last property depends on `AUTOINCREMENT`, which is load-bearing here
/// and must not be removed as the tuning advice in SQLite's own documentation
/// suggests. It is what guarantees a `blob_id` is never handed out twice. With
/// a plain `INTEGER PRIMARY KEY` the recreated blob reclaims the freed rowid,
/// the dangling reference becomes valid again, and the tombstone resurrects.
///
/// `value_sha256` stays on `captured_values` even though `value_blobs` also
/// holds it. It is what makes a tombstone auditable once its bytes are gone,
/// and it is hashed into the entry chain, so removing it would invalidate
/// every existing `entry_hash`.
///
/// This constant is the column and constraint body of `value_blobs`, without
/// the `CREATE TABLE` wrapper, so a future migration that rebuilds the table
/// cannot drift from the definition the provider creates.
const VALUE_BLOBS_BODY: &str = "\
     blob_id INTEGER PRIMARY KEY AUTOINCREMENT,\
     item TEXT NOT NULL,\
     value_sha256 TEXT NOT NULL,\
     value_blob BLOB NOT NULL,\
     UNIQUE (item, value_sha256)";

/// Column and constraint body of `captured_values`, shared with any future
/// migration for the same reason as [`VALUE_BLOBS_BODY`].
const CAPTURED_VALUES_BODY: &str = "\
     sequence INTEGER NOT NULL REFERENCES entries(sequence),\
     item TEXT NOT NULL,\
     value_sha256 TEXT NOT NULL,\
     blob_id INTEGER,\
     destroyed_by INTEGER REFERENCES entries(sequence),\
     live_blob_id INTEGER GENERATED ALWAYS AS \
         (CASE WHEN destroyed_by IS NULL THEN blob_id END) VIRTUAL \
         REFERENCES value_blobs(blob_id) ON DELETE RESTRICT,\
     PRIMARY KEY (sequence, item),\
     CHECK (blob_id IS NOT NULL OR destroyed_by IS NOT NULL),\
     CHECK (destroyed_by IS NULL OR destroyed_by > sequence)";

fn history_schema() -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS entries (\
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,\
             timestamp_ns INTEGER NOT NULL,\
             operation TEXT NOT NULL,\
             previous_hash TEXT NOT NULL,\
             entry_hash TEXT NOT NULL UNIQUE\
         ) STRICT;\
         CREATE TABLE IF NOT EXISTS value_blobs ({VALUE_BLOBS_BODY}) STRICT;\
         CREATE TABLE IF NOT EXISTS captured_values ({CAPTURED_VALUES_BODY}) STRICT;\
         CREATE TABLE IF NOT EXISTS head (\
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
             sequence INTEGER NOT NULL,\
             entry_hash TEXT NOT NULL\
         ) STRICT;"
    )
}

/// Everything that can only be built once `captured_values` is known to be in
/// its current shape. Applied after [`check_history_version`], never as part
/// of [`history_schema`].
///
/// The index is here rather than in the schema because the schema runs first,
/// against a table `CREATE TABLE IF NOT EXISTS` silently leaves in whatever
/// shape it already had. On a database from an older version, indexing
/// `blob_id` would fail with `no such column` instead of reporting the real
/// problem. Running after the version check means the guard's error is what
/// the caller sees.
///
/// `CREATE TRIGGER IF NOT EXISTS` matches on name alone, so it would keep an
/// old body forever once one existed: a stale invariant that still looks
/// present. Dropping first is what makes the definition here authoritative.
const HISTORY_POST_MIGRATION: &str = "\
     CREATE INDEX IF NOT EXISTS captured_values_blob_id \
         ON captured_values(item, blob_id);\
     DROP TRIGGER IF EXISTS captured_values_destroyed_by_is_write_once;\
     CREATE TRIGGER captured_values_destroyed_by_is_write_once \
         BEFORE UPDATE OF destroyed_by ON captured_values \
         FOR EACH ROW WHEN OLD.destroyed_by IS NOT NULL \
     BEGIN \
         SELECT RAISE(ABORT, 'captured_values.destroyed_by is write-once'); \
     END;\
     DROP TRIGGER IF EXISTS captured_values_is_append_only;\
     CREATE TRIGGER captured_values_is_append_only \
         BEFORE DELETE ON captured_values \
         FOR EACH ROW \
     BEGIN \
         SELECT RAISE(ABORT, 'captured_values is append-only'); \
     END;";

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Refuses to open a history database that is not already at
/// [`SCHEMA_VERSION`].
///
/// There is deliberately no migration path. The tables are created with
/// `CREATE TABLE IF NOT EXISTS`, which is silent about a table that already
/// exists in an older shape, so without this check an upgraded binary would
/// keep writing against a layout that no longer matches the code and never say
/// so. Refusing is the whole job. If a future version needs a migration, it
/// belongs here, branching on `user_version` *before* the schema is created.
fn check_history_version(conn: &Connection) -> Result<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| operation_error(e.to_string()))?;

    // A freshly created database reports 0 until it is stamped below, and is
    // already in the current shape because `history_schema()` just built it.
    // An old database also reports 0, and the difference between the two is
    // whether the current columns are there.
    if version == 0 && !has_current_shape(conn)? {
        return Err(operation_error(
            "this history database predates the current schema and cannot be \
             upgraded in place. Export its secrets with a build that matches it \
             and re-import them into a new database.",
        ));
    }
    if version > SCHEMA_VERSION {
        return Err(operation_error(format!(
            "this history database was written by a newer version (schema \
             {version}, this build understands {SCHEMA_VERSION})"
        )));
    }
    if version < SCHEMA_VERSION {
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
            .map_err(|e| operation_error(e.to_string()))?;
    }
    Ok(())
}

/// Whether `captured_values` carries the column the current schema depends on.
fn has_current_shape(conn: &Connection) -> Result<bool> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('captured_values')")
        .map_err(|e| operation_error(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| operation_error(e.to_string()))?;
    for row in rows {
        if row.map_err(|e| operation_error(e.to_string()))? == "blob_id" {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug)]
struct CapturedValue {
    item: String,
    value_sha256: String,
}

#[derive(Debug)]
struct Entry {
    sequence: i64,
    timestamp_ns: i64,
    operation: String,
    values: Vec<CapturedValue>,
    previous_hash: String,
    entry_hash: String,
}

fn canonical_entry_json(entry: &Entry) -> String {
    let mut map = BTreeMap::new();
    map.insert("sequence", serde_json::Value::Number(entry.sequence.into()));
    map.insert(
        "timestamp_ns",
        serde_json::Value::Number(entry.timestamp_ns.into()),
    );
    map.insert(
        "operation",
        serde_json::Value::String(entry.operation.clone()),
    );
    let values: Vec<serde_json::Value> = entry
        .values
        .iter()
        .map(|v| {
            let mut pair = serde_json::Map::new();
            pair.insert("item".into(), serde_json::Value::String(v.item.clone()));
            pair.insert(
                "value_sha256".into(),
                serde_json::Value::String(v.value_sha256.clone()),
            );
            serde_json::Value::Object(pair)
        })
        .collect();
    map.insert("values", serde_json::Value::Array(values));
    map.insert(
        "previous_hash",
        serde_json::Value::String(entry.previous_hash.clone()),
    );

    serde_json::to_string(&map).expect("a BTreeMap of JSON values always serializes")
}

fn compute_entry_hash(previous_hash: &str, entry: &Entry) -> String {
    let canonical = canonical_entry_json(entry);
    sha256_hex(format!("{previous_hash}\n{canonical}").as_bytes())
}

/// Appends one entry to the history chain, snapshotting every live secret.
///
/// Runs inside the caller's transaction so the chain and the `secrets` row
/// it describes commit or roll back together. Each entry hashes the previous
/// entry's hash together with a canonical JSON rendering of the sequence,
/// timestamp, operation, and the `(item, sha256)` pairs of every live
/// secret, so the ledger is tamper-evident: altering or removing an earlier
/// entry breaks every hash after it.
fn capture_history(conn: &Connection, operation: &str) -> Result<()> {
    let mut count: i64 = 0;
    let mut previous_hash = ZERO_HASH.to_string();

    let head_row: Option<(i64, String)> = conn
        .query_row(
            "SELECT sequence, entry_hash FROM head WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| operation_error(e.to_string()))?;

    if let Some((seq, hash)) = head_row {
        count = seq;
        previous_hash = hash;
    }

    let sequence = count + 1;
    let timestamp_ns = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| operation_error(format!("clock error: {e}")))?;
        i64::try_from(now.as_nanos()).unwrap_or(i64::MAX)
    };

    let mut stmt = conn
        .prepare("SELECT item, value FROM secrets ORDER BY item")
        .map_err(|e| operation_error(e.to_string()))?;

    let mut pairs = Vec::new();
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get_ref(1)?.as_bytes().map(<[u8]>::to_vec)?,
            ))
        })
        .map_err(|e| operation_error(e.to_string()))?;

    for row in rows {
        pairs.push(row.map_err(|e| operation_error(e.to_string()))?);
    }

    let values: Vec<CapturedValue> = pairs
        .iter()
        .map(|(item, value)| CapturedValue {
            item: item.clone(),
            value_sha256: sha256_hex(value),
        })
        .collect();

    let mut entry = Entry {
        sequence,
        timestamp_ns,
        operation: operation.to_string(),
        values,
        previous_hash: previous_hash.clone(),
        entry_hash: String::new(),
    };
    entry.entry_hash = compute_entry_hash(&previous_hash, &entry);

    conn.execute(
        "INSERT INTO entries (sequence, timestamp_ns, operation, previous_hash, entry_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            entry.sequence,
            entry.timestamp_ns,
            entry.operation,
            entry.previous_hash,
            entry.entry_hash,
        ],
    )
    .map_err(|e| operation_error(e.to_string()))?;

    for (val, (_, plain)) in entry.values.iter().zip(pairs.iter()) {
        // `OR IGNORE` is the dedup: the second and later captures of an
        // unchanged value find the blob already present and store only the
        // reference below. This is the whole point of the table: history
        // snapshots every secret on every operation, so without it the
        // plaintext count grows with entries x secrets.
        conn.execute(
            "INSERT OR IGNORE INTO value_blobs (item, value_sha256, value_blob) \
             VALUES (?1, ?2, ?3)",
            params![val.item, val.value_sha256, plain.as_slice()],
        )
        .map_err(|e| operation_error(e.to_string()))?;

        // Read the id back rather than using `last_insert_rowid()`: on the
        // dedup path above the insert is ignored, and the id that matters is
        // the existing blob's, not whatever this connection inserted last.
        let blob_id: i64 = conn
            .query_row(
                "SELECT blob_id FROM value_blobs WHERE item = ?1 AND value_sha256 = ?2",
                params![val.item, val.value_sha256],
                |row| row.get(0),
            )
            .map_err(|e| operation_error(e.to_string()))?;

        conn.execute(
            "INSERT INTO captured_values \
                 (sequence, item, value_sha256, blob_id, destroyed_by) \
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![entry.sequence, val.item, val.value_sha256, blob_id],
        )
        .map_err(|e| operation_error(e.to_string()))?;
    }

    conn.execute(
        "INSERT INTO head (singleton, sequence, entry_hash) VALUES (1, ?1, ?2) \
         ON CONFLICT(singleton) DO UPDATE SET \
         sequence = excluded.sequence, entry_hash = excluded.entry_hash",
        params![entry.sequence, entry.entry_hash],
    )
    .map_err(|e| operation_error(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use url::Url;

    fn provider_url(value: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(value).unwrap())
    }

    fn provider(path: PathBuf) -> SqliteProvider {
        SqliteProvider::new(SqliteConfig {
            path,
            history: false,
        })
    }

    fn history_provider(path: PathBuf) -> SqliteProvider {
        SqliteProvider::new(SqliteConfig {
            path,
            history: true,
        })
    }

    fn convention<'a>(key: &'a str) -> Address<'a> {
        Address::convention("project", "production", key)
    }

    #[test]
    fn config_parses_relative_and_absolute_paths() {
        let relative = SqliteConfig::try_from(&provider_url("sqlite://./secrets.db")).unwrap();
        assert_eq!(relative.path, PathBuf::from("./secrets.db"));
        assert!(!relative.history);

        let absolute =
            SqliteConfig::try_from(&provider_url("sqlite:///var/lib/secrets.db")).unwrap();
        assert_eq!(absolute.path, PathBuf::from("/var/lib/secrets.db"));
    }

    #[test]
    fn history_is_off_unless_the_uri_turns_it_on() {
        for (uri, expected) in [
            ("sqlite://./secrets.db", false),
            ("sqlite://./secrets.db?history=false", false),
            ("sqlite://./secrets.db?history=0", false),
            ("sqlite://./secrets.db?history=true", true),
            ("sqlite://./secrets.db?history=1", true),
            ("sqlite://./secrets.db?history=on", true),
        ] {
            let config = SqliteConfig::try_from(&provider_url(uri)).unwrap();
            assert_eq!(config.history, expected, "{uri}");
            assert_eq!(config.path, PathBuf::from("./secrets.db"), "{uri}");
        }
    }

    #[test]
    fn config_rejects_missing_path_and_query_options() {
        for uri in [
            "sqlite://",
            "sqlite://./secrets.db?invalid=on",
            "sqlite://./secrets.db?history=true&other=1",
            "sqlite://./secrets.db?history=maybe",
            "sqlite://user:pass@./secrets.db",
        ] {
            assert!(SqliteConfig::try_from(&provider_url(uri)).is_err(), "{uri}");
        }
    }

    #[test]
    fn registry_builds_documented_uri() {
        let provider = Box::<dyn Provider>::try_from("sqlite:./secrets.db").unwrap();
        assert_eq!(provider.name(), "sqlite");
        let provider = Box::<dyn Provider>::try_from("sqlite:./secrets.db?history=true").unwrap();
        assert_eq!(provider.name(), "sqlite");
    }

    #[test]
    fn convention_round_trip_is_exact_and_profile_isolated() {
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("secrets.db"));
        let value = SecretBytes::from_utf8("s3cr3t\nvalue");

        provider
            .set(Address::convention("app", "development", "TOKEN"), &value)
            .unwrap();

        let found = provider
            .get(Address::convention("app", "development", "TOKEN"))
            .unwrap()
            .unwrap();
        assert_eq!(found.expose_secret(), value.expose_secret());
        assert!(
            provider
                .get(Address::convention("app", "production", "TOKEN"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn binary_values_round_trip_exactly() {
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("secrets.db"));
        let expected = [0x00, 0xff, 0x80, 0x0a, 0x00];
        provider
            .set(
                convention("BLOB"),
                &SecretBytes::from_vec(expected.to_vec()),
            )
            .unwrap();
        let found = provider.get(convention("BLOB")).unwrap().unwrap();
        assert_eq!(found.expose_secret(), expected);

        let batch = provider.get_many(&[("B", convention("BLOB"))]).unwrap();
        assert_eq!(batch["B"].expose_secret(), expected);
    }

    #[test]
    fn value_bytes_reads_text_and_blob_cells_exactly() {
        // The provider writes BLOBs, but a row planted by another tool may
        // hold TEXT; both must read back as the same bytes.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE loose (item TEXT PRIMARY KEY, value ANY) STRICT;\
             INSERT INTO loose VALUES ('text', 'plain text');\
             INSERT INTO loose VALUES ('blob', x'00ff80');",
        )
        .unwrap();
        let typed: String = conn
            .query_row(
                "SELECT typeof(value) FROM loose WHERE item = 'text'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(typed, "text");

        let text = conn
            .query_row(
                "SELECT value FROM loose WHERE item = 'text'",
                [],
                value_bytes,
            )
            .unwrap();
        assert_eq!(text, b"plain text");
        let blob = conn
            .query_row(
                "SELECT value FROM loose WHERE item = 'blob'",
                [],
                value_bytes,
            )
            .unwrap();
        assert_eq!(blob, [0x00, 0xff, 0x80]);
    }

    #[test]
    fn set_updates_existing_row() {
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("secrets.db"));
        provider
            .set(convention("KEY"), &SecretBytes::from_utf8("old"))
            .unwrap();
        provider
            .set(convention("KEY"), &SecretBytes::from_utf8("new"))
            .unwrap();
        assert_eq!(
            provider
                .get(convention("KEY"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"new"
        );
    }

    #[test]
    fn missing_database_and_entry_are_absent_without_creating_a_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("secrets.db");
        assert!(
            provider(path.clone())
                .get(convention("MISSING"))
                .unwrap()
                .is_none()
        );
        assert!(!path.exists());
    }

    #[test]
    fn delete_is_idempotent_and_does_not_create_a_missing_database() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("secrets.db");
        let provider = provider(path.clone());
        assert!(!provider.delete(convention("KEY")).unwrap());
        assert!(!path.exists());

        provider
            .set(convention("KEY"), &SecretBytes::from_utf8("value"))
            .unwrap();
        assert!(provider.delete(convention("KEY")).unwrap());
        assert!(!provider.delete(convention("KEY")).unwrap());
        assert!(provider.get(convention("KEY")).unwrap().is_none());
    }

    #[test]
    fn delete_leaves_no_plaintext_in_the_database_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("secrets.db");
        let provider = provider(path.clone());
        // Distinctive enough that a hit in the raw file cannot be coincidence,
        // and long enough to occupy a cell rather than fit in a header.
        let plaintext = "PLAINTEXT-CANARY-eb4c1f9a".repeat(8);

        provider
            .set(
                convention("KEY"),
                &SecretBytes::from_utf8(plaintext.clone()),
            )
            .unwrap();

        // Anti-vacuity: prove the scan can find the value at all. Without this
        // the test passes for free if the value never reached the file, or if
        // the needle is simply wrong.
        assert!(
            file_contains(&path, plaintext.as_bytes()),
            "precondition failed: plaintext is not in the file even before delete, \
             so its later absence would prove nothing"
        );

        assert!(provider.delete(convention("KEY")).unwrap());

        assert!(
            !file_contains(&path, plaintext.as_bytes()),
            "deleted plaintext is still readable in {}: PRAGMA secure_delete is \
             not in effect on the provider's connections",
            path.display()
        );
    }

    fn file_contains(path: &Path, needle: &[u8]) -> bool {
        let bytes = std::fs::read(path).unwrap();
        bytes.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn uri_round_trips() {
        let provider = provider(PathBuf::from("./my secrets.db"));
        let uri = provider.uri();
        assert_eq!(uri, "sqlite:./my%20secrets.db");
        let reparsed = Box::<dyn Provider>::try_from(uri.as_str()).unwrap();
        assert_eq!(reparsed.uri(), uri);

        let provider = history_provider(PathBuf::from("./my secrets.db"));
        let uri = provider.uri();
        assert_eq!(uri, "sqlite:./my%20secrets.db?history=true");
        let reparsed = Box::<dyn Provider>::try_from(uri.as_str()).unwrap();
        assert_eq!(reparsed.uri(), uri);
    }

    #[test]
    fn history_does_not_change_the_storage_identity() {
        let plain = provider(PathBuf::from("./secrets.db"));
        let with_history = history_provider(PathBuf::from("./secrets.db"));
        assert_ne!(plain.uri(), with_history.uri());
        assert_eq!(plain.storage_identity(), with_history.storage_identity());
    }

    #[test]
    fn relative_path_is_rebased_to_the_manifest() {
        let mut provider = provider(PathBuf::from("data/secrets.db"));
        provider.with_base_dir(Path::new("/project"));
        assert_eq!(
            provider.config.path,
            PathBuf::from("/project/data/secrets.db")
        );
    }

    #[test]
    fn write_target_description_names_the_file_and_item_without_creating_them() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("not-created").join("secrets.db");
        let provider = provider(path.clone());
        let target = provider.describe_write_target(convention("KEY")).unwrap();
        assert!(target.contains(&path.display().to_string()), "{target}");
        assert!(target.contains("project/production/KEY"), "{target}");
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn database_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("secrets.db");
        provider(path.clone())
            .set(convention("KEY"), &SecretBytes::from_utf8("value"))
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn get_many_reads_multiple_entries_and_omits_missing_ones() {
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("secrets.db"));
        provider
            .set(convention("ONE"), &SecretBytes::from_utf8("one"))
            .unwrap();
        provider
            .set(convention("TWO"), &SecretBytes::from_utf8("two"))
            .unwrap();

        let results = provider
            .get_many(&[
                ("FIRST", convention("ONE")),
                ("SECOND", convention("TWO")),
                ("MISSING", convention("THREE")),
            ])
            .unwrap();
        assert_eq!(results["FIRST"].expose_secret(), b"one");
        assert_eq!(results["SECOND"].expose_secret(), b"two");
        assert!(!results.contains_key("MISSING"));
    }

    #[test]
    fn concurrent_writes_preserve_both_entries() {
        let temp = TempDir::new().unwrap();
        let provider = std::sync::Arc::new(provider(temp.path().join("secrets.db")));
        std::thread::scope(|scope| {
            for (name, value) in [("ONE", "one"), ("TWO", "two")] {
                let provider = std::sync::Arc::clone(&provider);
                scope.spawn(move || {
                    provider
                        .set(convention(name), &SecretBytes::from_utf8(value))
                        .unwrap();
                });
            }
        });
        assert_eq!(
            provider
                .get(convention("ONE"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"one"
        );
        assert_eq!(
            provider
                .get(convention("TWO"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"two"
        );
    }

    #[test]
    fn native_item_addresses_an_arbitrary_row() {
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("secrets.db"));
        let address = NativeAddress {
            item: "shared/anything".to_string(),
            ..Default::default()
        };
        provider
            .set(Address::Native(&address), &SecretBytes::from_utf8("value"))
            .unwrap();
        assert_eq!(
            provider
                .get(Address::Native(&address))
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"value"
        );
    }

    #[test]
    fn unsupported_native_coordinate_is_rejected_even_before_the_database_exists() {
        // `get`/`delete` resolve the address before checking file existence,
        // so an invalid coordinate is never misreported as "not found" just
        // because the store has not been created yet.
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("secrets.db"));
        let address = NativeAddress {
            item: "KEY".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&address)).unwrap_err();
        assert!(error.to_string().contains("`field`"), "{error}");
        let error = provider.delete(Address::Native(&address)).unwrap_err();
        assert!(error.to_string().contains("`field`"), "{error}");
        let error = provider
            .get_many(&[("KEY", Address::Native(&address))])
            .unwrap_err();
        assert!(error.to_string().contains("`field`"), "{error}");
    }

    #[test]
    fn a_plain_store_has_no_history_tables() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("secrets.db");
        provider(path.clone())
            .set(convention("KEY"), &SecretBytes::from_utf8("v"))
            .unwrap();

        let conn = Connection::open(&path).unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(tables, ["secrets"]);
    }

    #[test]
    fn foreign_keys_are_enforced_on_every_connection_this_provider_hands_out() {
        // `foreign_keys` is per-connection and off by default, so without the
        // pragma the REFERENCES clauses on captured_values are documentation:
        // a tombstone could name a `destroyed_by` sequence no entry has, and
        // the store would accept it.
        let dir = TempDir::new().unwrap();
        let provider = history_provider(dir.path().join("secrets.db"));
        provider
            .set(convention("APP_SECRET"), &SecretBytes::from_utf8("v"))
            .unwrap();

        let conn = provider.connection().unwrap();
        let enabled: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(enabled, 1, "foreign key enforcement must be on");

        // Give the row a real blob, so the only thing wrong with it is the
        // entry reference. Without this the `blob_id IS NOT NULL OR
        // destroyed_by IS NOT NULL` check fires first and the assertion below
        // passes without the foreign key ever being consulted.
        conn.execute(
            "INSERT INTO value_blobs (item, value_sha256, value_blob) VALUES ('x', 'd', x'00')",
            [],
        )
        .unwrap();
        let blob_id: i64 = conn
            .query_row(
                "SELECT blob_id FROM value_blobs WHERE item = 'x' AND value_sha256 = 'd'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // And prove it actually bites, rather than merely being reported on.
        let orphan = conn.execute(
            "INSERT INTO captured_values (sequence, item, value_sha256, blob_id) \
             VALUES (99999, 'x', 'd', ?1)",
            params![blob_id],
        );
        // Asserting the *reason*, not just `is_err()`, so a statement that
        // fails for an unrelated reason (a renamed column, say) cannot keep
        // this test green while testing nothing.
        let error = orphan.expect_err("a captured value referencing no entry must be refused");
        assert!(
            matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            ),
            "must be refused by a constraint, got: {error}"
        );
        assert!(
            error.to_string().contains("FOREIGN KEY"),
            "must be refused by the foreign key specifically, got: {error}"
        );
    }

    #[test]
    fn history_is_captured_when_enabled() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("secrets.db");
        let provider = history_provider(db_path.clone());

        provider
            .set(convention("APP_SECRET"), &SecretBytes::from_utf8("initial"))
            .unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let entries: i64 = conn
            .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entries, 1);

        let captured: i64 = conn
            .query_row("SELECT count(*) FROM captured_values", [], |row| row.get(0))
            .unwrap();
        assert_eq!(captured, 1);

        provider.delete(convention("APP_SECRET")).unwrap();

        let entries_after_delete: i64 = conn
            .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entries_after_delete, 2);
    }

    #[test]
    fn history_entries_form_a_verifiable_hash_chain() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("secrets.db");
        let provider = history_provider(db_path.clone());
        provider
            .set(convention("A"), &SecretBytes::from_utf8("one"))
            .unwrap();
        provider
            .set(convention("B"), &SecretBytes::from_utf8("two"))
            .unwrap();
        provider.delete(convention("A")).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT sequence, timestamp_ns, operation, previous_hash, entry_hash \
                 FROM entries ORDER BY sequence",
            )
            .unwrap();
        let entries: Vec<(i64, i64, String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].3, ZERO_HASH);

        let mut previous = ZERO_HASH.to_string();
        for (sequence, timestamp_ns, operation, previous_hash, entry_hash) in &entries {
            assert_eq!(
                previous_hash, &previous,
                "entry {sequence} breaks the chain"
            );
            let mut captured = conn
                .prepare(
                    "SELECT item, value_sha256 FROM captured_values \
                     WHERE sequence = ?1 ORDER BY item",
                )
                .unwrap();
            let values: Vec<CapturedValue> = captured
                .query_map(params![sequence], |row| {
                    Ok(CapturedValue {
                        item: row.get(0)?,
                        value_sha256: row.get(1)?,
                    })
                })
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            let entry = Entry {
                sequence: *sequence,
                timestamp_ns: *timestamp_ns,
                operation: operation.clone(),
                values,
                previous_hash: previous_hash.clone(),
                entry_hash: String::new(),
            };
            assert_eq!(
                &compute_entry_hash(previous_hash, &entry),
                entry_hash,
                "entry {sequence} does not hash to its stored entry_hash"
            );
            previous = entry_hash.clone();
        }

        let (head_sequence, head_hash): (i64, String) = conn
            .query_row("SELECT sequence, entry_hash FROM head", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(head_sequence, 3);
        assert_eq!(head_hash, previous);
        assert_eq!(entries[2].2, "delete", "the last entry records the delete");
    }

    /// A provider with history on, holding one captured value, plus the id of
    /// the blob that value lives in.
    fn history_with_one_capture(path: &Path) -> (SqliteProvider, Connection, i64) {
        let provider = history_provider(path.to_path_buf());
        provider
            .set(convention("KEY"), &SecretBytes::from_utf8("v"))
            .unwrap();
        let conn = provider.connection().unwrap();
        let blob_id: i64 = conn
            .query_row("SELECT blob_id FROM value_blobs", [], |row| row.get(0))
            .unwrap();
        (provider, conn, blob_id)
    }

    #[test]
    fn a_blob_a_live_snapshot_still_references_cannot_be_deleted() {
        let dir = TempDir::new().unwrap();
        let (_provider, conn, blob_id) = history_with_one_capture(&dir.path().join("secrets.db"));

        let error = conn
            .execute(
                "DELETE FROM value_blobs WHERE blob_id = ?1",
                params![blob_id],
            )
            .expect_err("a blob a live snapshot references must not be deletable");
        assert!(
            error.to_string().contains("FOREIGN KEY"),
            "must be refused by ON DELETE RESTRICT, got: {error}"
        );
    }

    #[test]
    fn a_tombstone_cannot_be_resurrected_even_when_its_value_returns() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secrets.db");
        let (provider, conn, blob_id) = history_with_one_capture(&path);

        // Tombstone the snapshot with a single-column write and drop the bytes
        // it released.
        conn.execute(
            "INSERT INTO entries (timestamp_ns, operation, previous_hash, entry_hash) \
             VALUES (0, 'destroy', 'p', 'h')",
            [],
        )
        .unwrap();
        let destroyer: i64 = conn.last_insert_rowid();
        // `capture_history` takes the next sequence from `head`, so an entry
        // written by hand has to advance it too or the `set` below collides.
        conn.execute(
            "UPDATE head SET sequence = ?1, entry_hash = 'h' WHERE singleton = 1",
            params![destroyer],
        )
        .unwrap();
        conn.execute(
            "UPDATE captured_values SET destroyed_by = ?1 WHERE sequence = 1",
            params![destroyer],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM value_blobs WHERE blob_id = ?1",
            params![blob_id],
        )
        .expect("once tombstoned, the blob releases and can be removed");

        // The same value comes back under the same name: byte-identical, same
        // digest, same item, which is the case that used to make the
        // tombstone restorable again.
        provider
            .set(convention("KEY"), &SecretBytes::from_utf8("v"))
            .unwrap();
        let recreated: i64 = conn
            .query_row(
                "SELECT blob_id FROM value_blobs ORDER BY blob_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(
            recreated, blob_id,
            "precondition: AUTOINCREMENT must not reissue the freed id, or the \
             dangling reference below would become valid again and this test \
             would prove nothing"
        );

        let error = conn
            .execute(
                "UPDATE captured_values SET destroyed_by = NULL WHERE sequence = 1",
                [],
            )
            .expect_err("a tombstone must not be clearable");
        // The trigger is deliberately not the only guard here: with it removed
        // the foreign key still refuses, because the row's `blob_id` names a
        // blob that no longer exists.
        assert!(
            error.to_string().contains("write-once") || error.to_string().contains("FOREIGN KEY"),
            "must be refused by the trigger or the foreign key, got: {error}"
        );
    }

    #[test]
    fn captured_values_rows_cannot_be_deleted_or_their_tombstones_rewritten() {
        let dir = TempDir::new().unwrap();
        let (_provider, conn, _) = history_with_one_capture(&dir.path().join("secrets.db"));

        let deleted = conn
            .execute("DELETE FROM captured_values WHERE sequence = 1", [])
            .expect_err("history rows must not be deletable");
        assert!(
            deleted.to_string().contains("append-only"),
            "must be refused by the append-only trigger, got: {deleted}"
        );

        conn.execute(
            "INSERT INTO entries (timestamp_ns, operation, previous_hash, entry_hash) \
             VALUES (0, 'destroy', 'p', 'h')",
            [],
        )
        .unwrap();
        let first: i64 = conn.last_insert_rowid();
        conn.execute(
            "UPDATE captured_values SET destroyed_by = ?1 WHERE sequence = 1",
            params![first],
        )
        .expect("the first tombstone must be allowed");

        // Re-attributing an existing tombstone to a different entry would let
        // the ledger disagree with itself about what destroyed a value.
        let rewritten = conn
            .execute(
                "UPDATE captured_values SET destroyed_by = ?1 WHERE sequence = 1",
                params![first],
            )
            .expect_err("destroyed_by must not be rewritable");
        assert!(
            rewritten.to_string().contains("write-once"),
            "must be refused by the write-once trigger, got: {rewritten}"
        );
    }

    #[test]
    fn a_tombstone_may_not_name_an_entry_at_or_before_its_own_sequence() {
        let dir = TempDir::new().unwrap();
        let (_provider, conn, _) = history_with_one_capture(&dir.path().join("secrets.db"));

        let error = conn
            .execute(
                "UPDATE captured_values SET destroyed_by = 1 WHERE sequence = 1",
                [],
            )
            .expect_err("a value cannot be destroyed by the entry that captured it");
        assert!(
            error.to_string().contains("CHECK"),
            "must be refused by the ordering check, got: {error}"
        );
    }

    #[test]
    fn a_fresh_database_is_created_already_at_the_current_version() {
        let dir = TempDir::new().unwrap();
        let provider = history_provider(dir.path().join("secrets.db"));
        provider
            .set(convention("APP_SECRET"), &SecretBytes::from_utf8("v"))
            .unwrap();

        let conn = provider.connection().unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert!(has_current_shape(&conn).unwrap());
    }

    #[test]
    fn a_database_from_an_older_version_is_refused_rather_than_written_to() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("secrets.db");

        // A pre-v2 `captured_values`: no `blob_id`, and `user_version` still 0,
        // which is exactly what an old database on disk looks like.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE captured_values (\
                     sequence INTEGER NOT NULL,\
                     item TEXT NOT NULL,\
                     value_sha256 TEXT NOT NULL,\
                     destroyed_by INTEGER,\
                     PRIMARY KEY (sequence, item)\
                 ) STRICT;",
            )
            .unwrap();
        }

        let provider = history_provider(db_path.clone());
        let error = provider
            .connection()
            .expect_err("an older database must be refused, not written to");
        let message = error.to_string();
        assert!(
            message.contains("predates the current schema"),
            "the refusal must say what is wrong and what to do, got: {message}"
        );

        // And it must refuse without leaving a version behind that would make
        // the next open believe the database is current.
        let conn = Connection::open(&db_path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 0, "a refused open must not stamp a version");
    }

    #[test]
    fn a_database_from_a_newer_version_is_refused() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("secrets.db");
        let provider = history_provider(db_path.clone());
        provider
            .set(convention("APP_SECRET"), &SecretBytes::from_utf8("v"))
            .unwrap();

        Connection::open(&db_path)
            .unwrap()
            .execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1))
            .unwrap();

        let error = provider
            .connection()
            .expect_err("a database from a newer build must be refused");
        assert!(error.to_string().contains("newer version"), "got: {error}");
    }

    #[test]
    fn repeated_captures_of_one_value_store_its_bytes_once() {
        let dir = TempDir::new().unwrap();
        let provider = history_provider(dir.path().join("secrets.db"));

        // Setting a second, unrelated secret re-snapshots the first one, which
        // is exactly how history grows with entries x secrets.
        provider
            .set(convention("APP_SECRET"), &SecretBytes::from_utf8("held"))
            .unwrap();
        for i in 0..4 {
            provider
                .set(
                    convention(&format!("OTHER_{i}")),
                    &SecretBytes::from_utf8("x"),
                )
                .unwrap();
        }

        let conn = provider.connection().unwrap();
        let captured: i64 = conn
            .query_row(
                "SELECT count(*) FROM captured_values WHERE item = ?1",
                params!["project/production/APP_SECRET"],
                |row| row.get(0),
            )
            .unwrap();
        let blobs: i64 = conn
            .query_row(
                "SELECT count(*) FROM value_blobs WHERE item = ?1",
                params!["project/production/APP_SECRET"],
                |row| row.get(0),
            )
            .unwrap();

        assert!(
            captured > 1,
            "the value should be captured in several snapshots, got {captured}"
        );
        assert_eq!(blobs, 1, "but its bytes should be stored exactly once");
    }
}

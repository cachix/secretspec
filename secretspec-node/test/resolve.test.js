'use strict';

const assert = require('node:assert');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

// Build the secretspec-ffi cdylib and point the SDK at it, unless
// SECRETSPEC_FFI_LIB is already set.
function ensureLib() {
  if (process.env.SECRETSPEC_FFI_LIB) return;
  const repo = path.resolve(__dirname, '..', '..');
  execFileSync('cargo', ['build', '-p', 'secretspec-ffi'], { cwd: repo, stdio: 'inherit' });
  const meta = JSON.parse(
    execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1'], { cwd: repo }),
  );
  const name =
    process.platform === 'darwin' ? 'libsecretspec_ffi.dylib' : 'libsecretspec_ffi.so';
  process.env.SECRETSPEC_FFI_LIB = path.join(meta.target_directory, 'debug', name);
}

ensureLib();
const {
  SecretSpec,
  MissingRequiredError,
  SecretSpecError,
  abiVersion,
} = require('../index.js');

const MANIFEST = `
[project]
name = "node-test"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "DB", required = true }
LOG_LEVEL = { description = "log", required = false, default = "info" }
SENTRY_DSN = { description = "sentry", required = false }
`;

function project(dotenv, manifest = MANIFEST) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-node-'));
  const manifestPath = path.join(dir, 'secretspec.toml');
  const envPath = path.join(dir, '.env');
  fs.writeFileSync(manifestPath, manifest);
  fs.writeFileSync(envPath, dotenv);
  return { manifestPath, provider: `dotenv://${envPath}` };
}

test('abiVersion is non-empty', () => {
  assert.ok(abiVersion().length > 0);
});

test('load returns values and provenance', () => {
  const { manifestPath, provider } = project('DATABASE_URL=postgres://db\n');

  const resolved = SecretSpec.builder()
    .withPath(manifestPath)
    .withProvider(provider)
    .withReason('node test')
    .load();

  assert.equal(resolved.profile, 'default');
  const db = resolved.secrets.DATABASE_URL;
  assert.equal(db.get(), 'postgres://db');
  assert.equal(db.source, 'provider');
  assert.ok(db.sourceProvider);

  const log = resolved.secrets.LOG_LEVEL;
  assert.equal(log.get(), 'info');
  assert.equal(log.source, 'default');

  assert.deepEqual(resolved.missingOptional, ['SENTRY_DSN']);
  assert.ok(!('SENTRY_DSN' in resolved.secrets));
});

test('setAsEnv exports secrets', () => {
  const { manifestPath, provider } = project('DATABASE_URL=postgres://db\n');
  delete process.env.DATABASE_URL;

  SecretSpec.builder()
    .withPath(manifestPath)
    .withProvider(provider)
    .withReason('node test')
    .load()
    .setAsEnv();

  assert.equal(process.env.DATABASE_URL, 'postgres://db');
});

test('missing required throws MissingRequiredError', () => {
  const { manifestPath, provider } = project('');

  assert.throws(
    () =>
      SecretSpec.builder()
        .withPath(manifestPath)
        .withProvider(provider)
        .withReason('node test')
        .load(),
    (err) => err instanceof MissingRequiredError && err.missing.includes('DATABASE_URL'),
  );
});

test('as_path returns a readable file path', () => {
  const manifest = `
[project]
name = "node-test"
revision = "1.0"

[profiles.default]
TLS_CERT = { description = "cert", required = true, as_path = true }
`;
  const { manifestPath, provider } = project('TLS_CERT=----cert----\n', manifest);

  const resolved = SecretSpec.builder()
    .withPath(manifestPath)
    .withProvider(provider)
    .withReason('node test')
    .load();

  const cert = resolved.secrets.TLS_CERT;
  assert.equal(cert.asPath, true);
  assert.equal(cert.value, null);
  assert.equal(fs.readFileSync(cert.get(), 'utf8'), '----cert----');
});

test('invalid manifest throws SecretSpecError (not MissingRequired)', () => {
  assert.throws(
    () =>
      SecretSpec.builder()
        .withPath('/definitely/does/not/exist/secretspec.toml')
        .withReason('node test')
        .load(),
    (err) =>
      err instanceof SecretSpecError &&
      !(err instanceof MissingRequiredError) &&
      typeof err.kind === 'string',
  );
});

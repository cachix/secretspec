'use strict';

// End-to-end codegen pipeline:
//   secretspec schema  ->  quicktype  ->  toSecretSpec(resolved.fieldsJson())
// Proves the schema we emit drives quicktype to a typed deserializer that
// consumes the runtime SDK's flat fields map.

const assert = require('node:assert');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..', '..');

function hasNpx() {
  try {
    execFileSync('bash', ['-lc', 'command -v npx'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function ensureAddon() {
  if (fs.existsSync(path.resolve(__dirname, '..', 'secretspec.node'))) return;
  execFileSync('bash', [path.resolve(__dirname, '..', 'scripts', 'build-addon.sh')], {
    stdio: 'inherit',
  });
}

function secretspecBin() {
  execFileSync('cargo', ['build', '-p', 'secretspec'], { cwd: REPO, stdio: 'inherit' });
  const meta = JSON.parse(
    execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1'], { cwd: REPO }),
  );
  return path.join(meta.target_directory, 'debug', 'secretspec');
}

const MANIFEST = `
[project]
name = "node-codegen"
revision = "1.0"

[profiles.default]
DATABASE_URL = { required = true }
LOG_LEVEL = { required = false, default = "info" }
SENTRY_DSN = { required = false }
`;

test('quicktype-generated converter consumes fieldsJson()', { skip: !hasNpx() }, () => {
  ensureAddon();
  const { SecretSpec } = require('../index.js');
  const bin = secretspecBin();

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-node-cg-'));
  const manifest = path.join(dir, 'secretspec.toml');
  const env = path.join(dir, '.env');
  fs.writeFileSync(manifest, MANIFEST);
  fs.writeFileSync(env, 'DATABASE_URL=postgres://db\n');

  const schema = path.join(dir, 'schema.json');
  execFileSync(bin, ['-f', manifest, 'schema', '-o', schema]);

  const generated = path.join(dir, 'gen.js');
  // On Windows npx is npx.cmd, which spawn only reaches through a shell.
  execFileSync('npx', [
    '--yes', 'quicktype', '-s', 'schema', schema,
    '--top-level', 'SecretSpec', '--lang', 'javascript', '-o', generated,
  ], { shell: process.platform === 'win32' });

  const { toSecretSpec } = require(generated);

  const resolved = SecretSpec.builder()
    .withPath(manifest)
    .withProvider(`dotenv://${env}`)
    .withReason('node codegen')
    .load();

  const typed = toSecretSpec(resolved.fieldsJson());
  assert.equal(typed.DATABASE_URL, 'postgres://db');
  assert.equal(typed.LOG_LEVEL, 'info'); // from default
});

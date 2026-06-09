'use strict';

// Cross-language conformance: resolve the shared fixtures and assert this SDK
// produces the canonical result every other SDK must also produce.

const assert = require('node:assert');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function ensureAddon() {
  const addon = path.resolve(__dirname, '..', 'secretspec.node');
  if (fs.existsSync(addon)) return;
  execFileSync('bash', [path.resolve(__dirname, '..', 'scripts', 'build-addon.sh')], {
    stdio: 'inherit',
  });
}

ensureAddon();
const { SecretSpec } = require('../index.js');

const FIXTURES = path.resolve(__dirname, '..', '..', 'conformance', 'fixtures');

function canonical(resolved) {
  const secrets = {};
  for (const [name, secret] of Object.entries(resolved.secrets)) {
    const value = secret.asPath ? fs.readFileSync(secret.get(), 'utf8') : secret.value;
    secrets[name] = { value, source: secret.source, as_path: secret.asPath };
  }
  return {
    profile: resolved.profile,
    secrets,
    missing_required: [],
    missing_optional: [...resolved.missingOptional].sort(),
  };
}

for (const fixture of fs.readdirSync(FIXTURES).sort()) {
  const dir = path.join(FIXTURES, fixture);
  if (!fs.statSync(dir).isDirectory()) continue;

  test(`conformance: ${fixture}`, () => {
    const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
    const resolved = SecretSpec.builder()
      .withPath(path.join(dir, 'secretspec.toml'))
      .withProvider(`dotenv://${path.join(dir, '.env')}`)
      .withReason('conformance')
      .load();

    assert.deepStrictEqual(canonical(resolved), expected);
  });
}

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
    const resolved = builder(dir).load();

    assert.deepStrictEqual(canonical(resolved), expected);
  });

  test(`conformance no_values: ${fixture}`, () => {
    // Under no_values every SDK must emit the same all-null fields map: a
    // value-less secret serializes to null, not an empty string.
    const expected = JSON.parse(
      fs.readFileSync(path.join(dir, 'expected_no_values.json'), 'utf8'),
    );
    const resolved = builder(dir).withNoValues().load();
    try {
      assert.deepStrictEqual(JSON.parse(resolved.fieldsJson()), expected);
    } finally {
      resolved.dispose();
    }
  });

  test(`conformance report: ${fixture}`, () => {
    // The value-free report (status + provenance) is identical across SDKs.
    const expected = JSON.parse(
      fs.readFileSync(path.join(dir, 'expected_report.json'), 'utf8'),
    );
    const report = builder(dir).report();

    assert.deepStrictEqual(canonicalReport(report), expected);
  });
}

function builder(dir) {
  return SecretSpec.builder()
    .withPath(path.join(dir, 'secretspec.toml'))
    .withProvider(`dotenv://${path.join(dir, '.env')}`)
    .withReason('conformance');
}

function canonicalReport(report) {
  const secrets = {};
  for (const s of report.secrets) {
    secrets[s.name] = {
      status: s.status,
      required: s.required,
      as_path: s.asPath,
      generated: s.generated,
      default_applied: s.defaultApplied,
      // Present-or-not (not the path-dependent value) so the vector is
      // machine-independent yet still catches a dropped source_provider.
      source_provider: s.sourceProvider != null,
    };
  }
  return { profile: report.profile, secrets };
}

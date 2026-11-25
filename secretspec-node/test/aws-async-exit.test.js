'use strict';

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const PACKAGE_DIR = path.resolve(__dirname, '..');

function ensureAddon() {
  const addon = path.join(PACKAGE_DIR, 'secretspec.node');
  if (fs.existsSync(addon)) return;
  require('node:child_process').execFileSync(
    'bash',
    [path.join(PACKAGE_DIR, 'scripts', 'build-addon.sh')],
    { stdio: 'inherit' },
  );
}

function manifest(provider) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-node-aws-exit-'));
  const manifestPath = path.join(dir, 'secretspec.toml');
  const [uri, item] = provider === 'awsps'
    ? ['awsps://us-east-1', '/demo/parameter']
    : ['awssm://us-east-1', 'demo/secret'];
  fs.writeFileSync(manifestPath, `
[project]
name = "node-aws-exit"
revision = "1.0"

[providers]
aws = "${uri}"

[profiles.default.defaults]
providers = ["aws"]
required = true

[profiles.default]
SECRET = { description = "AWS secret", ref = { item = "${item}" } }
`);
  return manifestPath;
}

function mockResponse(provider) {
  if (provider === 'awsps') {
    return {
      Parameters: [{
        ARN: 'arn:aws:ssm:us-east-1:123456789012:parameter/demo/parameter',
        DataType: 'text',
        Name: '/demo/parameter',
        Type: 'SecureString',
        Value: 'parameter-value',
        Version: 1,
      }],
      InvalidParameters: [],
    };
  }
  return {
    SecretValues: [{
      ARN: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:demo/secret',
      Name: 'demo/secret',
      SecretString: 'secret-value',
      VersionId: '00000000-0000-0000-0000-000000000000',
      VersionStages: ['AWSCURRENT'],
    }],
    Errors: [],
  };
}

async function mockAws(provider) {
  const server = http.createServer((request, response) => {
    request.resume();
    response.writeHead(200, {
      'content-type': 'application/x-amz-json-1.1',
      'x-amzn-requestid': '00000000-0000-0000-0000-000000000000',
    });
    response.end(JSON.stringify(mockResponse(provider)));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server;
}

function runAsyncResolve(manifestPath, endpoint) {
  const script = `
    const { SecretSpec } = require(${JSON.stringify(PACKAGE_DIR)});
    (async () => {
      const resolved = await SecretSpec.builder()
        .withPath(process.argv[1])
        .withReason('AWS async exit regression')
        .loadAsync();
      console.log(resolved.secrets.SECRET.get());
      resolved.dispose();
    })().catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
  `;

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', script, manifestPath], {
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: 'test',
        AWS_SECRET_ACCESS_KEY: 'test',
        AWS_REGION: 'us-east-1',
        AWS_EC2_METADATA_DISABLED: 'true',
        AWS_ENDPOINT_URL: endpoint,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`child did not exit after resolving (stdout: ${stdout}, stderr: ${stderr})`));
    }, 5_000);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(`child exited with code ${code}, signal ${signal}: ${stderr}`));
      }
    });
  });
}

ensureAddon();

for (const provider of ['awsps', 'awssm']) {
  test(`loadAsync exits cleanly after resolving with ${provider}`, async (t) => {
    const server = await mockAws(provider);
    t.after(() => server.close());
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const value = await runAsyncResolve(
      manifest(provider),
      `http://127.0.0.1:${address.port}`,
    );
    assert.equal(value, provider === 'awsps' ? 'parameter-value' : 'secret-value');
  });
}

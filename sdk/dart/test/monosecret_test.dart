import 'dart:convert';
import 'dart:io';

import 'package:monosecret/monosecret.dart';
import 'package:test/test.dart';

void main() {
  group('MonosecretClient.get', () {
    test('returns stdout with trailing CLI whitespace removed', () async {
      final cli = await _fakeCli(r'''
#!/usr/bin/env sh
printf 'secret-value  \n\n'
''');

      final client = MonosecretClient(executable: cli.path);

      expect(await client.get('API_KEY'), 'secret-value');
    });

    test(
      'passes secret name and optional profile/provider/file flags',
      () async {
        final dir = await Directory.systemTemp.createTemp(
          'monosecret_dart_test_',
        );
        addTearDown(() => dir.delete(recursive: true));

        final argsFile = File('${dir.path}/args.json');
        final cli = await _recordingCli(argsFile: argsFile, stdout: 'value\n');
        final client = MonosecretClient(executable: cli.path);

        await client.get(
          'DATABASE_URL',
          profile: 'production',
          provider: 'op',
          file: 'monosecret.production.toml',
        );

        expect(await _readRecordedArgs(argsFile), [
          'get',
          'DATABASE_URL',
          '--profile',
          'production',
          '--provider',
          'op',
          '--file',
          'monosecret.production.toml',
        ]);
      },
    );
  });

  group('MonosecretClient.check', () {
    test('uses --no-prompt by default and forwards selectors', () async {
      final dir = await Directory.systemTemp.createTemp(
        'monosecret_dart_test_',
      );
      addTearDown(() => dir.delete(recursive: true));

      final argsFile = File('${dir.path}/args.json');
      final cli = await _recordingCli(argsFile: argsFile);
      final client = MonosecretClient(executable: cli.path);

      await client.check(
        profile: 'ci',
        provider: 'env',
        file: 'monosecret.ci.toml',
      );

      expect(await _readRecordedArgs(argsFile), [
        'check',
        '--no-prompt',
        '--profile',
        'ci',
        '--provider',
        'env',
        '--file',
        'monosecret.ci.toml',
      ]);
    });

    test('omits --no-prompt when disabled', () async {
      final dir = await Directory.systemTemp.createTemp(
        'monosecret_dart_test_',
      );
      addTearDown(() => dir.delete(recursive: true));

      final argsFile = File('${dir.path}/args.json');
      final cli = await _recordingCli(argsFile: argsFile);
      final client = MonosecretClient(executable: cli.path);

      await client.check(noPrompt: false);

      expect(await _readRecordedArgs(argsFile), ['check']);
    });
  });

  group('MonosecretClient.loadEnvironment', () {
    test(
      'passes include/group selectors and returns injected environment',
      () async {
        final dir = await Directory.systemTemp.createTemp(
          'monosecret_dart_test_',
        );
        addTearDown(() => dir.delete(recursive: true));

        final argsFile = File('${dir.path}/args.json');
        final cli = await _environmentCli(
          argsFile: argsFile,
          injectedEnvironment: {
            'DATABASE_URL': 'postgres://localhost/app',
            'API_KEY': 'abc123',
          },
        );
        final client = MonosecretClient(executable: cli.path);

        final environment = await client.loadEnvironment(
          include: ['DATABASE_URL', 'API_KEY'],
          groups: ['backend', 'workers'],
          profile: 'development',
          provider: 'dotenv',
          file: 'monosecret.toml',
        );

        expect(
          environment,
          containsPair('DATABASE_URL', 'postgres://localhost/app'),
        );
        expect(environment, containsPair('API_KEY', 'abc123'));
        expect(await _readRecordedArgs(argsFile), [
          'run',
          '--profile',
          'development',
          '--provider',
          'dotenv',
          '--file',
          'monosecret.toml',
          '--include',
          'DATABASE_URL',
          '--include',
          'API_KEY',
          '--group',
          'backend',
          '--group',
          'workers',
          '--',
          if (Platform.isWindows) ...['cmd', '/c', 'set'] else ...['env'],
        ]);
      },
    );

    test('parses environment lines and preserves equals signs in values',
        () async {
      final cli = await _fakeCli('''
#!/usr/bin/env sh
printf 'DATABASE_URL=postgres://localhost/app\nTOKEN=value=with=equals\nIGNORED_LINE\n'
''');
      final client = MonosecretClient(executable: cli.path);

      expect(await client.loadEnvironment(), {
        'DATABASE_URL': 'postgres://localhost/app',
        'TOKEN': 'value=with=equals',
      });
    });
  });

  group('process configuration', () {
    test('passes custom environment to the CLI process', () async {
      final cli = await _fakeCli(r'''
#!/usr/bin/env sh
printf '%s' "$MONOSECRET_TEST_TOKEN"
''');
      final client = MonosecretClient(
        executable: cli.path,
        environment: {'MONOSECRET_TEST_TOKEN': 'from-client-env'},
      );

      expect(await client.get('TOKEN'), 'from-client-env');
    });

    test('runs the CLI from the configured working directory', () async {
      final dir = await Directory.systemTemp.createTemp(
        'monosecret_dart_test_',
      );
      addTearDown(() => dir.delete(recursive: true));

      final cli = await _fakeCli(r'''
#!/usr/bin/env sh
pwd
''');
      final client = MonosecretClient(
        executable: cli.path,
        workingDirectory: dir.path,
      );

      expect(
        await File(await client.get('PWD')).resolveSymbolicLinks(),
        await dir.resolveSymbolicLinks(),
      );
    });
  });

  group('MonosecretException', () {
    test('captures command, exit code, stdout, stderr, and message', () async {
      final cli = await _fakeCli(r'''
#!/usr/bin/env sh
echo "partial output"
echo "boom" >&2
exit 7
''');
      final client = MonosecretClient(executable: cli.path);

      await expectLater(
        client.check(profile: 'ci'),
        throwsA(
          isA<MonosecretException>()
              .having((error) => error.args, 'args', [
                'check',
                '--no-prompt',
                '--profile',
                'ci',
              ])
              .having((error) => error.exitCode, 'exitCode', 7)
              .having((error) => error.stdout, 'stdout', 'partial output\n')
              .having((error) => error.stderr, 'stderr', 'boom\n')
              .having(
                (error) => error.toString(),
                'toString',
                contains(
                  'monosecret check --no-prompt --profile ci failed with exit code 7: boom',
                ),
              ),
        ),
      );
    });
  });
}

Future<File> _fakeCli(String source) async {
  final dir = await Directory.systemTemp.createTemp('monosecret_dart_test_');
  addTearDown(() => dir.delete(recursive: true));

  final file = File('${dir.path}/monosecret');
  await file.writeAsString(source);
  await _makeExecutable(file);
  return file;
}

Future<File> _recordingCli({required File argsFile, String stdout = ''}) {
  return _fakeCli('''
#!/usr/bin/env sh
${_writeArgsSnippet(argsFile.path)}
printf '%s' ${shellQuote(stdout)}
''');
}

Future<File> _environmentCli({
  required File argsFile,
  required Map<String, String> injectedEnvironment,
}) {
  final exports = injectedEnvironment.entries
      .map((entry) => 'export ${entry.key}=${shellQuote(entry.value)}')
      .join('\n');

  return _fakeCli('''
#!/usr/bin/env sh
${_writeArgsSnippet(argsFile.path)}
while [ "\$#" -gt 0 ]; do
  if [ "\$1" = "--" ]; then
    shift
    break
  fi
  shift
done
$exports
exec "\$@"
''');
}

String _writeArgsSnippet(String path) => '''
ARGS_FILE=${shellQuote(path)}
: > "\$ARGS_FILE"
for arg do
  printf '%s\n' "\$arg" >> "\$ARGS_FILE"
done
''';

Future<List<String>> _readRecordedArgs(File file) async {
  return const LineSplitter().convert(await file.readAsString());
}

Future<void> _makeExecutable(File file) async {
  final result = await Process.run('chmod', ['+x', file.path]);
  if (result.exitCode != 0) {
    throw StateError('chmod failed: ${result.stderr}');
  }
}

String shellQuote(String value) => "'${value.replaceAll("'", "'\\''")}'";

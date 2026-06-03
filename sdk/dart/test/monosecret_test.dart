import 'dart:io';

import 'package:monosecret/monosecret.dart';
import 'package:test/test.dart';

void main() {
  test('get returns trimmed command output', () async {
    final script = await _fakeCli(r'''
#!/usr/bin/env sh
if [ "$1" = "get" ]; then
  echo "secret-value"
  exit 0
fi
exit 2
''');

    final client = MonosecretClient(executable: script.path);

    expect(await client.get('API_KEY'), 'secret-value');
  });

  test('throws when command exits non-zero', () async {
    final script = await _fakeCli(r'''
#!/usr/bin/env sh
echo "boom" >&2
exit 7
''');

    final client = MonosecretClient(executable: script.path);

    expect(
      () => client.check(),
      throwsA(
        isA<MonosecretException>().having(
          (error) => error.exitCode,
          'exitCode',
          7,
        ),
      ),
    );
  });
}

Future<File> _fakeCli(String source) async {
  final dir = await Directory.systemTemp.createTemp('monosecret_dart_test_');
  final file = File('${dir.path}/monosecret');
  await file.writeAsString(source);
  await Process.run('chmod', ['+x', file.path]);
  return file;
}

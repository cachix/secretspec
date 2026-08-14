import 'dart:convert';
import 'dart:io';

import 'package:monosecret/monosecret.dart';
import 'package:test/test.dart';

void main() {
  final fixtures = _fixturesDirectory();
  final cases = fixtures.listSync().whereType<Directory>().toList()
    ..sort((left, right) => left.path.compareTo(right.path));

  for (final directory in cases) {
    final name = directory.uri.pathSegments
        .where((segment) => segment.isNotEmpty)
        .last;

    test('$name resolve conformance', () async {
      final expected = await _jsonFile(directory, 'expected.json');
      final resolved = await _builder(directory).load();

      try {
        expect(await _canonicalResolved(resolved), expected);
      } finally {
        await resolved.close();
      }
    });

    test('$name no-values conformance', () async {
      final expected = await _jsonFile(directory, 'expected_no_values.json');
      final resolved = await _builder(directory).withNoValues().load();

      try {
        expect(resolved.fields, expected);
      } finally {
        await resolved.close();
      }
    });

    test('$name report conformance', () async {
      final expected = await _jsonFile(directory, 'expected_report.json');
      final report = await _builder(directory).report();

      expect(_canonicalReport(report), expected);
    });
  }

  test('reports typed constraint violations', () async {
    final directory = Directory(
      '${fixtures.parent.path}/constraint-violations',
    );
    final report = await _builder(directory).report();
    final violations = {
      for (final violation in report.constraintViolations)
        violation.kind: violation,
    };

    expect(
      violations.keys,
      unorderedEquals([
        ConstraintViolationKind.atLeastOne,
        ConstraintViolationKind.exactlyOne,
      ]),
    );
    expect(violations[ConstraintViolationKind.atLeastOne]!.group, 'cloud');
    expect(violations[ConstraintViolationKind.atLeastOne]!.present, isEmpty);
    expect(violations[ConstraintViolationKind.exactlyOne]!.group, 'token');
    expect(violations[ConstraintViolationKind.exactlyOne]!.present, [
      'FALLBACK',
      'PRIMARY',
    ]);
  });
}

Directory _fixturesDirectory() {
  var directory = Directory.current.absolute;

  while (true) {
    final fixtures = Directory('${directory.path}/conformance/fixtures');
    if (fixtures.existsSync()) {
      return fixtures;
    }

    final parent = directory.parent;
    if (parent.path == directory.path) {
      throw StateError(
        'Could not find conformance/fixtures from ${Directory.current}.',
      );
    }
    directory = parent;
  }
}

MonosecretBuilder _builder(Directory directory) {
  return Monosecret.builder()
      .withPath('${directory.path}/monosecret.toml')
      .withProvider('dotenv://${directory.path}/.env')
      .withReason('Dart conformance');
}

Future<Map<String, Object?>> _jsonFile(Directory directory, String name) async {
  return (jsonDecode(await File('${directory.path}/$name').readAsString())
      as Map<String, Object?>);
}

Future<Map<String, Object?>> _canonicalResolved(Resolved resolved) async {
  final secrets = <String, Object?>{};

  for (final entry in resolved.secrets.entries) {
    final secret = entry.value;
    final value = secret.asPath
        ? await File(secret.path!).readAsString()
        : secret.value;
    secrets[entry.key] = {
      'value': value,
      'source': secret.source,
      'as_path': secret.asPath,
    };
  }

  return {
    'profile': resolved.profile,
    'secrets': secrets,
    'missing_required': <String>[],
    'missing_optional': [...resolved.missingOptional]..sort(),
  };
}

Map<String, Object?> _canonicalReport(ResolutionReport report) {
  return {
    'profile': report.profile,
    'secrets': {
      for (final secret in report.secrets)
        secret.name: {
          'status': secret.status,
          'required': secret.required,
          'as_path': secret.asPath,
          'generated': secret.generated,
          'default_applied': secret.defaultApplied,
          'source_provider': secret.sourceProvider != null,
        },
    },
  };
}

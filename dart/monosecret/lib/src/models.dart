import 'dart:io';

/// A native resolution failure.
class MonosecretException implements Exception {
  const MonosecretException(this.kind, this.message);

  final String kind;
  final String message;

  @override
  String toString() => '$message (kind: $kind)';
}

/// Required secrets that could not be resolved.
class MissingRequiredException extends MonosecretException {
  MissingRequiredException(Iterable<String> missing)
    : missing = List.unmodifiable(missing),
      super(
        'missing_required',
        'Missing required secret(s): ${missing.join(', ')}',
      );

  final List<String> missing;
}

/// One resolved secret.
class ResolvedSecret {
  const ResolvedSecret({
    required this.value,
    required this.path,
    required this.asPath,
    required this.source,
    required this.sourceProvider,
  });

  final String? value;
  final String? path;
  final bool asPath;
  final String source;
  final String? sourceProvider;

  /// The file path for an `as_path` secret, otherwise its value.
  String? get usable => asPath ? path : value;
}

/// A successful native resolution.
class Resolved {
  Resolved({
    required this.provider,
    required this.profile,
    required this.scope,
    required Map<String, ResolvedSecret> secrets,
    required Iterable<String> missingOptional,
  }) : secrets = Map.unmodifiable(secrets),
       missingOptional = List.unmodifiable(missingOptional);

  final String provider;
  final String profile;
  final String? scope;
  final Map<String, ResolvedSecret> secrets;
  final List<String> missingOptional;

  /// A flat map suitable for typed generated deserializers.
  Map<String, String?> get fields => Map.unmodifiable({
    for (final entry in secrets.entries) entry.key: entry.value.usable,
  });

  /// Deletes temporary files created for `as_path` secrets.
  Future<void> close() async {
    for (final secret in secrets.values) {
      final path = secret.path;
      if (!secret.asPath || path == null) {
        continue;
      }

      final file = File(path);
      if (await file.exists()) {
        await file.delete();
      }
    }
  }
}

/// Value-free resolution information for one secret.
class SecretReport {
  const SecretReport({
    required this.name,
    required this.status,
    required this.required,
    required this.sourceProvider,
    required this.defaultApplied,
    required this.generated,
    required this.asPath,
  });

  final String name;
  final String status;
  final bool required;
  final String? sourceProvider;
  final bool defaultApplied;
  final bool generated;
  final bool asPath;
}

/// The kind of a failed cross-secret presence constraint.
enum ConstraintViolationKind { atLeastOne, exactlyOne }

/// A failed cross-secret presence constraint in a resolution report.
class ConstraintViolation {
  ConstraintViolation({
    required this.kind,
    required this.group,
    required Iterable<String> secrets,
    required Iterable<String> present,
  }) : secrets = List.unmodifiable(secrets),
       present = List.unmodifiable(present);

  final ConstraintViolationKind kind;
  final String group;
  final List<String> secrets;
  final List<String> present;
}

/// A value-free resolution snapshot.
class ResolutionReport {
  ResolutionReport({
    required this.provider,
    required this.profile,
    required this.scope,
    required Iterable<SecretReport> secrets,
    Iterable<ConstraintViolation> constraintViolations = const [],
  }) : secrets = List.unmodifiable(secrets),
       constraintViolations = List.unmodifiable(constraintViolations);

  final String provider;
  final String profile;
  final String? scope;
  final List<SecretReport> secrets;
  final List<ConstraintViolation> constraintViolations;
}

Resolved parseResolved(Map<String, Object?> response) {
  final missingRequired = _stringList(response['missing_required']);
  if (missingRequired.isNotEmpty) {
    throw MissingRequiredException(missingRequired);
  }

  final rawSecrets = _map(response['secrets'], 'response.secrets');
  final secrets = <String, ResolvedSecret>{};

  for (final entry in rawSecrets.entries) {
    final secret = _map(entry.value, 'response.secrets.${entry.key}');
    secrets[entry.key] = ResolvedSecret(
      value: secret['value'] as String?,
      path: secret['path'] as String?,
      asPath: secret['as_path'] as bool? ?? false,
      source: secret['source'] as String? ?? '',
      sourceProvider: secret['source_provider'] as String?,
    );
  }

  return Resolved(
    provider: _string(response, 'provider'),
    profile: _string(response, 'profile'),
    scope: response['scope'] as String?,
    secrets: secrets,
    missingOptional: _stringList(response['missing_optional']),
  );
}

ResolutionReport parseReport(Map<String, Object?> response) {
  final rawSecrets = response['secrets'];
  if (rawSecrets is! List<Object?>) {
    throw const MonosecretException(
      'ffi',
      'Native report response has an invalid secrets field.',
    );
  }

  return ResolutionReport(
    provider: _string(response, 'provider'),
    profile: _string(response, 'profile'),
    scope: response['scope'] as String?,
    secrets: rawSecrets.map((value) {
      final secret = _map(value, 'response.secrets[]');
      return SecretReport(
        name: _string(secret, 'name'),
        status: _string(secret, 'status'),
        required: secret['required'] as bool? ?? false,
        sourceProvider: secret['source_provider'] as String?,
        defaultApplied: secret['default_applied'] as bool? ?? false,
        generated: secret['generated'] as bool? ?? false,
        asPath: secret['as_path'] as bool? ?? false,
      );
    }),
    constraintViolations:
        (response['constraint_violations'] as List<Object?>? ?? const []).map((
          value,
        ) {
          final violation = _map(value, 'response.constraint_violations[]');
          return ConstraintViolation(
            kind: _constraintViolationKind(_string(violation, 'kind')),
            group: _string(violation, 'group'),
            secrets: _stringList(violation['secrets']),
            present: _stringList(violation['present']),
          );
        }),
  );
}

ConstraintViolationKind _constraintViolationKind(String value) =>
    switch (value) {
      'at_least_one' => ConstraintViolationKind.atLeastOne,
      'exactly_one' => ConstraintViolationKind.exactlyOne,
      _ => throw MonosecretException(
        'ffi',
        'Native report response has an invalid constraint kind: $value.',
      ),
    };

Map<String, Object?> parseEnvelope(
  Object? decoded, {
  required String kind,
  required int expectedSchemaVersion,
}) {
  final envelope = _map(decoded, 'envelope');
  if (envelope['ok'] != true) {
    final error = _map(envelope['error'], 'envelope.error');
    throw MonosecretException(
      error['kind'] as String? ?? 'unknown',
      error['message'] as String? ?? '',
    );
  }

  final response = _map(envelope['response'], 'envelope.response');
  final schemaVersion = response['schema_version'];
  if (schemaVersion != expectedSchemaVersion) {
    throw MonosecretException(
      'version',
      'Unsupported $kind schema version $schemaVersion '
          '(expected $expectedSchemaVersion).',
    );
  }

  return response;
}

Map<String, Object?> _map(Object? value, String name) {
  if (value is Map<String, Object?>) {
    return value;
  }

  throw MonosecretException('ffi', 'Native response has an invalid $name.');
}

String _string(Map<String, Object?> value, String key) {
  final field = value[key];
  if (field is String) {
    return field;
  }

  throw MonosecretException('ffi', 'Native response has an invalid $key.');
}

List<String> _stringList(Object? value) {
  if (value == null) {
    return const [];
  }

  if (value is! List<Object?> || value.any((entry) => entry is! String)) {
    throw const MonosecretException(
      'ffi',
      'Native response has an invalid string list.',
    );
  }

  return value.cast<String>();
}

import 'dart:convert';

import 'package:source_gen/source_gen.dart';

import 'manifest.dart';

String generateMonosecretLibrary({
  required String className,
  required MonosecretManifest manifest,
}) {
  final names = _GeneratedNames.fromClassName(className);
  final profiles = _identifiers(manifest.profiles.keys, prefix: 'profile');
  final secrets = _identifiers(manifest.secretNames, prefix: 'secret');
  final groups = _identifiers(manifest.groups, prefix: 'group');
  final buffer = StringBuffer()
    ..writeln(_enumDeclaration(names.profileEnum, profiles))
    ..writeln()
    ..writeln(_enumDeclaration(names.secretEnum, secrets))
    ..writeln();

  if (groups.isNotEmpty) {
    buffer
      ..writeln(_enumDeclaration(names.groupEnum, groups))
      ..writeln();
  }

  buffer
    ..writeln(_classDeclaration(className, names, manifest, secrets, groups))
    ..writeln()
    ..writeln(_extensionDeclaration(className, names, groups));

  return buffer.toString();
}

String _enumDeclaration(String enumName, Map<String, String> values) {
  final entries = values.entries.toList();
  final buffer = StringBuffer()..writeln('enum $enumName {');

  for (var index = 0; index < entries.length; index += 1) {
    final entry = entries[index];
    final separator = index == entries.length - 1 ? ';' : ',';
    buffer.writeln('  ${entry.value}(${jsonEncode(entry.key)})$separator');
  }

  buffer
    ..writeln()
    ..writeln('  const $enumName(this.name);')
    ..writeln()
    ..writeln('  final String name;')
    ..writeln('}');

  return buffer.toString();
}

String _classDeclaration(
  String className,
  _GeneratedNames names,
  MonosecretManifest manifest,
  Map<String, String> secrets,
  Map<String, String> groups,
) {
  final constructorFields = secrets.entries
      .map((entry) => '    required this.${entry.value},')
      .join('\n');
  final fields = secrets.entries
      .map((entry) {
        final nullable = manifest.isSecretNullable(entry.key) ? '?' : '';
        return '  final String$nullable ${entry.value};';
      })
      .join('\n');
  final assignments = secrets.entries
      .map((entry) {
        final fieldName = entry.value;
        final secretName = entry.key;
        final read = manifest.isSecretNullable(secretName)
            ? 'environment[${jsonEncode(secretName)}]'
            : '_required(environment, ${jsonEncode(secretName)})';
        return '      $fieldName: $read,';
      })
      .join('\n');
  final groupParameter = groups.isEmpty
      ? ''
      : '    Iterable<${names.groupEnum}> groups = const [],\n';
  final groupArgument = groups.isEmpty
      ? '      groups: const [],\n'
      : '      groups: groups.map((group) => group.name),\n';
  final selectedSecrets = groups.isEmpty
      ? 'include ?? ${names.secretEnum}.values'
      : 'include ??\n'
            '        (groups.isEmpty\n'
            '            ? ${names.secretEnum}.values\n'
            '            : const <${names.secretEnum}>[])';

  return '''final class $className {
  const $className({
$constructorFields
  });

$fields

  static Future<$className> load({
    MonosecretClient? client,
    ${names.profileEnum}? profile,
    String? provider,
    String? file,
    String? scope,
    String? reason,
    Iterable<${names.secretEnum}>? include,
$groupParameter  }) async {
    final selectedSecrets = $selectedSecrets;
    final environment = await (client ?? MonosecretClient()).exportEnvironment(
      include: selectedSecrets.map((secret) => secret.name),
$groupArgument      profile: profile?.name,
      provider: provider,
      file: file,
      scope: scope,
      reason: reason,
    );

    return $className.fromEnvironment(environment);
  }

  factory $className.fromEnvironment(Map<String, String> environment) {
    return $className(
$assignments
    );
  }

  static String _required(Map<String, String> environment, String name) {
    final value = environment[name];
    if (value == null) {
      throw StateError('Required Monosecret secret "\$name" was not loaded.');
    }
    return value;
  }
}''';
}

String _extensionDeclaration(
  String className,
  _GeneratedNames names,
  Map<String, String> groups,
) {
  final groupParameter = groups.isEmpty
      ? ''
      : '    Iterable<${names.groupEnum}> groups = const [],\n';
  final groupArgument = groups.isEmpty ? '' : '      groups: groups,\n';

  return '''extension ${names.clientExtension} on MonosecretClient {
  Future<String> ${names.getSecretMethod}(
    ${names.secretEnum} secret, {
    ${names.profileEnum}? profile,
    String? provider,
    String? file,
    String? scope,
    String? reason,
  }) {
    return get(
      secret.name,
      profile: profile?.name,
      provider: provider,
      file: file,
      scope: scope,
      reason: reason,
    );
  }

  Future<$className> ${names.loadMethod}({
    ${names.profileEnum}? profile,
    String? provider,
    String? file,
    String? scope,
    String? reason,
    Iterable<${names.secretEnum}>? include,
$groupParameter  }) {
    return $className.load(
      client: this,
      profile: profile,
      provider: provider,
      file: file,
      scope: scope,
      reason: reason,
      include: include,
$groupArgument    );
  }
}''';
}

Map<String, String> _identifiers(
  Iterable<String> names, {
  required String prefix,
}) {
  final identifiers = <String, String>{};
  final seen = <String, String>{};
  final sorted = names.toList()..sort();

  for (final name in sorted) {
    final identifier = _lowerCamel(name, fallbackPrefix: prefix);
    final existing = seen[identifier];
    if (existing != null) {
      throw InvalidGenerationSourceError(
        'Monosecret names $existing and $name both generate identifier $identifier.',
      );
    }
    seen[identifier] = name;
    identifiers[name] = identifier;
  }

  return identifiers;
}

String _lowerCamel(String value, {required String fallbackPrefix}) {
  final words = _words(value);
  if (words.isEmpty) {
    return fallbackPrefix;
  }

  final first = words.first.toLowerCase();
  final rest = words.skip(1).map(_upperFirst).join();
  return _safeIdentifier('$first$rest', fallbackPrefix: fallbackPrefix);
}

String _upperCamel(String value, {required String fallbackPrefix}) {
  final words = _words(value);
  final identifier = words.isEmpty
      ? fallbackPrefix
      : words.map(_upperFirst).join();
  return _safeIdentifier(identifier, fallbackPrefix: fallbackPrefix);
}

List<String> _words(String value) {
  return value
      .split(RegExp('[^A-Za-z0-9]+'))
      .where((word) => word.isNotEmpty)
      .toList(growable: false);
}

String _upperFirst(String value) {
  final lower = value.toLowerCase();
  return '${lower[0].toUpperCase()}${lower.substring(1)}';
}

String _safeIdentifier(String value, {required String fallbackPrefix}) {
  final buffer = StringBuffer();
  for (var index = 0; index < value.length; index += 1) {
    final char = value[index];
    final isAllowed = RegExp(r'[A-Za-z0-9_]').hasMatch(char);
    buffer.write(isAllowed ? char : '_');
  }

  var identifier = buffer.toString();
  if (identifier.isEmpty || RegExp(r'^[0-9]').hasMatch(identifier)) {
    identifier =
        '$fallbackPrefix${_upperFirst(identifier.isEmpty ? fallbackPrefix : identifier)}';
  }
  if (_dartKeywords.contains(identifier)) {
    identifier = '${identifier}_';
  }
  return identifier;
}

final class _GeneratedNames {
  const _GeneratedNames({
    required this.profileEnum,
    required this.secretEnum,
    required this.groupEnum,
    required this.clientExtension,
    required this.getSecretMethod,
    required this.loadMethod,
  });

  final String profileEnum;
  final String secretEnum;
  final String groupEnum;
  final String clientExtension;
  final String getSecretMethod;
  final String loadMethod;

  factory _GeneratedNames.fromClassName(String className) {
    final base =
        className.endsWith('Secrets') && className.length > 'Secrets'.length
        ? className.substring(0, className.length - 'Secrets'.length)
        : className;
    final safeBase = _upperCamel(base, fallbackPrefix: 'Monosecret');
    return _GeneratedNames(
      profileEnum: '${safeBase}Profile',
      secretEnum: '${safeBase}Secret',
      groupEnum: '${safeBase}SecretGroup',
      clientExtension: '${safeBase}SecretsClient',
      getSecretMethod: 'get${safeBase}Secret',
      loadMethod: 'load${safeBase}Secrets',
    );
  }
}

const _dartKeywords = {
  'abstract',
  'as',
  'assert',
  'async',
  'await',
  'base',
  'break',
  'case',
  'catch',
  'class',
  'const',
  'continue',
  'covariant',
  'default',
  'deferred',
  'do',
  'dynamic',
  'else',
  'enum',
  'export',
  'extends',
  'extension',
  'external',
  'factory',
  'false',
  'final',
  'finally',
  'for',
  'Function',
  'get',
  'hide',
  'if',
  'implements',
  'import',
  'in',
  'interface',
  'is',
  'late',
  'library',
  'mixin',
  'new',
  'null',
  'on',
  'operator',
  'part',
  'required',
  'rethrow',
  'return',
  'sealed',
  'set',
  'show',
  'static',
  'super',
  'switch',
  'sync',
  'this',
  'throw',
  'true',
  'try',
  'type',
  'typedef',
  'var',
  'void',
  'when',
  'with',
  'while',
  'yield',
};

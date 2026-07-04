import 'package:toml/toml.dart';

/// Parsed, secret-value-free Monosecret manifest used for code generation.
final class MonosecretManifest {
  const MonosecretManifest({
    required this.projectName,
    required this.profiles,
    required this.groups,
  });

  final String projectName;
  final Map<String, ManifestProfile> profiles;
  final Set<String> groups;

  Iterable<String> get secretNames sync* {
    final names = <String>{};
    for (final profile in profiles.values) {
      names.addAll(profile.secrets.keys);
    }
    final sorted = names.toList()..sort();
    yield* sorted;
  }

  bool isSecretNullable(String name) {
    for (final profile in profiles.values) {
      final secret = profile.secrets[name];
      if (secret == null || !secret.required) {
        return true;
      }
    }
    return false;
  }

  factory MonosecretManifest.parse(String content) {
    final map = TomlDocument.parse(content).toMap();
    return MonosecretManifest.fromMap(map);
  }

  factory MonosecretManifest.fromMap(Map<String, dynamic> map) {
    final project = _asMap(map['project'], 'project');
    final revision = project['revision'];
    if (revision != '1.0') {
      throw FormatException('Unsupported monosecret.toml revision: $revision');
    }

    final projectName = project['name'];
    if (projectName is! String || projectName.isEmpty) {
      throw const FormatException('monosecret.toml must define project.name');
    }

    final rawProfiles = _parseProfiles(_asMap(map['profiles'], 'profiles'));
    if (rawProfiles.isEmpty) {
      throw const FormatException(
        'monosecret.toml must define at least one profile',
      );
    }

    final profiles = _effectiveProfiles(rawProfiles);
    final groups = _parseGroups(map['groups']);

    return MonosecretManifest(
      projectName: projectName,
      profiles: profiles,
      groups: groups,
    );
  }
}

final class ManifestProfile {
  const ManifestProfile({required this.name, required this.secrets});

  final String name;
  final Map<String, ManifestSecret> secrets;
}

final class ManifestSecret {
  const ManifestSecret({
    required this.name,
    required this.required,
    required this.hasDefault,
    required this.asPath,
    required this.groups,
  });

  final String name;
  final bool required;
  final bool hasDefault;
  final bool asPath;
  final List<String> groups;
}

final class _RawProfile {
  const _RawProfile({required this.defaults, required this.secrets});

  final _ProfileDefaults defaults;
  final Map<String, _RawSecret> secrets;
}

final class _ProfileDefaults {
  const _ProfileDefaults({this.required, this.hasDefault = false});

  final bool? required;
  final bool hasDefault;
}

final class _RawSecret {
  const _RawSecret({
    this.required,
    this.hasDefault = false,
    this.asPath,
    this.groups,
  });

  final bool? required;
  final bool hasDefault;
  final bool? asPath;
  final List<String>? groups;
}

Map<String, _RawProfile> _parseProfiles(Map<String, dynamic> profiles) {
  final parsed = <String, _RawProfile>{};

  for (final entry in profiles.entries) {
    final profileMap = _asMap(entry.value, 'profiles.${entry.key}');
    final defaults = _parseProfileDefaults(profileMap['defaults']);
    final secrets = <String, _RawSecret>{};

    for (final secretEntry in profileMap.entries) {
      if (secretEntry.key == 'defaults') {
        continue;
      }
      if (secretEntry.value is! Map) {
        continue;
      }

      secrets[secretEntry.key] = _parseSecret(
        Map<String, dynamic>.from(secretEntry.value as Map),
      );
    }

    parsed[entry.key] = _RawProfile(defaults: defaults, secrets: secrets);
  }

  return parsed;
}

_ProfileDefaults _parseProfileDefaults(Object? value) {
  if (value is! Map) {
    return const _ProfileDefaults();
  }
  final map = Map<String, dynamic>.from(value);
  return _ProfileDefaults(
    required: map['required'] as bool?,
    hasDefault: map.containsKey('default'),
  );
}

_RawSecret _parseSecret(Map<String, dynamic> map) {
  return _RawSecret(
    required: map['required'] as bool?,
    hasDefault: map.containsKey('default'),
    asPath: map['as_path'] as bool?,
    groups: _parseStringList(map['groups']),
  );
}

Map<String, ManifestProfile> _effectiveProfiles(
  Map<String, _RawProfile> rawProfiles,
) {
  final result = <String, ManifestProfile>{};
  final defaultProfile = rawProfiles['default'];

  for (final entry in rawProfiles.entries) {
    final profileName = entry.key;
    final profile = entry.value;
    final secretNames = <String>{...profile.secrets.keys};
    if (profileName != 'default' && defaultProfile != null) {
      secretNames.addAll(defaultProfile.secrets.keys);
    }

    final secrets = <String, ManifestSecret>{};
    for (final name in secretNames) {
      final current = profile.secrets[name];
      final fallback =
          profileName == 'default' ? null : defaultProfile?.secrets[name];
      final secret = _effectiveSecret(
        name,
        current,
        fallback,
        profile.defaults,
      );
      if (secret != null) {
        secrets[name] = secret;
      }
    }

    result[profileName] = ManifestProfile(name: profileName, secrets: secrets);
  }

  return result;
}

ManifestSecret? _effectiveSecret(
  String name,
  _RawSecret? current,
  _RawSecret? fallback,
  _ProfileDefaults defaults,
) {
  if (current == null && fallback == null) {
    return null;
  }

  return ManifestSecret(
    name: name,
    required:
        current?.required ?? fallback?.required ?? defaults.required ?? true,
    hasDefault: current?.hasDefault == true ||
        fallback?.hasDefault == true ||
        defaults.hasDefault,
    asPath: current?.asPath ?? fallback?.asPath ?? false,
    groups: current?.groups ?? fallback?.groups ?? const [],
  );
}

Set<String> _parseGroups(Object? value) {
  if (value is! Map) {
    return const {};
  }
  return value.keys.map((key) => key.toString()).toSet();
}

List<String>? _parseStringList(Object? value) {
  if (value is! List) {
    return null;
  }
  return value.map((item) => item.toString()).toList(growable: false);
}

Map<String, dynamic> _asMap(Object? value, String name) {
  if (value is Map) {
    return Map<String, dynamic>.from(value);
  }
  throw FormatException('monosecret.toml must define [$name]');
}

import 'dart:convert';
import 'dart:isolate';

import 'models.dart';
import 'native_bindings.dart';
import 'version.dart';

const _resolveSchemaVersion = 1;
const _reportSchemaVersion = 1;

/// Entry point for native Monosecret resolution.
abstract final class Monosecret {
  static MonosecretBuilder builder() => MonosecretBuilder();
}

/// Configures one native resolution request.
class MonosecretBuilder {
  final Map<String, Object?> _request = {};

  MonosecretBuilder withPath(String? path) => _set('path', path);

  MonosecretBuilder withProvider(String? provider) =>
      _set('provider', provider);

  MonosecretBuilder withProfile(String? profile) => _set('profile', profile);

  MonosecretBuilder withReason(String? reason) => _set('reason', reason);

  MonosecretBuilder withNoValues([bool noValues = true]) =>
      _set('no_values', noValues);

  MonosecretBuilder withInclude(Iterable<String> include) =>
      _set('include', include.toList(growable: false));

  MonosecretBuilder withGroups(Iterable<String> groups) =>
      _set('groups', groups.toList(growable: false));

  /// Resolves secret values through the bundled native library.
  Future<Resolved> load() async {
    final response = await _requestNative(
      _request,
      kind: 'resolve',
      expectedSchemaVersion: _resolveSchemaVersion,
    );

    return parseResolved(response);
  }

  /// Produces a value-free resolution report.
  Future<ResolutionReport> report() async {
    final request = {..._request, 'mode': 'report'};
    final response = await _requestNative(
      request,
      kind: 'report',
      expectedSchemaVersion: _reportSchemaVersion,
    );

    return parseReport(response);
  }

  MonosecretBuilder _set(String key, Object? value) {
    if (value == null) {
      _request.remove(key);
    } else {
      _request[key] = value;
    }

    return this;
  }
}

/// Convenience client over the native builder API.
class MonosecretClient {
  const MonosecretClient();

  MonosecretBuilder builder() => Monosecret.builder();

  Future<Resolved> resolve({
    String? path,
    String? profile,
    String? provider,
    String? reason,
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
    bool noValues = false,
  }) {
    return builder()
        .withPath(path)
        .withProfile(profile)
        .withProvider(provider)
        .withReason(reason)
        .withInclude(include)
        .withGroups(groups)
        .withNoValues(noValues)
        .load();
  }

  Future<ResolutionReport> report({
    String? path,
    String? profile,
    String? provider,
    String? reason,
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
  }) {
    return builder()
        .withPath(path)
        .withProfile(profile)
        .withProvider(provider)
        .withReason(reason)
        .withInclude(include)
        .withGroups(groups)
        .report();
  }

  /// Resolves one named secret.
  ///
  /// Prefer [resolve] for an `as_path` secret so its temporary file can be
  /// closed explicitly after use.
  Future<String> get(
    String name, {
    String? profile,
    String? provider,
    String? file,
    String? reason,
  }) async {
    final resolved = await resolve(
      path: file,
      profile: profile,
      provider: provider,
      reason: reason,
      include: [name],
    );
    final secret = resolved.secrets[name];
    final value = secret?.usable;

    if (value == null) {
      await resolved.close();
      throw MonosecretException(
        'missing_secret',
        'Secret $name did not resolve to a value.',
      );
    }

    if (secret!.asPath) {
      return value;
    }

    await resolved.close();
    return value;
  }

  /// Resolves selected secrets into a flat environment map.
  ///
  /// Prefer [resolve] when using `as_path` so the returned [Resolved] can be
  /// closed explicitly after its temporary files are no longer needed.
  Future<Map<String, String>> exportEnvironment({
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
    String? profile,
    String? provider,
    String? file,
    String? reason,
  }) async {
    final resolved = await resolve(
      path: file,
      profile: profile,
      provider: provider,
      reason: reason,
      include: include,
      groups: groups,
    );
    final environment = <String, String>{
      for (final entry in resolved.fields.entries)
        if (entry.value != null) entry.key: entry.value!,
    };

    if (resolved.secrets.values.every((secret) => !secret.asPath)) {
      await resolved.close();
    }

    return environment;
  }
}

/// Returns the version exported by the bundled native library.
String abiVersion() => nativeAbiVersion();

Future<Map<String, Object?>> _requestNative(
  Map<String, Object?> request, {
  required String kind,
  required int expectedSchemaVersion,
}) async {
  final actualVersion = nativeAbiVersion();
  if (actualVersion != monosecretVersion) {
    throw MonosecretException(
      'version',
      'Native ABI version $actualVersion does not match Dart package version '
          '$monosecretVersion.',
    );
  }

  final requestJson = jsonEncode(request);
  final responseJson = await Isolate.run(() => nativeResolve(requestJson));
  final decoded = jsonDecode(responseJson);

  return parseEnvelope(
    decoded,
    kind: kind,
    expectedSchemaVersion: expectedSchemaVersion,
  );
}

import 'dart:convert';
import 'dart:io';

/// Marks a Dart library for typed Monosecret code generation.
///
/// Add this annotation to a library that declares a `part '<name>.g.dart';`, then
/// run `dart run build_runner build` with `monosecret_builder` in dev dependencies.
class MonosecretConfig {
  const MonosecretConfig({
    this.path = 'monosecret.toml',
    this.className = 'MonosecretSecrets',
  });

  /// Path to the Monosecret manifest, relative to the annotated library's package.
  final String path;

  /// Name of the generated secrets class.
  final String className;
}

/// Dart client for the `monosecret` CLI.
class MonosecretClient {
  MonosecretClient({
    this.executable = 'monosecret',
    this.workingDirectory,
    Map<String, String>? environment,
  }) : environment = environment ?? const {};

  final String executable;
  final String? workingDirectory;
  final Map<String, String> environment;

  Future<String> get(
    String name, {
    String? profile,
    String? provider,
    String? file,
  }) async {
    final result = await _run([
      'get',
      name,
      if (profile != null) ...['--profile', profile],
      if (provider != null) ...['--provider', provider],
      if (file != null) ...['--file', file],
    ]);
    return result.stdout.trimRight();
  }

  Future<void> check({
    String? profile,
    String? provider,
    String? file,
    bool noPrompt = true,
  }) async {
    await _run([
      'check',
      if (noPrompt) '--no-prompt',
      if (profile != null) ...['--profile', profile],
      if (provider != null) ...['--provider', provider],
      if (file != null) ...['--file', file],
    ]);
  }

  Future<Map<String, String>> loadEnvironment({
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
    String? profile,
    String? provider,
    String? file,
  }) async {
    final result = await _run([
      'run',
      if (profile != null) ...['--profile', profile],
      if (provider != null) ...['--provider', provider],
      if (file != null) ...['--file', file],
      for (final name in include) ...['--include', name],
      for (final group in groups) ...['--group', group],
      '--',
      if (Platform.isWindows) ...['cmd', '/c', 'set'] else ...['env'],
    ]);

    return _parseEnvironment(result.stdout);
  }

  /// Resolves Monosecret secrets and returns only the emitted secret environment.
  ///
  /// This uses `monosecret env --shell dotenv`, avoiding unrelated parent process
  /// variables that are present when using [loadEnvironment].
  Future<Map<String, String>> exportEnvironment({
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
    String? profile,
    String? provider,
    String? file,
  }) async {
    final result = await _run([
      'env',
      '--shell',
      'dotenv',
      if (profile != null) ...['--profile', profile],
      if (provider != null) ...['--provider', provider],
      if (file != null) ...['--file', file],
      for (final name in include) ...['--include', name],
      for (final group in groups) ...['--group', group],
    ]);

    return _parseDotenv(result.stdout);
  }

  Future<_ProcessOutput> _run(List<String> args) async {
    final result = await Process.run(
      executable,
      args,
      workingDirectory: workingDirectory,
      environment: environment,
    );

    if (result.exitCode != 0) {
      throw MonosecretException(
        args: args,
        exitCode: result.exitCode,
        stdout: result.stdout.toString(),
        stderr: result.stderr.toString(),
      );
    }

    return _ProcessOutput(result.stdout.toString(), result.stderr.toString());
  }
}

Map<String, String> _parseEnvironment(String stdout) {
  final environment = <String, String>{};

  for (final line in const LineSplitter().convert(stdout)) {
    final separator = line.indexOf('=');
    if (separator < 0) {
      continue;
    }

    environment[line.substring(0, separator)] = line.substring(separator + 1);
  }

  return environment;
}

Map<String, String> _parseDotenv(String stdout) {
  final environment = <String, String>{};

  for (final line in const LineSplitter().convert(stdout)) {
    if (line.trim().isEmpty || line.trimLeft().startsWith('#')) {
      continue;
    }

    final separator = line.indexOf('=');
    if (separator < 0) {
      continue;
    }

    final key = line.substring(0, separator).trim();
    final rawValue = line.substring(separator + 1).trim();
    environment[key] = _decodeDotenvValue(rawValue);
  }

  return environment;
}

String _decodeDotenvValue(String value) {
  if (value.length < 2 || !value.startsWith('"') || !value.endsWith('"')) {
    return value;
  }

  final buffer = StringBuffer();
  final inner = value.substring(1, value.length - 1);
  for (var index = 0; index < inner.length; index += 1) {
    final char = inner[index];
    if (char != r'\' || index == inner.length - 1) {
      buffer.write(char);
      continue;
    }

    index += 1;
    switch (inner[index]) {
      case 'n':
        buffer.write('\n');
        break;
      case 'r':
        buffer.write('\r');
        break;
      case '"':
        buffer.write('"');
        break;
      case r'\':
        buffer.write(r'\');
        break;
      default:
        buffer
          ..write(r'\')
          ..write(inner[index]);
    }
  }

  return buffer.toString();
}

class MonosecretException implements Exception {
  MonosecretException({
    required this.args,
    required this.exitCode,
    required this.stdout,
    required this.stderr,
  });

  final List<String> args;
  final int exitCode;
  final String stdout;
  final String stderr;

  @override
  String toString() =>
      "monosecret ${args.join(' ')} failed with exit code $exitCode: $stderr";
}

class _ProcessOutput {
  const _ProcessOutput(this.stdout, this.stderr);

  final String stdout;
  final String stderr;
}

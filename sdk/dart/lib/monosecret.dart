import 'dart:convert';
import 'dart:io';

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
      Platform.resolvedExecutable,
      '-e',
      'import "dart:convert"; import "dart:io"; void main() => stdout.write(jsonEncode(Platform.environment));',
    ]);

    final decoded = jsonDecode(result.stdout) as Map<String, dynamic>;
    return decoded.map((key, value) => MapEntry(key, value.toString()));
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

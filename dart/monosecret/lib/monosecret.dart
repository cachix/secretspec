/// Native Dart SDK for Monosecret.
library;

export 'src/client.dart';
export 'src/models.dart';
export 'src/version.dart';

/// Marks a Dart library for typed Monosecret code generation.
///
/// Add this annotation to a library that declares a `part '<name>.g.dart';`,
/// then run `dart run build_runner build` with `monosecret_builder` in the
/// development dependencies.
class MonosecretConfig {
  const MonosecretConfig({
    this.path = 'monosecret.toml',
    this.className = 'MonosecretSecrets',
  });

  /// Path to the Monosecret manifest, relative to the annotated package.
  final String path;

  /// Name of the generated secrets class.
  final String className;
}

// coverage:ignore-file

import 'package:analyzer/dart/element/element.dart';
import 'package:build/build.dart';
import 'package:monosecret/monosecret.dart';
import 'package:source_gen/source_gen.dart';

import 'generator.dart';
import 'manifest.dart';

/// Connects the pure Monosecret generator to source_gen/build_runner.
final class MonosecretGenerator
    extends GeneratorForAnnotation<MonosecretConfig> {
  @override
  Future<String> generateForAnnotatedElement(
    Element element,
    ConstantReader annotation,
    BuildStep buildStep,
  ) async {
    if (element is! LibraryElement) {
      throw InvalidGenerationSourceError(
        'MonosecretConfig can only annotate a library.',
        element: element,
      );
    }

    final path = annotation.read('path').stringValue;
    final className = annotation.read('className').stringValue;
    final manifestId = AssetId(buildStep.inputId.package, path);
    final content = await buildStep.readAsString(manifestId);
    final manifest = MonosecretManifest.parse(content);

    return generateMonosecretLibrary(className: className, manifest: manifest);
  }
}

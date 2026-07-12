import 'package:monosecret_builder/src/generator.dart';
import 'package:monosecret_builder/src/manifest.dart';
import 'package:source_gen/source_gen.dart';
import 'package:test/test.dart';

void main() {
  group('generateMonosecretLibrary', () {
    test(
      'generates typed profiles, secrets, groups, fields, and client helpers',
      () {
        final source = generateMonosecretLibrary(
          className: 'AppSecrets',
          manifest: MonosecretManifest.parse('''
[project]
name = "demo"
revision = "1.0"

[groups]
backend = "Backend services"

[profiles.default]
DATABASE_URL = { description = "Database", required = true, groups = ["backend"] }
OPTIONAL_TOKEN = { description = "Optional", required = false }

[profiles.ci]
PUB_TOKEN = { description = "Pub token", required = true }
'''),
        );

        expect(source, contains('enum AppProfile'));
        expect(source, contains('ci("ci")'));
        expect(source, contains('default_("default")'));
        expect(source, contains('enum AppSecret'));
        expect(source, contains('databaseUrl("DATABASE_URL")'));
        expect(source, contains('optionalToken("OPTIONAL_TOKEN")'));
        expect(source, contains('pubToken("PUB_TOKEN")'));
        expect(source, contains('enum AppSecretGroup'));
        expect(source, contains('backend("backend")'));
        expect(source, contains('final class AppSecrets'));
        expect(source, contains('final String databaseUrl;'));
        expect(source, contains('final String? optionalToken;'));
        expect(source, contains('final String? pubToken;'));
        expect(source, contains('Future<AppSecrets> loadAppSecrets'));
        expect(source, contains('Future<String> getAppSecret'));
        expect(source, contains('groups: groups.map((group) => group.name)'));
        expect(source, contains('String? reason'));
        expect(source, contains('reason: reason'));
        expect(
          source,
          contains(
            'groups.isEmpty\n'
            '            ? AppSecret.values\n'
            '            : const <AppSecret>[]',
          ),
        );
        expect(source, contains('_required(environment, "DATABASE_URL")'));
      },
    );

    test(
      'omits the group enum and group parameters when no groups are declared',
      () {
        final source = generateMonosecretLibrary(
          className: 'MonosecretSecrets',
          manifest: MonosecretManifest.parse('''
[project]
name = "demo"
revision = "1.0"

[profiles.default]
TOKEN = { description = "Token" }
'''),
        );

        expect(source, contains('enum MonosecretProfile'));
        expect(source, contains('enum MonosecretSecret'));
        expect(source, isNot(contains('enum MonosecretSecretGroup')));
        expect(
          source,
          isNot(contains('Iterable<MonosecretSecretGroup> groups')),
        );
        expect(source, contains('groups: const []'));
      },
    );

    test('rejects identifiers that would collide after camel-casing', () {
      final manifest = MonosecretManifest.parse('''
[project]
name = "demo"
revision = "1.0"

[profiles.default]
API_KEY = { description = "Token" }
api_key = { description = "Token" }
''');

      expect(
        () => generateMonosecretLibrary(
          className: 'AppSecrets',
          manifest: manifest,
        ),
        throwsA(isA<InvalidGenerationSourceError>()),
      );
    });

    test('prefixes identifiers that start with digits', () {
      final source = generateMonosecretLibrary(
        className: 'AppSecrets',
        manifest: MonosecretManifest.parse('''
[project]
name = "demo"
revision = "1.0"

[profiles.123-ci]
9TOKEN = { description = "Token" }
'''),
      );

      expect(source, contains('profile123ci("123-ci")'));
      expect(source, contains('secret9token("9TOKEN")'));
    });
  });
}

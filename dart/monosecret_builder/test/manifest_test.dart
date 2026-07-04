import 'package:monosecret_builder/src/manifest.dart';
import 'package:test/test.dart';

void main() {
  group('MonosecretManifest.parse', () {
    test(
      'parses profiles, inherited default secrets, defaults, and groups',
      () {
        final manifest = MonosecretManifest.parse('''
[project]
name = "demo"
revision = "1.0"

[groups]
backend = "Backend services"
worker = "Workers"

[profiles.default]
DATABASE_URL = { description = "Database", required = true, groups = ["backend"] }
LOG_LEVEL = { description = "Log level", required = false, default = "info" }
TLS_CERT = { description = "TLS certificate", as_path = true }

[profiles.development.defaults]
required = false

[profiles.development]
DATABASE_URL = { description = "Development database", default = "sqlite://dev.db" }
DEBUG_TOKEN = { description = "Debug token" }

[profiles.production]
API_KEY = { description = "API key", required = true }
''');

        expect(manifest.projectName, 'demo');
        expect(manifest.groups, {'backend', 'worker'});
        expect(manifest.secretNames, [
          'API_KEY',
          'DATABASE_URL',
          'DEBUG_TOKEN',
          'LOG_LEVEL',
          'TLS_CERT',
        ]);

        final development = manifest.profiles['development']!;
        expect(development.secrets['DATABASE_URL']!.required, true);
        expect(development.secrets['DATABASE_URL']!.hasDefault, true);
        expect(development.secrets['DEBUG_TOKEN']!.required, false);
        expect(development.secrets['LOG_LEVEL']!.required, false);
        expect(development.secrets['TLS_CERT']!.asPath, true);
        expect(development.secrets['TLS_CERT']!.required, false);
        expect(development.secrets['API_KEY'], isNull);

        final production = manifest.profiles['production']!;
        expect(production.secrets['DATABASE_URL']!.required, true);
        expect(production.secrets['API_KEY']!.required, true);
        expect(production.secrets['LOG_LEVEL']!.required, false);

        expect(manifest.isSecretNullable('DATABASE_URL'), false);
        expect(manifest.isSecretNullable('API_KEY'), true);
        expect(manifest.isSecretNullable('DEBUG_TOKEN'), true);
        expect(manifest.isSecretNullable('LOG_LEVEL'), true);
      },
    );

    test('rejects unsupported revisions', () {
      expect(
        () => MonosecretManifest.parse('''
[project]
name = "demo"
revision = "2.0"

[profiles.default]
TOKEN = { description = "Token" }
'''),
        throwsFormatException,
      );
    });

    test('requires project metadata and profiles', () {
      expect(
        () => MonosecretManifest.parse('''
[project]
revision = "1.0"

[profiles.default]
TOKEN = { description = "Token" }
'''),
        throwsFormatException,
      );

      expect(
        () => MonosecretManifest.parse('''
[project]
name = "demo"
revision = "1.0"
'''),
        throwsFormatException,
      );
    });
  });
}

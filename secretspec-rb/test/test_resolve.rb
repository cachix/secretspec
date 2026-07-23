# frozen_string_literal: true

require "json"
require "tmpdir"
require "minitest/autorun"

# Compile the native extension (statically linking libsecretspec_ffi.a) unless it
# is already built. ci-sdks.sh builds it explicitly; this covers standalone runs.
def ensure_ext
  pkg = File.expand_path("..", __dir__)
  return unless Dir[File.join(pkg, "lib", "secretspec", "secretspec_ext.{so,bundle}")].empty?

  system("bash", File.join(pkg, "scripts", "build-ext.sh")) || raise("build-ext.sh failed")
end

ensure_ext
require_relative "../lib/secretspec"

MANIFEST = <<~TOML
  [project]
  name = "rb-test"
  revision = "1.0"

  [profiles.default]
  DATABASE_URL = { description = "DB", required = true }
  LOG_LEVEL = { description = "log", required = false, default = "info" }
  SENTRY_DSN = { description = "sentry", required = false }

  [scopes.database]
  secrets = ["DATABASE_URL"]
TOML

def project(dir, dotenv, manifest: MANIFEST)
  manifest_path = File.join(dir, "secretspec.toml")
  env_path = File.join(dir, ".env")
  File.write(manifest_path, manifest)
  File.write(env_path, dotenv)
  [manifest_path, "dotenv://#{env_path}"]
end

class ResolveTest < Minitest::Test
  def test_abi_version_nonempty
    refute_empty Secretspec.abi_version
  end

  def test_load_values_and_provenance
    Dir.mktmpdir do |dir|
      manifest, provider = project(dir, "DATABASE_URL=postgres://db\n")

      resolved = Secretspec::SecretSpec.builder
                                       .with_path(manifest)
                                       .with_provider(provider)
                                       .with_reason("rb test")
                                       .load

      assert_equal "default", resolved.profile
      db = resolved.secrets["DATABASE_URL"]
      assert_equal "postgres://db", db.get
      assert_equal "provider", db.source
      refute_nil db.source_provider

      log = resolved.secrets["LOG_LEVEL"]
      assert_equal "info", log.get
      assert_equal "default", log.source

      assert_equal ["SENTRY_DSN"], resolved.missing_optional
      refute resolved.secrets.key?("SENTRY_DSN")
    end
  end

  def test_set_as_env
    Dir.mktmpdir do |dir|
      manifest, provider = project(dir, "DATABASE_URL=postgres://db\n")
      ENV.delete("DATABASE_URL")

      Secretspec::SecretSpec.builder
                            .with_path(manifest)
                            .with_provider(provider)
                            .with_reason("rb test")
                            .load
                            .set_as_env!

      assert_equal "postgres://db", ENV.fetch("DATABASE_URL")
    end
  end

  def test_scope_is_selected_and_returned
    Dir.mktmpdir do |dir|
      manifest, provider = project(
        dir,
        "DATABASE_URL=postgres://db\nSENTRY_DSN=https://sentry\n"
      )
      builder = Secretspec::SecretSpec.builder
                                       .with_path(manifest)
                                       .with_provider(provider)
                                       .with_scope("database")
                                       .with_reason("rb scoped test")

      resolved = builder.load
      assert_equal "database", resolved.scope
      assert_equal ["DATABASE_URL"], resolved.secrets.keys

      report = builder.report
      assert_equal "database", report.scope
      assert_equal ["DATABASE_URL"], report.secrets.map(&:name)
    end
  end

  def test_missing_required_raises
    Dir.mktmpdir do |dir|
      manifest, provider = project(dir, "")

      error = assert_raises(Secretspec::MissingRequiredError) do
        Secretspec::SecretSpec.builder
                              .with_path(manifest)
                              .with_provider(provider)
                              .with_reason("rb test")
                              .load
      end
      assert_includes error.missing, "DATABASE_URL"
    end
  end

  def test_as_path_returns_readable_file
    Dir.mktmpdir do |dir|
      manifest = <<~TOML
        [project]
        name = "rb-test"
        revision = "1.0"

        [profiles.default]
        TLS_CERT = { description = "cert", required = true, as_path = true }
      TOML
      manifest_path, provider = project(dir, "TLS_CERT=----cert----\n", manifest: manifest)

      # Block form closes the Resolved (removing the 0400 as_path temp file) so
      # the test leaves no secret-bearing file behind in the temp dir.
      Secretspec::SecretSpec.builder
                            .with_path(manifest_path)
                            .with_provider(provider)
                            .with_reason("rb test")
                            .load do |resolved|
        cert = resolved.secrets["TLS_CERT"]
        assert cert.as_path
        assert_nil cert.value
        assert_equal "----cert----", File.read(cert.get)
      end
    end
  end

  def test_invalid_manifest_raises_error
    error = assert_raises(Secretspec::Error) do
      Secretspec::SecretSpec.builder
                            .with_path("/definitely/does/not/exist/secretspec.toml")
                            .with_reason("rb test")
                            .load
    end
    refute_instance_of Secretspec::MissingRequiredError, error
    refute_empty error.kind
  end
end

# Cross-language conformance: resolve the shared fixtures and assert this SDK
# produces the canonical result every other SDK must also produce.
class ConformanceTest < Minitest::Test
  FIXTURES = File.expand_path("../../conformance/fixtures", __dir__)

  def canonical(resolved)
    secrets = {}
    resolved.secrets.each do |name, secret|
      value = secret.as_path ? File.read(secret.get) : secret.value
      secrets[name] = { "value" => value, "source" => secret.source, "as_path" => secret.as_path }
    end
    {
      "profile" => resolved.profile,
      "secrets" => secrets,
      "missing_required" => [],
      "missing_optional" => resolved.missing_optional.sort
    }
  end

  def canonical_report(report)
    secrets = {}
    report.secrets.each do |s|
      secrets[s.name] = {
        "status" => s.status,
        "required" => s.required,
        "as_path" => s.as_path,
        "generated" => s.generated,
        "default_applied" => s.default_applied,
        # Present-or-not (not the path-dependent value) so the vector is
        # machine-independent yet still catches a dropped source_provider.
        "source_provider" => !s.source_provider.nil?
      }
    end
    { "profile" => report.profile, "secrets" => secrets }
  end

  def conformance_builder(dir)
    Secretspec::SecretSpec.builder
                          .with_path(File.join(dir, "secretspec.toml"))
                          .with_provider("dotenv://#{File.join(dir, '.env')}")
                          .with_reason("conformance")
  end

  Dir.glob(File.join(FIXTURES, "*")).select { |p| File.directory?(p) }.sort.each do |dir|
    name = File.basename(dir)

    define_method("test_conformance_#{name}") do
      expected = JSON.parse(File.read(File.join(dir, "expected.json")))
      # Block form closes the Resolved so as_path temp files do not accumulate.
      conformance_builder(dir).load do |resolved|
        assert_equal expected, canonical(resolved)
      end
    end

    # Under no_values every SDK must emit the same all-null fields map: a
    # value-less secret serializes to null, not an empty string.
    define_method("test_conformance_no_values_#{name}") do
      expected = JSON.parse(File.read(File.join(dir, "expected_no_values.json")))
      conformance_builder(dir).with_no_values.load do |resolved|
        assert_equal expected, resolved.fields
      end
    end

    # The value-free report (status + provenance) is identical across SDKs.
    define_method("test_conformance_report_#{name}") do
      expected = JSON.parse(File.read(File.join(dir, "expected_report.json")))
      assert_equal expected, canonical_report(conformance_builder(dir).report)
    end
  end
end

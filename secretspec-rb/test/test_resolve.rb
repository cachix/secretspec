# frozen_string_literal: true

require "json"
require "rbconfig"
require "tmpdir"
require "minitest/autorun"

# Build the secretspec-ffi cdylib and point the SDK at it, unless
# SECRETSPEC_FFI_LIB is already set.
def ensure_lib
  return if ENV["SECRETSPEC_FFI_LIB"] && !ENV["SECRETSPEC_FFI_LIB"].empty?

  repo = File.expand_path("../..", __dir__)
  system("cargo", "build", "-p", "secretspec-ffi", chdir: repo) || raise("cargo build failed")
  meta = JSON.parse(`cd #{repo} && cargo metadata --no-deps --format-version 1`)
  name = RbConfig::CONFIG["host_os"] =~ /darwin/ ? "libsecretspec_ffi.dylib" : "libsecretspec_ffi.so"
  ENV["SECRETSPEC_FFI_LIB"] = File.join(meta["target_directory"], "debug", name)
end

ensure_lib
require_relative "../lib/secretspec"

MANIFEST = <<~TOML
  [project]
  name = "rb-test"
  revision = "1.0"

  [profiles.default]
  DATABASE_URL = { description = "DB", required = true }
  LOG_LEVEL = { description = "log", required = false, default = "info" }
  SENTRY_DSN = { description = "sentry", required = false }
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

      resolved = Secretspec::SecretSpec.builder
                                       .with_path(manifest_path)
                                       .with_provider(provider)
                                       .with_reason("rb test")
                                       .load

      cert = resolved.secrets["TLS_CERT"]
      assert cert.as_path
      assert_nil cert.value
      assert_equal "----cert----", File.read(cert.get)
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

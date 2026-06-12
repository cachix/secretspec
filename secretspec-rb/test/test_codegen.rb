# frozen_string_literal: true

# End-to-end codegen pipeline:
#   secretspec schema  ->  quicktype --lang ruby  ->  SecretSpec.from_dynamic!(resolved.fields)
# Proves the schema drives quicktype to a typed class that consumes the runtime
# SDK's flat fields hash.

require "json"
require "rbconfig"
require "tmpdir"
require "minitest/autorun"

REPO = File.expand_path("../..", __dir__)

def npx?
  system("bash", "-lc", "command -v npx", out: File::NULL, err: File::NULL)
end

def build_artifacts
  unless system("cargo", "build", "-p", "secretspec-ffi", "-p", "secretspec", chdir: REPO)
    raise "cargo build failed"
  end
  meta = JSON.parse(`cd #{REPO} && cargo metadata --no-deps --format-version 1`)
  target = meta["target_directory"]
  lib = RbConfig::CONFIG["host_os"] =~ /darwin/ ? "libsecretspec_ffi.dylib" : "libsecretspec_ffi.so"
  [File.join(target, "debug", lib), File.join(target, "debug", "secretspec")]
end

class CodegenTest < Minitest::Test
  def test_quicktype_ruby_consumes_fields
    skip "npx (quicktype) not available" unless npx?

    lib, bin = build_artifacts
    ENV["SECRETSPEC_FFI_LIB"] = lib

    Dir.mktmpdir do |dir|
      manifest = File.join(dir, "secretspec.toml")
      env_path = File.join(dir, ".env")
      File.write(manifest, <<~TOML)
        [project]
        name = "rb-codegen"
        revision = "1.0"

        [profiles.default]
        DATABASE_URL = { required = true }
        LOG_LEVEL = { required = false, default = "info" }
      TOML
      File.write(env_path, "DATABASE_URL=postgres://db\n")

      schema = File.join(dir, "schema.json")
      assert system(bin, "-f", manifest, "schema", "-o", schema), "schema failed"

      gen = File.join(dir, "gen.rb")
      assert system("npx", "--yes", "quicktype", "-s", "schema", schema,
                    "--top-level", "SecretSpec", "--lang", "ruby", "-o", gen),
             "quicktype failed"

      # quicktype's Ruby output needs dry-struct/dry-types; install them into a
      # throwaway gem home and make them requireable in-process.
      gemhome = File.join(dir, "gems")
      assert system("gem", "install", "--no-document", "--install-dir", gemhome,
                    "dry-struct", "dry-types", out: File::NULL),
             "gem install failed"
      Gem.use_paths(gemhome, [gemhome] + Gem.path)

      require gen
      require_relative "../lib/secretspec"

      resolved = Secretspec::SecretSpec.builder
                                       .with_path(manifest)
                                       .with_provider("dotenv://#{env_path}")
                                       .with_reason("rb codegen")
                                       .load
      typed = SecretSpec.from_dynamic!(resolved.fields)
      assert_equal "postgres://db", typed.database_url
      assert_equal "info", typed.log_level
    end
  end
end

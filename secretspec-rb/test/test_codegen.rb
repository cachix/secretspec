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

# Build the CLI (for `secretspec schema`) and compile the native extension (the
# resolver, statically linked). Returns the CLI path; the SDK loads the resolver
# from the compiled extension, not a runtime library.
def build_artifacts
  unless system("cargo", "build", "-p", "secretspec-ffi", "-p", "secretspec", chdir: REPO)
    raise "cargo build failed"
  end
  pkg = File.expand_path("..", __dir__)
  if Dir[File.join(pkg, "lib", "secretspec", "secretspec_ext.{so,bundle}")].empty?
    system("bash", File.join(pkg, "scripts", "build-ext.sh")) || raise("build-ext.sh failed")
  end
  meta = JSON.parse(`cd #{REPO} && cargo metadata --no-deps --format-version 1`)
  File.join(meta["target_directory"], "debug", "secretspec")
end

class CodegenTest < Minitest::Test
  def test_quicktype_ruby_consumes_fields
    skip "npx (quicktype) not available" unless npx?

    bin = build_artifacts

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

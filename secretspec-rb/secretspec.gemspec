# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = "secretspec"
  spec.version     = "0.12.0"
  spec.summary     = "Declarative secrets, every environment, any provider (Ruby SDK)"
  spec.description = "Ruby bindings for SecretSpec: a native extension that " \
                     "statically links the secretspec-ffi C ABI."
  spec.authors     = ["Cachix"]
  spec.license     = "Apache-2.0"
  spec.homepage    = "https://secretspec.dev/"
  spec.files       = Dir["lib/**/*.rb"] + Dir["ext/**/*.{c,rb}"] +
                     ["README.md"] + Dir["vendor/*"]
  spec.extensions  = ["ext/secretspec/extconf.rb"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.0"

  # The extension compiles a tiny C glue at `gem install` and statically links
  # the prebuilt libsecretspec_ffi.a staged into vendor/ (see
  # scripts/stage-staticlib.sh). The archive is platform-specific, so build a
  # platform gem when it is present; one such gem serves every Ruby ABI.
  staged = File.exist?("vendor/libsecretspec_ffi.a")
  spec.platform = Gem::Platform::CURRENT if staged
end

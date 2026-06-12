# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = "secretspec"
  spec.version     = "0.12.0"
  spec.summary     = "Declarative secrets, every environment, any provider (Ruby SDK)"
  spec.description = "Ruby bindings for SecretSpec, a thin client over the " \
                     "secretspec-ffi C ABI (loaded via stdlib Fiddle)."
  spec.authors     = ["Cachix"]
  spec.license     = "Apache-2.0"
  spec.homepage    = "https://secretspec.dev/"
  spec.files       = Dir["lib/**/*.rb"] + ["README.md"] + Dir["vendor/*"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.0"

  # When the cdylib has been staged into vendor/ (see scripts/stage-cdylib.sh),
  # build a platform-specific gem that bundles it, so `gem install` needs no
  # native build. Without it, a pure-Ruby gem is built (the SDK then falls back
  # to SECRETSPEC_FFI_LIB or a Cargo target directory).
  staged = Dir["vendor/libsecretspec_ffi.*"] + Dir["vendor/secretspec_ffi.dll"]
  spec.platform = Gem::Platform::CURRENT unless staged.empty?
end

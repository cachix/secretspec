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
  spec.files       = Dir["lib/**/*.rb"] + ["README.md"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.0"
end

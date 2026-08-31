# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = "secretspec"
  spec.version     = "0.20.0"
  spec.summary     = "A declarative interface for every secret provider. Ruby SDK."
  spec.description = "Ruby bindings for SecretSpec: a native extension that " \
                     "statically links the libsecretspec C ABI."
  spec.authors     = ["Cachix"]
  spec.license     = "Apache-2.0"
  spec.homepage    = "https://secretspec.dev/"
  spec.files       = Dir["lib/**/*.rb"] + Dir["ext/**/*.{c,rb}"] +
                     ["README.md"] + Dir["vendor/*"]
  spec.extensions  = ["ext/secretspec/extconf.rb"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.0"

  # The extension compiles a tiny C glue at `gem install` and statically links
  # the prebuilt libsecretspec.a staged into vendor/ (see
  # scripts/stage-staticlib.sh). The archive is platform-specific, so build a
  # platform gem when it is present; one such gem serves every Ruby ABI.
  staged = File.exist?("vendor/libsecretspec.a")
  if staged
    platform = Gem::Platform.new(Gem::Platform.local)
    platform.version = nil if platform.os == "darwin"
    spec.platform = platform
  end
end

# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = "monosecret_rb"
  spec.version     = "0.2.0"
  spec.summary     = "Declarative secrets, every environment, any provider (Ruby SDK)"
  spec.description = "Ruby bindings for Monosecret: a native extension that " \
                     "statically links the monosecret_ffi C ABI."
  spec.authors     = ["Ifiok Jr."]
  spec.license     = "Apache-2.0"
  spec.homepage    = "https://ifiokjr.github.io/monosecret/"
  spec.metadata    = {
    "source_code_uri" => "https://github.com/ifiokjr/monosecret/tree/main/ruby/monosecret_rb",
    "rubygems_mfa_required" => "true"
  }
  spec.files       = Dir["lib/**/*.rb"] + Dir["ext/**/*.{c,rb}"] +
                     ["LICENSE", "README.md"] + Dir["vendor/*"]
  spec.extensions  = ["ext/monosecret/extconf.rb"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.0"

  # A future platform gem will compile the C glue at `gem install` and link the
  # prebuilt libmonosecret_ffi.a staged into vendor/ (see
  # scripts/stage-staticlib.sh). Without that platform-specific archive, this
  # gemspec is validated only as a source payload; standalone installability and
  # distribution are explicitly deferred.
  staged = File.exist?("vendor/libmonosecret_ffi.a")
  spec.platform = Gem::Platform::CURRENT if staged
end

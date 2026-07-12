#!/usr/bin/env bash
#
# Validate the deferred Ruby distribution's source-gem metadata and payload.
# This deliberately does not stage libmonosecret_ffi.a or claim that the source
# gem can be installed standalone; platform-gem assembly and smoke installation
# remain part of the deferred distribution work.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

gem_path="$tmp_dir/monosecret_rb-source.gem"

if [ -e "$pkg_dir/vendor/libmonosecret_ffi.a" ]; then
	echo "source-gem check requires an unstaged vendor directory" >&2
	exit 1
fi

(
	cd "$pkg_dir"
	gem build monosecret_rb.gemspec --output "$gem_path"
)

ruby -rrubygems/package -e '
  package = Gem::Package.new(ARGV.fetch(0))
  spec = package.spec
  required = %w[
    ext/monosecret/extconf.rb
    ext/monosecret/monosecret_ext.c
    lib/monosecret.rb
  ]
  missing = required - spec.files
  vendor_files = spec.files.grep(%r{\Avendor/})

  abort "unexpected gem name: #{spec.name}" unless spec.name == "monosecret_rb"
  abort "expected a Ruby source gem, got platform #{spec.platform}" unless spec.platform == Gem::Platform::RUBY
  abort "source gem is missing: #{missing.join(", ")}" unless missing.empty?
  abort "source gem unexpectedly contains staged native files: #{vendor_files.join(", ")}" unless vendor_files.empty?

  puts "validated deferred Ruby source-gem metadata and source payload (installability not claimed)"
' "$gem_path"

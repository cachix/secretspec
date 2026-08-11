#!/bin/sh
set -eu

case "${REPRO_CASE:?set REPRO_CASE to gnu, musl, or force-ruby}" in
  gnu)
    # The slim Debian image also omits the extension toolchain. Keep this
    # control on the small image while still testing the complete gem install.
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install --yes --no-install-recommends build-essential >/dev/null
    ;;
  musl)
    # The Alpine Ruby image omits the compiler needed for SecretSpec's small C
    # extension. Installing it ensures this case reaches the libc mismatch.
    apk add --no-cache build-base >/dev/null
    ;;
  force-ruby)
    ;;
  *)
    echo "unknown reproduction case: $REPRO_CASE" >&2
    exit 2
    ;;
esac

mkdir /work
cp /repro/Gemfile /work/Gemfile
cd /work

ruby --version
ruby -rbundler -e '
  abort "expected Bundler 4, got #{Bundler::VERSION}" unless Bundler::VERSION.start_with?("4.")
  puts "Bundler #{Bundler::VERSION}"
'
gem env platform

show_resolution() {
  sed -n '/^PLATFORMS$/,/^DEPENDENCIES$/p' Gemfile.lock
  bundle exec ruby -e '
    spec = Gem.loaded_specs.fetch("secretspec")
    puts "selected gem platform: #{spec.platform}"
  '
}

case "$REPRO_CASE" in
  gnu)
    bundle install
    show_resolution
    bundle exec ruby /repro/require_secretspec.rb
    ;;
  musl)
    bundle install
    show_resolution

    set +e
    bundle exec ruby /repro/require_secretspec.rb >load-error.log 2>&1
    status=$?
    set -e
    cat load-error.log

    if [ "$status" -eq 0 ]; then
      echo "expected the generic Linux gem to fail when loaded on musl" >&2
      exit 1
    fi
    if ! grep -F "Error relocating" load-error.log >/dev/null; then
      echo "SecretSpec failed to load, but not with the expected libc relocation error" >&2
      exit 1
    fi
    echo "reproduced: the generic Linux gem installs on musl but does not load"
    ;;
  force-ruby)
    set +e
    BUNDLE_FORCE_RUBY_PLATFORM=true bundle install >force-ruby-error.log 2>&1
    status=$?
    set -e
    cat force-ruby-error.log

    if [ "$status" -eq 0 ]; then
      echo "expected force_ruby_platform resolution to fail" >&2
      exit 1
    fi
    if ! grep -F "with platform 'ruby'" force-ruby-error.log >/dev/null; then
      echo "Bundler failed, but not because the ruby platform gem is absent" >&2
      exit 1
    fi
    echo "reproduced: force_ruby_platform has no source gem to select"
    ;;
esac

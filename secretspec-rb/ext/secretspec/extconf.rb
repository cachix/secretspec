# frozen_string_literal: true

# Builds the secretspec native extension. By default it statically links the
# libsecretspec archive (libsecretspec.a) and appends the archive's native
# dependency closure captured from `rustc --print native-static-libs`.
#
# With --enable-pkg-config every link input instead comes from an installed
# libsecretspec.pc, which may select a static or shared library, and the
# discovery tiers below are skipped entirely.

require "mkmf"

if enable_config("pkg-config", false)
  # mkmf routes the .pc's -l flags to $libs and the rest (-L, macOS -framework)
  # to $LDFLAGS.
  unless pkg_config("libsecretspec")
    abort("secretspec: pkg-config could not find libsecretspec; point " \
          "PKG_CONFIG_PATH at a prefix containing libsecretspec.pc")
  end

  create_makefile("secretspec/secretspec_ext")
  return
end

ext_dir = __dir__
pkg_dir = File.expand_path("../..", ext_dir) # secretspec-rb
repo_root = File.expand_path("..", pkg_dir)  # workspace root (dev checkout)
vendor = File.join(pkg_dir, "vendor")

# The staticlib: explicit contract, the bundled platform-gem copy, or a Cargo
# target dir (dev checkout, newest of release/debug).
def find_staticlib(vendor, repo_root)
  env = ENV["SECRETSPEC_FFI_STATICLIB"]
  return env if env && !env.empty? && File.exist?(env)

  bundled = %w[libsecretspec.a libsecretspec_ffi.a]
    .map { |name| File.join(vendor, name) }
    .find { |candidate| File.exist?(candidate) }
  return bundled if bundled

  %w[release debug]
    .flat_map do |profile|
      %w[libsecretspec.a libsecretspec_ffi.a]
        .map { |name| File.join(repo_root, "target", profile, name) }
    end
    .select { |c| File.exist?(c) }
    .max_by { |c| File.mtime(c) }
end

# The archive's transitive native deps: explicit contract, the bundled manifest,
# or captured live from rustc (dev checkout).
def find_native_libs(vendor, repo_root)
  env = ENV["SECRETSPEC_FFI_NATIVE_LIBS"]
  return env if env && !env.empty?

  manifest = File.join(vendor, "native-static-libs.txt")
  return File.read(manifest).strip if File.exist?(manifest)

  note = `cd #{repo_root} && cargo rustc -q -p libsecretspec --crate-type staticlib -- --print native-static-libs 2>&1`
  note[/native-static-libs:\s*(.*)/, 1].to_s.strip
end

staticlib = find_staticlib(vendor, repo_root)
abort("secretspec: could not locate libsecretspec.a; set SECRETSPEC_FFI_STATICLIB") unless staticlib

# Header: explicit contract, the bundled vendor copy (platform gem), or the
# ffi crate's include dir.
include_dir =
  if (env = ENV["SECRETSPEC_FFI_INCLUDE"]) && !env.empty? && File.directory?(env)
    env
  elsif File.exist?(File.join(vendor, "secretspec.h"))
    vendor
  else
    File.join(repo_root, "libsecretspec", "include")
  end

$INCFLAGS << " -I#{include_dir}"
# $LOCAL_LIBS is emitted before $libs on the link line, so the archive (pulled
# for the referenced symbols) precedes the system libs it depends on.
$LOCAL_LIBS << " #{staticlib}"
$libs = "#{$libs} #{find_native_libs(vendor, repo_root)}"
# The Windows gem bundles MinGW import libraries next to the staticlib
# (libwindows.*.a / libwinapi_*.a ship inside cargo registry crates, so an
# installing machine has them nowhere else); let the linker search vendor/.
$LIBPATH << vendor if File.directory?(vendor)

create_makefile("secretspec/secretspec_ext")

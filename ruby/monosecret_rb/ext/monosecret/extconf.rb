# frozen_string_literal: true

# Builds the monosecret native extension. By default it statically links the
# monosecret_ffi archive (libmonosecret_ffi.a) and appends the archive's native
# dependency closure captured from `rustc --print native-static-libs`.
#
# With --enable-pkg-config every link input instead comes from an installed
# monosecret_ffi.pc, which may select a static or shared library, and the
# discovery tiers below are skipped entirely.

require "mkmf"

if enable_config("pkg-config", false)
  # mkmf routes the .pc's -l flags to $libs and the rest (-L, macOS -framework)
  # to $LDFLAGS.
  unless pkg_config("monosecret_ffi")
    abort("monosecret: pkg-config could not find monosecret_ffi; point " \
          "PKG_CONFIG_PATH at a prefix containing monosecret_ffi.pc")
  end

  create_makefile("monosecret/monosecret_ext")
  return
end

ext_dir = __dir__
pkg_dir = File.expand_path("../..", ext_dir) # ruby/monosecret_rb
repo_root = File.expand_path("../..", pkg_dir)  # workspace root (dev checkout)
vendor = File.join(pkg_dir, "vendor")

# The staticlib: explicit contract, the bundled platform-gem copy, or a Cargo
# target dir (dev checkout, newest of release/debug).
def find_staticlib(vendor, repo_root)
  env = ENV["MONOSECRET_FFI_STATICLIB"]
  return env if env && !env.empty? && File.exist?(env)

  bundled = File.join(vendor, "libmonosecret_ffi.a")
  return bundled if File.exist?(bundled)

  %w[release debug]
    .map { |p| File.join(repo_root, "target", p, "libmonosecret_ffi.a") }
    .select { |c| File.exist?(c) }
    .max_by { |c| File.mtime(c) }
end

# The archive's transitive native deps: explicit contract, the bundled manifest,
# or captured live from rustc (dev checkout).
def find_native_libs(vendor, repo_root)
  env = ENV["MONOSECRET_FFI_NATIVE_LIBS"]
  return env if env && !env.empty?

  manifest = File.join(vendor, "native-static-libs.txt")
  return File.read(manifest).strip if File.exist?(manifest)

  note = `cd #{repo_root} && cargo rustc -q -p monosecret_ffi --crate-type staticlib -- --print native-static-libs 2>&1`
  note[/native-static-libs:\s*(.*)/, 1].to_s.strip
end

staticlib = find_staticlib(vendor, repo_root)
abort("monosecret: could not locate libmonosecret_ffi.a; set MONOSECRET_FFI_STATICLIB") unless staticlib

# Header: explicit contract, the bundled vendor copy (platform gem), or the
# ffi crate's include dir.
include_dir =
  if (env = ENV["MONOSECRET_FFI_INCLUDE"]) && !env.empty? && File.directory?(env)
    env
  elsif File.exist?(File.join(vendor, "monosecret.h"))
    vendor
  else
    File.join(repo_root, "crates", "monosecret_ffi", "include")
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

create_makefile("monosecret/monosecret_ext")

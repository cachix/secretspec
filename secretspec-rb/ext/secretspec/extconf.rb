# frozen_string_literal: true

# Builds the secretspec native extension, statically linking the secretspec-ffi
# archive (libsecretspec_ffi.a) into the extension object. A Rust staticlib does
# not carry its own native dependency closure, so the archive's transitive system
# libs (captured from `rustc --print native-static-libs`, never hardcoded) are
# appended to the link line after it.

require "mkmf"

ext_dir = __dir__
pkg_dir = File.expand_path("../..", ext_dir) # secretspec-rb
repo_root = File.expand_path("..", pkg_dir)  # workspace root (dev checkout)
vendor = File.join(pkg_dir, "vendor")

# The staticlib: explicit contract, the bundled platform-gem copy, or a Cargo
# target dir (dev checkout, newest of release/debug).
def find_staticlib(vendor, repo_root)
  env = ENV["SECRETSPEC_FFI_STATICLIB"]
  return env if env && !env.empty? && File.exist?(env)

  bundled = File.join(vendor, "libsecretspec_ffi.a")
  return bundled if File.exist?(bundled)

  %w[release debug]
    .map { |p| File.join(repo_root, "target", p, "libsecretspec_ffi.a") }
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

  note = `cd #{repo_root} && cargo rustc -q -p secretspec-ffi --crate-type staticlib -- --print native-static-libs 2>&1`
  note[/native-static-libs:\s*(.*)/, 1].to_s.strip
end

staticlib = find_staticlib(vendor, repo_root)
abort("secretspec: could not locate libsecretspec_ffi.a; set SECRETSPEC_FFI_STATICLIB") unless staticlib

# Header: the bundled vendor copy (platform gem) or the ffi crate's include dir.
include_dir =
  if File.exist?(File.join(vendor, "secretspec.h"))
    vendor
  else
    File.join(repo_root, "secretspec-ffi", "include")
  end

$INCFLAGS << " -I#{include_dir}"
# $LOCAL_LIBS is emitted before $libs on the link line, so the archive (pulled
# for the referenced symbols) precedes the system libs it depends on.
$LOCAL_LIBS << " #{staticlib}"
$libs = "#{$libs} #{find_native_libs(vendor, repo_root)}"

create_makefile("secretspec/secretspec_ext")

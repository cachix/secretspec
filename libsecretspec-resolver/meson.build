project(
  'libsecretspec-resolver',
  'c',
  version: '1.0.0',
  meson_version: '>=1.3.0',
  # Nix development environments define _FORTIFY_SOURCE, which requires an
  # optimised build. Keep the strict warnings while making the default usable
  # in those environments.
  default_options: [
    'buildtype=debugoptimized',
    'c_std=c11',
    'warning_level=3',
    'werror=true',
  ],
)

threads = dependency('threads')
yyjson = dependency('yyjson')
inc = include_directories('include', 'src')
platform_source = host_machine.system() == 'windows' ? 'src/process_windows.c' : 'src/process_posix.c'
sources = files(
  'src/frame.c',
  'src/json.c',
  'src/secure_memory.c',
  'src/session.c',
  platform_source,
)

cc = meson.get_compiler('c')
common_c_args = ['-DSECRETSPEC_RESOLVER_BUILDING']
# yyjson arrives as a static archive whose symbols carry default visibility, so
# linking it into the shared library would re-export roughly fifty yyjson
# symbols and let an application's own copy of yyjson interpose on the one this
# library calls. Keep them local, matching what the previously vendored build
# achieved by compiling yyjson with hidden visibility. Windows needs nothing:
# there only SECRETSPEC_RESOLVER_API marks a symbol dllexport.
hide_yyjson_args = []
foreach candidate : ['-Wl,--exclude-libs,ALL', '-Wl,-unexported_symbol,_yyjson*']
  if hide_yyjson_args.length() == 0 and cc.has_link_argument(candidate)
    hide_yyjson_args += candidate
  endif
endforeach
# MSVC gates <stdatomic.h> behind an opt-in switch even in C11 mode.
if cc.get_id() == 'msvc'
  common_c_args += '/experimental:c11atomics'
endif

resolver_lib = library(
  'secretspec-resolver',
  sources,
  include_directories: inc,
  dependencies: [threads, yyjson],
  c_args: common_c_args,
  c_shared_args: ['-DSECRETSPEC_RESOLVER_SHARED'],
  link_args: hide_yyjson_args,
  gnu_symbol_visibility: 'hidden',
  soversion: '1',
  install: true,
)

install_headers('include/secretspec_resolver.h')

pkgconfig = import('pkgconfig')
pkgconfig.generate(
  resolver_lib,
  filebase: 'secretspec-resolver',
  name: 'libsecretspec-resolver',
  description: 'SecretSpec local IPC C client',
  version: meson.project_version(),
  requires_private: ['yyjson'],
)

smoke = executable(
  'secretspec_resolver_smoke',
  'tests/smoke.c',
  include_directories: inc,
  link_with: resolver_lib,
  dependencies: threads,
)
test('secretspec_resolver_smoke', smoke)

smoke_shared = executable(
  'secretspec_resolver_smoke_shared',
  'tests/smoke.c',
  include_directories: inc,
  link_with: resolver_lib,
  dependencies: threads,
)
test('secretspec_resolver_smoke_shared', smoke_shared)

fake_peer = executable(
  'secretspec_resolver_fake_peer',
  'tests/fake_peer.c',
  include_directories: inc,
  dependencies: yyjson,
)
session_test = executable(
  'secretspec_resolver_session',
  'tests/session.c',
  include_directories: inc,
  link_with: resolver_lib,
  dependencies: threads,
)
test('secretspec_resolver_session', session_test, args: [fake_peer.full_path()])

backpressure_test = executable(
  'secretspec_resolver_backpressure',
  'tests/backpressure.c',
  include_directories: inc,
  link_with: resolver_lib,
  dependencies: threads,
)
test('secretspec_resolver_backpressure', backpressure_test, args: [fake_peer.full_path()])

regressions_test = executable(
  'secretspec_resolver_regressions',
  'tests/regressions.c',
  include_directories: inc,
  link_with: resolver_lib,
  dependencies: threads,
)
test('secretspec_resolver_regressions', regressions_test, args: [fake_peer.full_path()])

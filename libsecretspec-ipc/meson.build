project(
  'libsecretspec-ipc',
  'c',
  version: '1.0.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=true'],
)

threads = dependency('threads')
inc = include_directories('include', 'vendor', 'src')
platform_source = host_machine.system() == 'windows' ? 'src/process_windows.c' : 'src/process_posix.c'
sources = files(
  'src/frame.c',
  'src/json.c',
  'src/secure_memory.c',
  'src/session.c',
  platform_source,
  'vendor/yyjson.c',
)

common_c_args = ['-DSECRETSPEC_IPC_BUILDING', '-Dyyjson_api=']

static_lib = static_library(
  'secretspec-ipc',
  sources,
  include_directories: inc,
  dependencies: threads,
  c_args: common_c_args,
  gnu_symbol_visibility: 'hidden',
  install: true,
)

shared_lib = shared_library(
  'secretspec-ipc',
  sources,
  include_directories: inc,
  dependencies: threads,
  c_args: common_c_args + ['-DSECRETSPEC_IPC_SHARED'],
  gnu_symbol_visibility: 'hidden',
  install: true,
)

install_headers('include/secretspec_ipc.h')

smoke = executable(
  'secretspec_ipc_smoke',
  'tests/smoke.c',
  include_directories: inc,
  link_with: static_lib,
  dependencies: threads,
)
test('secretspec_ipc_smoke', smoke)

smoke_shared = executable(
  'secretspec_ipc_smoke_shared',
  'tests/smoke.c',
  include_directories: inc,
  link_with: shared_lib,
  dependencies: threads,
)
test('secretspec_ipc_smoke_shared', smoke_shared)

fake_peer = executable(
  'secretspec_ipc_fake_peer',
  ['tests/fake_peer.c', 'vendor/yyjson.c'],
  include_directories: inc,
)
session_test = executable(
  'secretspec_ipc_session',
  'tests/session.c',
  include_directories: inc,
  link_with: static_lib,
  dependencies: threads,
)
test('secretspec_ipc_session', session_test, args: [fake_peer.full_path()])

backpressure_test = executable(
  'secretspec_ipc_backpressure',
  'tests/backpressure.c',
  include_directories: inc,
  link_with: static_lib,
  dependencies: threads,
)
test('secretspec_ipc_backpressure', backpressure_test, args: [fake_peer.full_path()])

regressions_test = executable(
  'secretspec_ipc_regressions',
  'tests/regressions.c',
  include_directories: inc,
  link_with: static_lib,
  dependencies: threads,
)
test('secretspec_ipc_regressions', regressions_test, args: [fake_peer.full_path()])

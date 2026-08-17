cmake_minimum_required(VERSION 3.20)
project(libsecretspec_ipc VERSION 1.0.0 LANGUAGES C)

option(SECRETSPEC_IPC_BUILD_TESTS "Build C client tests" ON)

find_package(Threads REQUIRED)

set(SECRETSPEC_IPC_SOURCES
    src/frame.c
    src/json.c
    src/secure_memory.c
    src/session.c)

if(WIN32)
  list(APPEND SECRETSPEC_IPC_SOURCES src/process_windows.c)
else()
  list(APPEND SECRETSPEC_IPC_SOURCES src/process_posix.c)
endif()

add_library(secretspec_ipc_objects OBJECT ${SECRETSPEC_IPC_SOURCES})
set_target_properties(secretspec_ipc_objects PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE YES
    C_VISIBILITY_PRESET hidden)
target_include_directories(secretspec_ipc_objects PRIVATE include vendor src)
target_compile_definitions(secretspec_ipc_objects PRIVATE SECRETSPEC_IPC_BUILDING yyjson_api=)
if(MSVC)
  target_compile_options(secretspec_ipc_objects PRIVATE /W4 /WX)
else()
  target_compile_options(secretspec_ipc_objects PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# A Windows DLL must compile the public definitions with dllexport, while the
# static archive must not carry DLL export directives. Other platforms can
# safely share the hidden-visibility object set.
if(WIN32)
  add_library(secretspec_ipc_shared_objects OBJECT ${SECRETSPEC_IPC_SOURCES})
  set_target_properties(secretspec_ipc_shared_objects PROPERTIES
      C_STANDARD 11
      C_STANDARD_REQUIRED YES
      C_EXTENSIONS NO
      POSITION_INDEPENDENT_CODE YES
      C_VISIBILITY_PRESET hidden)
  target_include_directories(secretspec_ipc_shared_objects PRIVATE include vendor src)
  target_compile_definitions(secretspec_ipc_shared_objects PRIVATE
      SECRETSPEC_IPC_BUILDING SECRETSPEC_IPC_SHARED yyjson_api=)
  if(MSVC)
    target_compile_options(secretspec_ipc_shared_objects PRIVATE /W4 /WX)
  else()
    target_compile_options(secretspec_ipc_shared_objects PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
  endif()
  set(SECRETSPEC_IPC_SHARED_OBJECTS $<TARGET_OBJECTS:secretspec_ipc_shared_objects>)
else()
  set(SECRETSPEC_IPC_SHARED_OBJECTS $<TARGET_OBJECTS:secretspec_ipc_objects>)
endif()

add_library(yyjson_objects OBJECT vendor/yyjson.c)
set_target_properties(yyjson_objects PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE YES
    C_VISIBILITY_PRESET hidden)
target_include_directories(yyjson_objects PRIVATE vendor)
target_compile_definitions(yyjson_objects PRIVATE yyjson_api=)

add_library(secretspec_ipc_static STATIC
    $<TARGET_OBJECTS:secretspec_ipc_objects>
    $<TARGET_OBJECTS:yyjson_objects>)
add_library(secretspec_ipc_shared SHARED
    ${SECRETSPEC_IPC_SHARED_OBJECTS}
    $<TARGET_OBJECTS:yyjson_objects>)
set_target_properties(secretspec_ipc_static PROPERTIES OUTPUT_NAME secretspec-ipc)
set_target_properties(secretspec_ipc_shared PROPERTIES OUTPUT_NAME secretspec-ipc)
target_link_libraries(secretspec_ipc_static PUBLIC Threads::Threads)
target_link_libraries(secretspec_ipc_shared PUBLIC Threads::Threads)
target_compile_definitions(secretspec_ipc_shared PUBLIC SECRETSPEC_IPC_SHARED)
target_include_directories(secretspec_ipc_static PUBLIC include)
target_include_directories(secretspec_ipc_shared PUBLIC include)

install(TARGETS secretspec_ipc_static secretspec_ipc_shared)
install(FILES include/secretspec_ipc.h DESTINATION include)

if(SECRETSPEC_IPC_BUILD_TESTS)
  enable_testing()
  add_executable(secretspec_ipc_smoke tests/smoke.c)
  target_link_libraries(secretspec_ipc_smoke PRIVATE secretspec_ipc_static)
  add_test(NAME secretspec_ipc_smoke COMMAND secretspec_ipc_smoke)
  add_executable(secretspec_ipc_smoke_shared tests/smoke.c)
  target_link_libraries(secretspec_ipc_smoke_shared PRIVATE secretspec_ipc_shared)
  add_test(NAME secretspec_ipc_smoke_shared COMMAND secretspec_ipc_smoke_shared)
  add_executable(secretspec_ipc_fake_peer tests/fake_peer.c $<TARGET_OBJECTS:yyjson_objects>)
  target_include_directories(secretspec_ipc_fake_peer PRIVATE vendor)
  add_executable(secretspec_ipc_session tests/session.c)
  target_link_libraries(secretspec_ipc_session PRIVATE secretspec_ipc_static)
  add_test(NAME secretspec_ipc_session
           COMMAND secretspec_ipc_session $<TARGET_FILE:secretspec_ipc_fake_peer>)
  add_executable(secretspec_ipc_backpressure tests/backpressure.c)
  target_link_libraries(secretspec_ipc_backpressure PRIVATE secretspec_ipc_static)
  add_test(NAME secretspec_ipc_backpressure
           COMMAND secretspec_ipc_backpressure $<TARGET_FILE:secretspec_ipc_fake_peer>)
  add_executable(secretspec_ipc_regressions tests/regressions.c)
  target_link_libraries(secretspec_ipc_regressions PRIVATE secretspec_ipc_static)
  add_test(NAME secretspec_ipc_regressions
           COMMAND secretspec_ipc_regressions $<TARGET_FILE:secretspec_ipc_fake_peer>)

  foreach(test_target IN ITEMS
      secretspec_ipc_smoke
      secretspec_ipc_smoke_shared
      secretspec_ipc_fake_peer
      secretspec_ipc_session
      secretspec_ipc_backpressure
      secretspec_ipc_regressions)
    set_target_properties(${test_target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    if(MSVC)
      target_compile_options(${test_target} PRIVATE /W4 /WX)
    else()
      target_compile_options(${test_target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
  endforeach()
endif()

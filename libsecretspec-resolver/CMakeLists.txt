cmake_minimum_required(VERSION 3.20)
project(libsecretspec_resolver VERSION 1.0.0 LANGUAGES C)

option(SECRETSPEC_RESOLVER_BUILD_TESTS "Build C client tests" ON)

include(GNUInstallDirs)
include(CheckLinkerFlag)
find_package(Threads REQUIRED)
find_package(yyjson CONFIG REQUIRED)

# yyjson arrives as a static archive whose symbols carry default visibility, so
# linking it into the shared library would re-export roughly fifty yyjson
# symbols and let an application's own copy of yyjson interpose on the one this
# library calls. Keep them local, matching what the previously vendored build
# achieved by compiling yyjson with hidden visibility. Windows needs nothing:
# there only SECRETSPEC_RESOLVER_API marks a symbol dllexport.
check_linker_flag(C "LINKER:--exclude-libs,ALL" SECRETSPEC_RESOLVER_HAS_EXCLUDE_LIBS)
if(SECRETSPEC_RESOLVER_HAS_EXCLUDE_LIBS)
  set(SECRETSPEC_RESOLVER_HIDE_YYJSON "LINKER:--exclude-libs,ALL")
else()
  check_linker_flag(C "LINKER:-unexported_symbol,_yyjson*"
      SECRETSPEC_RESOLVER_HAS_UNEXPORTED_SYMBOL)
  if(SECRETSPEC_RESOLVER_HAS_UNEXPORTED_SYMBOL)
    set(SECRETSPEC_RESOLVER_HIDE_YYJSON "LINKER:-unexported_symbol,_yyjson*")
  else()
    set(SECRETSPEC_RESOLVER_HIDE_YYJSON "")
  endif()
endif()

set(SECRETSPEC_RESOLVER_SOURCES
    src/frame.c
    src/json.c
    src/secure_memory.c
    src/session.c)

if(WIN32)
  list(APPEND SECRETSPEC_RESOLVER_SOURCES src/process_windows.c)
else()
  list(APPEND SECRETSPEC_RESOLVER_SOURCES src/process_posix.c)
endif()

add_library(secretspec_resolver_objects OBJECT ${SECRETSPEC_RESOLVER_SOURCES})
set_target_properties(secretspec_resolver_objects PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE YES
    C_VISIBILITY_PRESET hidden)
target_include_directories(secretspec_resolver_objects PRIVATE include src)
target_link_libraries(secretspec_resolver_objects PRIVATE yyjson::yyjson)
target_compile_definitions(secretspec_resolver_objects PRIVATE SECRETSPEC_RESOLVER_BUILDING)
if(MSVC)
  target_compile_options(secretspec_resolver_objects PRIVATE /W4 /WX /experimental:c11atomics)
else()
  target_compile_options(secretspec_resolver_objects PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# A Windows DLL must compile the public definitions with dllexport, while the
# static archive must not carry DLL export directives. Other platforms can
# safely share the hidden-visibility object set.
if(WIN32)
  add_library(secretspec_resolver_shared_objects OBJECT ${SECRETSPEC_RESOLVER_SOURCES})
  set_target_properties(secretspec_resolver_shared_objects PROPERTIES
      C_STANDARD 11
      C_STANDARD_REQUIRED YES
      C_EXTENSIONS NO
      POSITION_INDEPENDENT_CODE YES
      C_VISIBILITY_PRESET hidden)
  target_include_directories(secretspec_resolver_shared_objects PRIVATE include src)
  target_link_libraries(secretspec_resolver_shared_objects PRIVATE yyjson::yyjson)
  target_compile_definitions(secretspec_resolver_shared_objects PRIVATE
      SECRETSPEC_RESOLVER_BUILDING SECRETSPEC_RESOLVER_SHARED)
  if(MSVC)
    target_compile_options(secretspec_resolver_shared_objects PRIVATE /W4 /WX /experimental:c11atomics)
  else()
    target_compile_options(secretspec_resolver_shared_objects PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
  endif()
  set(SECRETSPEC_RESOLVER_SHARED_OBJECTS $<TARGET_OBJECTS:secretspec_resolver_shared_objects>)
else()
  set(SECRETSPEC_RESOLVER_SHARED_OBJECTS $<TARGET_OBJECTS:secretspec_resolver_objects>)
endif()

add_library(secretspec_resolver_static STATIC
    $<TARGET_OBJECTS:secretspec_resolver_objects>)
add_library(secretspec_resolver_shared SHARED
    ${SECRETSPEC_RESOLVER_SHARED_OBJECTS})
set_target_properties(secretspec_resolver_static PROPERTIES OUTPUT_NAME secretspec-resolver)
set_target_properties(secretspec_resolver_shared PROPERTIES
    OUTPUT_NAME secretspec-resolver
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
target_link_libraries(secretspec_resolver_static PUBLIC Threads::Threads)
target_link_libraries(secretspec_resolver_static PRIVATE yyjson::yyjson)
target_link_libraries(secretspec_resolver_shared PUBLIC Threads::Threads)
target_link_libraries(secretspec_resolver_shared PRIVATE yyjson::yyjson)
target_compile_definitions(secretspec_resolver_shared PUBLIC SECRETSPEC_RESOLVER_SHARED)
target_link_options(secretspec_resolver_shared PRIVATE ${SECRETSPEC_RESOLVER_HIDE_YYJSON})
target_include_directories(secretspec_resolver_static PUBLIC include)
target_include_directories(secretspec_resolver_shared PUBLIC include)

install(TARGETS secretspec_resolver_static secretspec_resolver_shared
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/secretspec_resolver.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(secretspec-resolver.pc.in secretspec-resolver.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/secretspec-resolver.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(SECRETSPEC_RESOLVER_BUILD_TESTS)
  enable_testing()
  add_executable(secretspec_resolver_smoke tests/smoke.c)
  target_link_libraries(secretspec_resolver_smoke PRIVATE secretspec_resolver_static)
  add_test(NAME secretspec_resolver_smoke COMMAND secretspec_resolver_smoke)
  add_executable(secretspec_resolver_smoke_shared tests/smoke.c)
  target_link_libraries(secretspec_resolver_smoke_shared PRIVATE secretspec_resolver_shared)
  add_test(NAME secretspec_resolver_smoke_shared COMMAND secretspec_resolver_smoke_shared)
  add_executable(secretspec_resolver_fake_peer tests/fake_peer.c)
  target_link_libraries(secretspec_resolver_fake_peer PRIVATE yyjson::yyjson)
  add_executable(secretspec_resolver_session tests/session.c)
  target_link_libraries(secretspec_resolver_session PRIVATE secretspec_resolver_static)
  add_test(NAME secretspec_resolver_session
           COMMAND secretspec_resolver_session $<TARGET_FILE:secretspec_resolver_fake_peer>)
  add_executable(secretspec_resolver_backpressure tests/backpressure.c)
  target_link_libraries(secretspec_resolver_backpressure PRIVATE secretspec_resolver_static)
  add_test(NAME secretspec_resolver_backpressure
           COMMAND secretspec_resolver_backpressure $<TARGET_FILE:secretspec_resolver_fake_peer>)
  add_executable(secretspec_resolver_regressions tests/regressions.c)
  target_link_libraries(secretspec_resolver_regressions PRIVATE secretspec_resolver_static)
  add_test(NAME secretspec_resolver_regressions
           COMMAND secretspec_resolver_regressions $<TARGET_FILE:secretspec_resolver_fake_peer>)

  foreach(test_target IN ITEMS
      secretspec_resolver_smoke
      secretspec_resolver_smoke_shared
      secretspec_resolver_fake_peer
      secretspec_resolver_session
      secretspec_resolver_backpressure
      secretspec_resolver_regressions)
    set_target_properties(${test_target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    if(MSVC)
      target_compile_options(${test_target} PRIVATE /W4 /WX /experimental:c11atomics)
    else()
      target_compile_options(${test_target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
  endforeach()
endif()

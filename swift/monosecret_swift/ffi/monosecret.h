/*
 * Development-only forwarding header for the checked-in module map.
 *
 * The release XCFramework places the canonical monosecret_ffi header beside
 * that module map; keep a relative include here so local Clang/Swift tooling
 * can validate the same module without duplicating the ABI declaration.
 */
#include "../../../crates/monosecret_ffi/include/monosecret.h"

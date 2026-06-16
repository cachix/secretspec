/*
 * Native glue for the secretspec Ruby SDK.
 *
 * A thin C extension that statically links the secretspec-ffi archive
 * (libsecretspec_ffi.a) and exposes its three C ABI functions to Ruby as
 * Secretspec::Native.c_resolve / c_abi_version. The Rust resolver is embedded in
 * this extension object, so there is no separate cdylib to ship or dlopen.
 */
#include <ruby.h>
#include "secretspec.h"

/*
 * Secretspec::Native.c_resolve(request_json) -> String or nil
 *
 * Marshals the JSON request to the Rust resolver and copies the owned response
 * into a Ruby String before freeing it. Returns nil if the resolver returns NULL
 * (catastrophic allocation failure); the Ruby wrapper turns that into an Error.
 */
static VALUE
native_resolve(VALUE self, VALUE request_json)
{
    const char *request = StringValueCStr(request_json);
    char *result = secretspec_resolve(request);
    if (result == NULL) {
        return Qnil;
    }
    VALUE out = rb_str_new_cstr(result);
    secretspec_free(result);
    return out;
}

/* Secretspec::Native.c_abi_version -> String (static, not freed). */
static VALUE
native_abi_version(VALUE self)
{
    return rb_str_new_cstr(secretspec_abi_version());
}

void
Init_secretspec_ext(void)
{
    VALUE mod = rb_define_module("Secretspec");
    VALUE native = rb_define_module_under(mod, "Native");
    rb_define_singleton_method(native, "c_resolve", native_resolve, 1);
    rb_define_singleton_method(native, "c_abi_version", native_abi_version, 0);
}

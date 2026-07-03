/*
 * Native glue for the secretspec Ruby SDK.
 *
 * A thin C extension that statically links the secretspec-ffi archive
 * (libsecretspec_ffi.a) and exposes its three C ABI functions to Ruby as
 * Secretspec::Native.c_resolve / c_abi_version. The Rust resolver is embedded in
 * this extension object, so there is no separate cdylib to ship or dlopen.
 */
#include <ruby.h>
#include <ruby/thread.h>
#include <stdlib.h>
#include "secretspec.h"

static void *
resolve_nogvl(void *arg)
{
    return secretspec_resolve((const char *)arg);
}

/*
 * Secretspec::Native.c_resolve(request_json) -> String or nil
 *
 * Marshals the JSON request to the Rust resolver and copies the owned response
 * into a Ruby String before freeing it. Returns nil if the resolver returns NULL
 * (catastrophic allocation failure); the Ruby wrapper turns that into an Error.
 *
 * The resolver may block on network-backed providers (1Password, LastPass,
 * Vault), so it runs with the GVL released — otherwise the round-trip would
 * freeze every other Ruby thread. The request bytes are copied into a C-owned
 * buffer first: the Ruby string may move once the GVL is released.
 */
static VALUE
native_resolve(VALUE self, VALUE request_json)
{
    char *request = strdup(StringValueCStr(request_json));
    if (request == NULL) {
        return Qnil;
    }
    char *result = rb_thread_call_without_gvl(
        resolve_nogvl, request, RUBY_UBF_IO, NULL);
    free(request);
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

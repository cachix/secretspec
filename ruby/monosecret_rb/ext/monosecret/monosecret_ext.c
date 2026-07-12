/*
 * Native glue for the monosecret Ruby SDK.
 *
 * A thin C extension that statically links the monosecret_ffi archive
 * (libmonosecret_ffi.a) and exposes its three C ABI functions to Ruby as
 * Monosecret::Native.c_resolve / c_abi_version. The Rust resolver is embedded in
 * this extension object, so there is no separate cdylib to ship or dlopen.
 */
#include <ruby.h>
#include <ruby/thread.h>
#include <stdlib.h>
#include <string.h>
#include "monosecret.h"

struct resolve_state {
    VALUE request_json;
    char *request;
    char *response;
};

static void *
resolve_nogvl(void *arg)
{
    struct resolve_state *state = (struct resolve_state *)arg;

    /* Store ownership before Ruby reacquires the GVL and processes interrupts. */
    state->response = monosecret_resolve(state->request);
    return NULL;
}

/*
 * Monosecret::Native.c_resolve(request_json) -> String or nil
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
resolve_body(VALUE arg)
{
    struct resolve_state *state = (struct resolve_state *)arg;

    state->request = strdup(StringValueCStr(state->request_json));
    if (state->request == NULL) {
        return Qnil;
    }

    rb_thread_call_without_gvl(resolve_nogvl, state, RUBY_UBF_IO, NULL);
    if (state->response == NULL) {
        return Qnil;
    }

    return rb_str_new_cstr(state->response);
}

static VALUE
resolve_cleanup(VALUE arg)
{
    struct resolve_state *state = (struct resolve_state *)arg;

    monosecret_free(state->response);
    state->response = NULL;
    free(state->request);
    state->request = NULL;
    return Qnil;
}

static VALUE
native_resolve(VALUE self, VALUE request_json)
{
    struct resolve_state state = {
        .request_json = request_json,
        .request = NULL,
        .response = NULL,
    };

    return rb_ensure(
        resolve_body, (VALUE)&state, resolve_cleanup, (VALUE)&state);
}

/* Monosecret::Native.c_abi_version -> String (static, not freed). */
static VALUE
native_abi_version(VALUE self)
{
    return rb_str_new_cstr(monosecret_abi_version());
}

void
Init_monosecret_ext(void)
{
    VALUE mod = rb_define_module("Monosecret");
    VALUE native = rb_define_module_under(mod, "Native");
    rb_define_singleton_method(native, "c_resolve", native_resolve, 1);
    rb_define_singleton_method(native, "c_abi_version", native_abi_version, 0);
}

/*
 * Minimal C smoke test for the SecretSpec C ABI. Proves the cdylib links, the
 * three entry points are callable from C, and the malloc/free roundtrip works.
 * Run by the ffi-build workflow against the freshly built library.
 */
#include <stdio.h>
#include <string.h>
#include "secretspec.h"

int main(void) {
    const char *version = secretspec_abi_version();
    if (version == NULL || version[0] == '\0') {
        printf("FAIL: abi_version empty\n");
        return 1;
    }
    printf("abi_version: %s\n", version);

    /* A deliberately invalid request must yield a well-formed error envelope. */
    char *out = secretspec_resolve("not json");
    if (out == NULL) {
        printf("FAIL: resolve returned NULL\n");
        return 1;
    }
    printf("resolve(bad): %s\n", out);
    if (strstr(out, "\"ok\":false") == NULL) {
        printf("FAIL: expected an error envelope\n");
        secretspec_free(out);
        return 1;
    }
    secretspec_free(out);
    secretspec_free(NULL); /* must be a no-op */

    printf("OK\n");
    return 0;
}

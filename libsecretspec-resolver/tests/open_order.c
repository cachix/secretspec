/* Built against a copy of the library compiled with SECRETSPEC_RESOLVER_TESTING,
 * whose hook holds client_open until the reader has closed the session. That
 * forces the ordering a scheduler only produces sometimes: the reader handles
 * the peer's first output before open does anything after starting it. */
#include "secretspec_resolver.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void ss_test_hold_open_until_closed(bool enabled);

static const char client_initialize[] =
    "{\"protocol\":\"secretspec.resolver\",\"versions\":[1],"
    "\"client\":{\"name\":\"c-test\",\"version\":\"1\"},"
    "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
    "\"application\":{}}";

static secretspec_resolver_slice slice(const char *text) {
    secretspec_resolver_slice value;
    value.data = (const unsigned char *)text;
    value.size = strlen(text);
    return value;
}

static uint64_t far_deadline(void) {
    struct timespec time;
    if (timespec_get(&time, TIME_UTC) != TIME_UTC) return UINT64_MAX;
    return (uint64_t)time.tv_sec * UINT64_C(1000) + UINT64_C(60000);
}

/* A banner the reader sees before anything else must still fail open with the
 * diagnostic, not a bare UNAVAILABLE and an empty error. */
int main(int argc, char **argv) {
    secretspec_resolver_slice arguments[1];
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    int named;
    if (argc != 2) return EXIT_FAILURE;

    memset(&options, 0, sizeof(options));
    arguments[0] = slice("--banner-on-stdout");
    options.struct_size = sizeof(options);
    options.abi_version = SECRETSPEC_RESOLVER_ABI_VERSION;
    options.executable = slice(argv[1]);
    options.arguments = arguments;
    options.argument_count = 1;
    options.initialize_params_json = slice(client_initialize);
    options.max_stderr_bytes = 4096;

    ss_test_hold_open_until_closed(true);
    status = secretspec_resolver_client_open(&options, far_deadline(), &client, &server, &error);
    named = error.data != NULL &&
            strstr((const char *)error.data, "non-protocol text") != NULL;
    if (status != SECRETSPEC_RESOLVER_PROTOCOL || client != NULL || !named) {
        fprintf(stderr, "open after early output: status=%d client=%s error=%.*s\n",
                (int)status, client != NULL ? "set" : "NULL",
                error.data != NULL ? (int)error.size : 6,
                error.data != NULL ? (const char *)error.data : "(null)");
    }
    secretspec_resolver_buffer_free(server);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_PROTOCOL && client == NULL && named ? EXIT_SUCCESS
                                                                             : EXIT_FAILURE;
}

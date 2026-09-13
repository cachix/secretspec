#include "secretspec_resolver.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ms(void) {
    struct timespec time;
    if (timespec_get(&time, TIME_UTC) != TIME_UTC) return 0;
    return (uint64_t)time.tv_sec * UINT64_C(1000) +
           (uint64_t)time.tv_nsec / UINT64_C(1000000);
}

static secretspec_resolver_slice slice(const char *text) {
    secretspec_resolver_slice value;
    value.data = (const unsigned char *)text;
    value.size = strlen(text);
    return value;
}

int main(int argc, char **argv) {
    static const char initialize[] =
        "{\"protocol\":\"secretspec.resolver\",\"versions\":[1],"
        "\"client\":{\"name\":\"c-test\",\"version\":\"1\"},"
        "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
        "\"application\":{}}";
    const char *peer_argument = "--stall-after-init";
    secretspec_resolver_slice arguments[1];
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *calls[4] = {NULL, NULL, NULL, NULL};
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    char *params = NULL;
    uint64_t call_deadline;
    uint64_t started;
    size_t prefix;
    size_t index;

    if (argc != 2) return EXIT_FAILURE;
    arguments[0] = slice(peer_argument);
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = SECRETSPEC_RESOLVER_ABI_VERSION;
    options.executable = slice(argv[1]);
    options.arguments = arguments;
    options.argument_count = 1;
    options.initialize_params_json.data = (const unsigned char *)initialize;
    options.initialize_params_json.size = sizeof(initialize) - 1;
    options.max_stderr_bytes = 4096;
    status = secretspec_resolver_client_open(
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
    if (status != SECRETSPEC_RESOLVER_OK) goto failed;
    secretspec_resolver_buffer_free(server);
    server.data = NULL;
    server.size = 0;

    params = (char *)malloc(30001);
    if (params == NULL) goto failed;
    call_deadline = now_ms() + UINT64_C(2000);
    prefix = (size_t)snprintf(params, 30001, "{\"padding\":\"");
    if (prefix >= 29998) goto failed;
    memset(params + prefix, 'a', 29998 - prefix);
    params[29998] = '\"';
    params[29999] = '}';
    params[30000] = '\0';

    started = now_ms();
    for (index = 0; index < 4; index++) {
        status = secretspec_resolver_call_start(
            client,
            (const unsigned char *)"resolver.get",
            strlen("resolver.get"),
            (const unsigned char *)params,
            strlen(params),
            call_deadline,
            &calls[index],
            &error);
        if (status != SECRETSPEC_RESOLVER_OK) goto failed;
    }
    if (now_ms() - started >= UINT64_C(1000)) goto failed;

    (void)secretspec_resolver_client_close(client, now_ms() + UINT64_C(250), &error);
    secretspec_resolver_buffer_free(error);
    error.data = NULL;
    error.size = 0;
    for (index = 0; index < 4; index++) {
        secretspec_resolver_call_free(calls[index]);
        calls[index] = NULL;
    }
    secretspec_resolver_client_free(client);
    free(params);
    return EXIT_SUCCESS;

failed:
    if (error.data != NULL) fwrite(error.data, 1, error.size, stderr);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_buffer_free(server);
    for (index = 0; index < 4; index++) {
        if (calls[index] != NULL) secretspec_resolver_call_free(calls[index]);
    }
    if (client != NULL) secretspec_resolver_client_free(client);
    free(params);
    return EXIT_FAILURE;
}

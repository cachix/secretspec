#include "secretspec_ipc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ms(void) {
    struct timespec time;
    if (timespec_get(&time, TIME_UTC) != TIME_UTC) return 0;
    return (uint64_t)time.tv_sec * UINT64_C(1000) + (uint64_t)time.tv_nsec / UINT64_C(1000000);
}

static secretspec_ipc_slice slice(const char *text) {
    secretspec_ipc_slice value;
    value.data = (const unsigned char *)text;
    value.size = strlen(text);
    return value;
}

int main(int argc, char **argv) {
    static const char initialize[] =
        "{\"protocol\":\"secretspec.client\",\"versions\":[1],"
        "\"client\":{\"name\":\"c-test\",\"version\":\"1\"},"
        "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
        "\"application\":{}}";
    secretspec_ipc_options options;
    secretspec_ipc_client *client = NULL;
    secretspec_ipc_buffer server = {NULL, 0};
    secretspec_ipc_buffer result = {NULL, 0};
    secretspec_ipc_buffer error = {NULL, 0};
    secretspec_ipc_status status;
    uint64_t deadline;
    static const unsigned char params[] = "{}";

    if (argc != 2) return EXIT_FAILURE;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = SECRETSPEC_IPC_ABI_VERSION;
    options.executable = slice(argv[1]);
    options.initialize_params_json.data = (const unsigned char *)initialize;
    options.initialize_params_json.size = sizeof(initialize) - 1;
    options.max_stderr_bytes = 4096;
    deadline = now_ms() + 2000;
    status = secretspec_ipc_client_open(&options, deadline, &client, &server, &error);
    if (status != SECRETSPEC_IPC_OK) goto failed;
    secretspec_ipc_buffer_free(server);
    deadline = now_ms() + 2000;
    status = secretspec_ipc_client_call(client,
                                        (const unsigned char *)"client.resolve",
                                        strlen("client.resolve"),
                                        params,
                                        sizeof(params) - 1,
                                        deadline,
                                        &result,
                                        &error);
    if (status != SECRETSPEC_IPC_OK || result.size != strlen("{\"echo\":true}") ||
        memcmp(result.data, "{\"echo\":true}", result.size) != 0) goto failed;
    secretspec_ipc_buffer_free(result);
    status = secretspec_ipc_client_close(client, now_ms() + 2000, &error);
    if (status != SECRETSPEC_IPC_OK) goto failed;
    secretspec_ipc_client_free(client);
    return EXIT_SUCCESS;

failed:
    if (error.data != NULL) fwrite(error.data, 1, error.size, stderr);
    secretspec_ipc_buffer_free(error);
    secretspec_ipc_buffer_free(result);
    if (client != NULL) secretspec_ipc_client_free(client);
    return EXIT_FAILURE;
}

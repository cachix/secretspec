#include "secretspec_ipc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static secretspec_ipc_slice slice(const char *text) {
    secretspec_ipc_slice value;
    value.data = (const unsigned char *)text;
    value.size = strlen(text);
    return value;
}

static int rejects(secretspec_ipc_options *options) {
    secretspec_ipc_client *client = NULL;
    secretspec_ipc_buffer server = {NULL, 0};
    secretspec_ipc_buffer error = {NULL, 0};
    secretspec_ipc_status status = secretspec_ipc_client_open(
        options, UINT64_MAX, &client, &server, &error);
    int valid = status == SECRETSPEC_IPC_INVALID_ARGUMENT && client == NULL &&
                server.data == NULL && server.size == 0 && error.data != NULL;
    secretspec_ipc_buffer_free(server);
    secretspec_ipc_buffer_free(error);
    if (client != NULL) secretspec_ipc_client_free(client);
    return valid;
}

int main(void) {
    secretspec_ipc_buffer empty = {NULL, 0};
    secretspec_ipc_options options;
    if (secretspec_ipc_abi_version() != SECRETSPEC_IPC_ABI_VERSION) return EXIT_FAILURE;
    secretspec_ipc_buffer_free(empty);

    memset(&options, 0, sizeof(options));
    if (!rejects(&options)) return EXIT_FAILURE;

    options.struct_size = sizeof(options);
    options.abi_version = SECRETSPEC_IPC_ABI_VERSION;
    options.executable = slice("endpoint");
    options.initialize_params_json = slice("{}");
    options.reserved = 1;
    if (!rejects(&options)) return EXIT_FAILURE;

    options.reserved = 0;
    options.flags = UINT32_C(1) << 31;
    if (!rejects(&options)) return EXIT_FAILURE;

    options.flags = 0;
    options.executable.data = NULL;
    options.executable.size = 1;
    if (!rejects(&options)) return EXIT_FAILURE;

    options.executable = slice("endpoint");
    options.struct_size = sizeof(options) + 1;
    if (!rejects(&options)) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

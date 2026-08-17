#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "secretspec_ipc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static const char client_initialize[] =
    "{\"protocol\":\"secretspec.client\",\"versions\":[1],"
    "\"client\":{\"name\":\"c-test\",\"version\":\"1\"},"
    "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
    "\"application\":{}}";

static const char provider_initialize[] =
    "{\"protocol\":\"secretspec.provider\",\"versions\":[1],"
    "\"client\":{\"name\":\"c-test\",\"version\":\"1\"},"
    "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
    "\"application\":{}}";

static const char provider_set_initialize[] =
    "{\"protocol\":\"secretspec.provider\",\"versions\":[1],"
    "\"client\":{\"name\":\"c-test\",\"version\":\"1\"},"
    "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
    "\"application\":{}}";

static uint64_t now_ms(void) {
    struct timespec time;
    if (timespec_get(&time, TIME_UTC) != TIME_UTC) return 0;
    return (uint64_t)time.tv_sec * UINT64_C(1000) +
           (uint64_t)time.tv_nsec / UINT64_C(1000000);
}

static void pause_ms(uint64_t milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds > MAXDWORD ? MAXDWORD : (DWORD)milliseconds);
#else
    struct timespec delay;
    delay.tv_sec = (time_t)(milliseconds / UINT64_C(1000));
    delay.tv_nsec = (long)((milliseconds % UINT64_C(1000)) * UINT64_C(1000000));
    (void)nanosleep(&delay, NULL);
#endif
}

static secretspec_ipc_slice slice(const char *text) {
    secretspec_ipc_slice value;
    value.data = (const unsigned char *)text;
    value.size = strlen(text);
    return value;
}

static void set_options(
    secretspec_ipc_options *options,
    const char *peer,
    const char *mode,
    const char *initialize) {
    static secretspec_ipc_slice arguments[1];
    memset(options, 0, sizeof(*options));
    arguments[0] = slice(mode);
    options->struct_size = sizeof(*options);
    options->abi_version = SECRETSPEC_IPC_ABI_VERSION;
    options->executable = slice(peer);
    options->arguments = arguments;
    options->argument_count = 1;
    options->initialize_params_json = slice(initialize);
    options->max_stderr_bytes = 4096;
}

static int open_client(
    const char *peer,
    const char *mode,
    secretspec_ipc_client **client,
    secretspec_ipc_buffer *error) {
    secretspec_ipc_options options;
    secretspec_ipc_buffer server = {NULL, 0};
    secretspec_ipc_status status;
    set_options(&options, peer, mode, client_initialize);
    status = secretspec_ipc_client_open(
        &options, now_ms() + UINT64_C(2000), client, &server, error);
    secretspec_ipc_buffer_free(server);
    return status == SECRETSPEC_IPC_OK;
}

static int rejects_bad_provider_capabilities(
    const char *peer,
    const char *mode,
    const char *initialize) {
    secretspec_ipc_options options;
    secretspec_ipc_client *client = NULL;
    secretspec_ipc_buffer server = {NULL, 0};
    secretspec_ipc_buffer error = {NULL, 0};
    secretspec_ipc_status status;
    set_options(&options, peer, mode, initialize);
    status = secretspec_ipc_client_open(
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
    secretspec_ipc_buffer_free(server);
    secretspec_ipc_buffer_free(error);
    if (client != NULL) secretspec_ipc_client_free(client);
    return status == SECRETSPEC_IPC_PROTOCOL && client == NULL;
}

static int rejects_bad_shutdown(const char *peer) {
    secretspec_ipc_client *client = NULL;
    secretspec_ipc_buffer error = {NULL, 0};
    secretspec_ipc_status status;
    if (!open_client(peer, "--bad-shutdown", &client, &error)) goto failed;
    status = secretspec_ipc_client_close(
        client, now_ms() + UINT64_C(2000), &error);
    secretspec_ipc_buffer_free(error);
    secretspec_ipc_client_free(client);
    return status == SECRETSPEC_IPC_PROTOCOL;
failed:
    secretspec_ipc_buffer_free(error);
    if (client != NULL) secretspec_ipc_client_free(client);
    return 0;
}

static int freed_calls_expire(const char *peer) {
    secretspec_ipc_client *client = NULL;
    secretspec_ipc_call *call = NULL;
    secretspec_ipc_buffer error = {NULL, 0};
    secretspec_ipc_status status;
    size_t index;
    if (!open_client(peer, "--ignore-calls", &client, &error)) goto failed;
    for (index = 0; index < 4; index++) {
        static const unsigned char params[] = "{}";
        uint64_t deadline = now_ms() + UINT64_C(100);
        status = secretspec_ipc_call_start(
            client, (const unsigned char *)"client.resolve", strlen("client.resolve"),
            params, sizeof(params) - 1, deadline, &call, &error);
        if (status != SECRETSPEC_IPC_OK) goto failed;
        secretspec_ipc_call_free(call);
        call = NULL;
    }
    pause_ms(UINT64_C(400));
    {
        static const unsigned char params[] = "{}";
        uint64_t deadline = now_ms() + UINT64_C(1000);
        status = secretspec_ipc_call_start(
            client, (const unsigned char *)"client.resolve", strlen("client.resolve"),
            params, sizeof(params) - 1, deadline, &call, &error);
        if (status != SECRETSPEC_IPC_OK) goto failed;
    }
    secretspec_ipc_call_free(call);
    call = NULL;
    status = secretspec_ipc_client_close(
        client, now_ms() + UINT64_C(2000), &error);
    secretspec_ipc_buffer_free(error);
    secretspec_ipc_client_free(client);
    return status == SECRETSPEC_IPC_OK;
failed:
    secretspec_ipc_buffer_free(error);
    if (call != NULL) secretspec_ipc_call_free(call);
    if (client != NULL) secretspec_ipc_client_free(client);
    return 0;
}

static int descendant_pipes_do_not_block_close(const char *peer) {
    secretspec_ipc_client *client = NULL;
    secretspec_ipc_buffer error = {NULL, 0};
    secretspec_ipc_status status;
    uint64_t started;
    if (!open_client(peer, "--descendant-holds-pipes", &client, &error)) goto failed;
    started = now_ms();
    status = secretspec_ipc_client_close(
        client, started + UINT64_C(250), &error);
    secretspec_ipc_buffer_free(error);
    secretspec_ipc_client_free(client);
    return status == SECRETSPEC_IPC_OK && now_ms() - started < UINT64_C(2000);
failed:
    secretspec_ipc_buffer_free(error);
    if (client != NULL) secretspec_ipc_client_free(client);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return EXIT_FAILURE;
    if (!rejects_bad_provider_capabilities(
            argv[1], "--bad-provider-capabilities", provider_initialize)) return EXIT_FAILURE;
    if (!rejects_bad_provider_capabilities(
            argv[1], "--bad-provider-set-capabilities", provider_set_initialize)) return EXIT_FAILURE;
    if (!rejects_bad_shutdown(argv[1])) return EXIT_FAILURE;
    if (!freed_calls_expire(argv[1])) return EXIT_FAILURE;
    if (!descendant_pipes_do_not_block_close(argv[1])) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

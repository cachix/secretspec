#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "yyjson.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

typedef enum {
    MODE_NORMAL,
    MODE_STALL_AFTER_INIT,
    MODE_BAD_SHUTDOWN,
    MODE_BAD_PROVIDER_CAPABILITIES,
    MODE_BAD_PROVIDER_SET_CAPABILITIES,
    MODE_IGNORE_CALLS,
    MODE_DESCENDANT_HOLDS_PIPES,
    MODE_HOLD_PIPES
} peer_mode;

static void pause_for_backpressure(void) {
#ifdef _WIN32
    Sleep(10000);
#else
    struct timespec delay = {10, 0};
    (void)nanosleep(&delay, NULL);
#endif
}

static int read_exact(unsigned char *buffer, size_t size) {
    return fread(buffer, 1, size, stdin) == size;
}

static int read_frame(unsigned char **payload, size_t *size) {
    unsigned char prefix[4];
    if (!read_exact(prefix, sizeof(prefix))) return 0;
    *size = ((size_t)prefix[0] << 24) | ((size_t)prefix[1] << 16) |
            ((size_t)prefix[2] << 8) | prefix[3];
    if (*size == 0 || *size > 1048576) return 0;
    *payload = (unsigned char *)malloc(*size);
    return *payload != NULL && read_exact(*payload, *size);
}

static int write_frame(const char *payload) {
    size_t size = strlen(payload);
    unsigned char prefix[4] = {
        (unsigned char)(size >> 24),
        (unsigned char)(size >> 16),
        (unsigned char)(size >> 8),
        (unsigned char)size
    };
    return fwrite(prefix, 1, sizeof(prefix), stdout) == sizeof(prefix) &&
           fwrite(payload, 1, size, stdout) == size && fflush(stdout) == 0;
}

static int start_pipe_holder(const char *executable) {
#ifdef _WIN32
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    char command[4096];
    int length;
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = sizeof(startup);
    length = snprintf(command, sizeof(command), "\"%s\" --hold-pipes", executable);
    if (length <= 0 || (size_t)length >= sizeof(command) ||
        !CreateProcessA(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) return 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 1;
#else
    pid_t child = fork();
    (void)executable;
    if (child < 0) return 0;
    if (child == 0) {
        struct timespec delay = {5, 0};
        (void)nanosleep(&delay, NULL);
        _exit(EXIT_SUCCESS);
    }
    return 1;
#endif
}

static peer_mode parse_mode(int argc, char **argv) {
    if (argc != 2) return MODE_NORMAL;
    if (strcmp(argv[1], "--stall-after-init") == 0) return MODE_STALL_AFTER_INIT;
    if (strcmp(argv[1], "--bad-shutdown") == 0) return MODE_BAD_SHUTDOWN;
    if (strcmp(argv[1], "--bad-provider-capabilities") == 0) return MODE_BAD_PROVIDER_CAPABILITIES;
    if (strcmp(argv[1], "--bad-provider-set-capabilities") == 0) return MODE_BAD_PROVIDER_SET_CAPABILITIES;
    if (strcmp(argv[1], "--ignore-calls") == 0) return MODE_IGNORE_CALLS;
    if (strcmp(argv[1], "--descendant-holds-pipes") == 0) return MODE_DESCENDANT_HOLDS_PIPES;
    if (strcmp(argv[1], "--hold-pipes") == 0) return MODE_HOLD_PIPES;
    return MODE_NORMAL;
}

int main(int argc, char **argv) {
    peer_mode mode = parse_mode(argc, argv);
    if (mode == MODE_HOLD_PIPES) {
        pause_for_backpressure();
        return EXIT_SUCCESS;
    }
    for (;;) {
        unsigned char *payload = NULL;
        size_t size = 0;
        yyjson_doc *document;
        yyjson_val *root;
        yyjson_val *method;
        yyjson_val *id;
        yyjson_val *deadline;
        char response[2048];
        int length;
        if (!read_frame(&payload, &size)) return EXIT_FAILURE;
        document = yyjson_read((char *)payload, size, 0);
        free(payload);
        if (document == NULL) return EXIT_FAILURE;
        root = yyjson_doc_get_root(document);
        method = yyjson_obj_get(root, "method");
        id = yyjson_obj_get(root, "id");
        deadline = yyjson_obj_get(root, "deadline_unix_ms");
        if (id != NULL && !yyjson_is_uint(deadline)) {
            yyjson_doc_free(document);
            return EXIT_FAILURE;
        }
        if (yyjson_equals_str(method, "rpc.initialize")) {
            if (mode == MODE_BAD_PROVIDER_CAPABILITIES ||
                mode == MODE_BAD_PROVIDER_SET_CAPABILITIES) {
                length = snprintf(response, sizeof(response),
                    "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{"
                    "\"protocol\":\"secretspec.provider\",\"version\":1,"
                    "\"server\":{\"name\":\"fake-peer\",\"version\":\"1\"},"
                    "\"capabilities\":[\"provider.resolve_address\",\"provider.exists\",\"%s\"],"
                    "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
                    "\"application\":{}}}",
                    (unsigned long long)yyjson_get_uint(id),
                    mode == MODE_BAD_PROVIDER_CAPABILITIES
                        ? "provider.get_many"
                        : "provider.set_expiring");
            } else {
                length = snprintf(response, sizeof(response),
                    "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{"
                    "\"protocol\":\"secretspec.client\",\"version\":1,"
                    "\"server\":{\"name\":\"fake-peer\",\"version\":\"1\"},"
                    "\"capabilities\":[\"client.resolve\",\"client.release\"],"
                    "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
                    "\"application\":{}}}",
                    (unsigned long long)yyjson_get_uint(id));
            }
        } else if (yyjson_equals_str(method, "rpc.shutdown")) {
            length = snprintf(response, sizeof(response),
                              mode == MODE_BAD_SHUTDOWN
                                  ? "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{\"unexpected\":true}}"
                                  : "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{}}",
                              (unsigned long long)yyjson_get_uint(id));
            yyjson_doc_free(document);
            if (length <= 0 || (size_t)length >= sizeof(response) || !write_frame(response)) return EXIT_FAILURE;
            if (mode == MODE_DESCENDANT_HOLDS_PIPES && !start_pipe_holder(argv[0])) return EXIT_FAILURE;
            return EXIT_SUCCESS;
        } else if (id == NULL) {
            yyjson_doc_free(document);
            continue;
        } else if (mode == MODE_IGNORE_CALLS) {
            yyjson_doc_free(document);
            continue;
        } else {
            length = snprintf(response, sizeof(response),
                              "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{\"echo\":true}}",
                              (unsigned long long)yyjson_get_uint(id));
        }
        yyjson_doc_free(document);
        if (length <= 0 || (size_t)length >= sizeof(response) || !write_frame(response)) return EXIT_FAILURE;
        if (mode == MODE_STALL_AFTER_INIT) {
            pause_for_backpressure();
            return EXIT_SUCCESS;
        }
    }
}

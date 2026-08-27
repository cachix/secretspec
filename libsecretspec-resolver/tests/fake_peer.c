#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "yyjson.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

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
    MODE_IGNORE_CALLS,
    MODE_DESCENDANT_HOLDS_PIPES,
    MODE_HOLD_PIPES,
    MODE_BANNER_ON_STDOUT,
    MODE_FUTURE_ERROR_KIND,
    MODE_PROMPT,
    MODE_EXPIRED_PROMPT,
    MODE_CHECK_ENVIRONMENT
} peer_mode;

static uint64_t now_ms(void) {
    struct timespec time;
    if (timespec_get(&time, TIME_UTC) != TIME_UTC) return 0;
    return (uint64_t)time.tv_sec * UINT64_C(1000) +
           (uint64_t)time.tv_nsec / UINT64_C(1000000);
}

static void pause_for_backpressure(void) {
#ifdef _WIN32
    Sleep(10000);
#else
    struct timespec delay = {10, 0};
    (void)nanosleep(&delay, NULL);
#endif
}

#ifdef _WIN32
static size_t environment_key_size(const wchar_t *entry) {
    const wchar_t *equals = wcschr(entry + (entry[0] == L'=' ? 1 : 0), L'=');
    return equals == NULL ? wcslen(entry) : (size_t)(equals - entry);
}

static int environment_names_are_sorted(void) {
    wchar_t *block = GetEnvironmentStringsW();
    wchar_t *entry;
    wchar_t *previous = NULL;
    int sorted = 1;
    if (block == NULL) return 0;
    for (entry = block; *entry != L'\0'; entry += wcslen(entry) + 1) {
        if (previous != NULL) {
            size_t previous_size = environment_key_size(previous);
            size_t entry_size = environment_key_size(entry);
            size_t common = previous_size < entry_size ? previous_size : entry_size;
            int compared = _wcsnicmp(previous, entry, common);
            if (compared > 0 || (compared == 0 && previous_size > entry_size)) {
                sorted = 0;
                break;
            }
        }
        previous = entry;
    }
    FreeEnvironmentStringsW(block);
    return sorted;
}
#else
static int environment_names_are_sorted(void) {
    return 1;
}
#endif

static int expected_environment_is_present(void) {
    const char *first = getenv("secretspec_a_first");
    const char *middle = getenv("SecretSpec_M_Middle");
    const char *last = getenv("SECRETSPEC_Z_LAST");
    return first != NULL && strcmp(first, "first") == 0 &&
           middle != NULL && strcmp(middle, "middle") == 0 &&
           last != NULL && strcmp(last, "last") == 0 &&
           environment_names_are_sorted();
}

static int read_frame(unsigned char **payload, size_t *size) {
    int byte;
    *payload = (unsigned char *)malloc(1048576);
    if (*payload == NULL) return 0;
    *size = 0;
    while ((byte = fgetc(stdin)) != EOF) {
        if (byte == '\n') return *size != 0;
        if (byte == '\r' || *size == 1048576) { free(*payload); return 0; }
        (*payload)[(*size)++] = (unsigned char)byte;
    }
    free(*payload);
    return 0;
}

static int write_frame(const char *payload) {
    size_t size = strlen(payload);
    return fwrite(payload, 1, size, stdout) == size && fputc('\n', stdout) != EOF && fflush(stdout) == 0;
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
    if (strcmp(argv[1], "--ignore-calls") == 0) return MODE_IGNORE_CALLS;
    if (strcmp(argv[1], "--descendant-holds-pipes") == 0) return MODE_DESCENDANT_HOLDS_PIPES;
    if (strcmp(argv[1], "--hold-pipes") == 0) return MODE_HOLD_PIPES;
    if (strcmp(argv[1], "--banner-on-stdout") == 0) return MODE_BANNER_ON_STDOUT;
    if (strcmp(argv[1], "--future-error-kind") == 0) return MODE_FUTURE_ERROR_KIND;
    if (strcmp(argv[1], "--prompt") == 0) return MODE_PROMPT;
    if (strcmp(argv[1], "--expired-prompt") == 0) return MODE_EXPIRED_PROMPT;
    if (strcmp(argv[1], "--check-environment") == 0) return MODE_CHECK_ENVIRONMENT;
    return MODE_NORMAL;
}

int main(int argc, char **argv) {
    peer_mode mode = parse_mode(argc, argv);
    int expired_prompt_sent = 0;
    if (mode == MODE_HOLD_PIPES) {
        pause_for_backpressure();
        return EXIT_SUCCESS;
    }
    if (mode == MODE_BANNER_ON_STDOUT) {
        /* The endpoint bug this diagnostic exists for: a banner on the stream
         * reserved for frames, before a single frame is written. */
        (void)fputs("secretspec-provider-example starting\n", stdout);
        (void)fflush(stdout);
        pause_for_backpressure();
        return EXIT_SUCCESS;
    }
    if (mode == MODE_CHECK_ENVIRONMENT && !expected_environment_is_present()) {
        return EXIT_FAILURE;
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
        deadline = yyjson_obj_get(yyjson_obj_get(root, "_meta"), "deadline_unix_ms");
        if (id != NULL && !yyjson_is_uint(deadline)) {
            yyjson_doc_free(document);
            return EXIT_FAILURE;
        }
        if (yyjson_equals_str(method, "rpc.initialize")) {
            length = snprintf(response, sizeof(response),
                    "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{"
                    "\"protocol\":\"secretspec.resolver\",\"version\":1,"
                    "\"server\":{\"name\":\"fake-peer\",\"version\":\"1\"},"
                    "\"methods\":[\"resolver.get\",\"resolver.release\"],\"capabilities\":{},"
                    "\"limits\":{\"max_frame_bytes\":32768,\"max_in_flight\":4},"
                    "\"application\":{}}}",
                (unsigned long long)yyjson_get_uint(id));
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
        } else if (mode == MODE_FUTURE_ERROR_KIND) {
            /* A peer speaking a later revision: an error code and kind this
             * client has never heard of. It must survive it. */
            length = snprintf(response, sizeof(response),
                "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"error\":{\"code\":-32011,"
                "\"message\":\"dynamic session required\","
                "\"data\":{\"kind\":\"dynamic_session_required\",\"retryable\":false}}}",
                (unsigned long long)yyjson_get_uint(id));
        } else if (mode == MODE_PROMPT) {
            /* Ask the client for a value mid-call, then answer the call with
             * whatever came back. The prompt uses this side's own request ID
             * space, which deliberately overlaps the client's. */
            unsigned char *answer = NULL;
            size_t answer_size = 0;
            yyjson_doc *reply;
            yyjson_val *value;
            uint64_t call_id = yyjson_get_uint(id);
            yyjson_doc_free(document);
            length = snprintf(response, sizeof(response),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"client.prompt\","
                "\"_meta\":{\"deadline_unix_ms\":%llu,\"parent_request_id\":%llu},\"params\":{\"name\":\"DEPLOY_PASSWORD\","
                "\"profile\":\"default\",\"target_provider\":\"dotenv:values.env\"}}",
                (unsigned long long)(now_ms() + UINT64_C(5000)), (unsigned long long)call_id);
            if (length <= 0 || (size_t)length >= sizeof(response) ||
                !write_frame(response) || !read_frame(&answer, &answer_size)) return EXIT_FAILURE;
            reply = yyjson_read((char *)answer, answer_size, 0);
            free(answer);
            if (reply == NULL) return EXIT_FAILURE;
            value = yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(reply), "result"), "value");
            length = yyjson_is_str(value)
                ? snprintf(response, sizeof(response),
                           "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{\"answered\":\"%s\"}}",
                           (unsigned long long)call_id, yyjson_get_str(value))
                : snprintf(response, sizeof(response),
                           "{\"jsonrpc\":\"2.0\",\"id\":%llu,\"result\":{\"declined\":true}}",
                           (unsigned long long)call_id);
            yyjson_doc_free(reply);
            if (length <= 0 || (size_t)length >= sizeof(response) ||
                !write_frame(response)) return EXIT_FAILURE;
            continue;
        } else if (mode == MODE_EXPIRED_PROMPT && !expired_prompt_sent) {
            /* Leave the first call unanswered after asking a short-lived
             * question. Later calls still receive normal responses, which
             * exposes a stale prompt that was not removed at its deadline. */
            expired_prompt_sent = 1;
            length = snprintf(response, sizeof(response),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"client.prompt\","
                "\"_meta\":{\"deadline_unix_ms\":%llu,\"parent_request_id\":%llu},\"params\":{\"name\":\"STALE_SECRET\","
                "\"profile\":\"default\",\"target_provider\":null}}",
                (unsigned long long)(now_ms() + UINT64_C(100)), (unsigned long long)yyjson_get_uint(id));
            yyjson_doc_free(document);
            if (length <= 0 || (size_t)length >= sizeof(response) ||
                !write_frame(response)) return EXIT_FAILURE;
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

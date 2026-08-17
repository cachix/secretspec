#include "internal.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef CRITICAL_SECTION ss_mutex;
typedef CONDITION_VARIABLE ss_condition;
typedef HANDLE ss_thread;
typedef DWORD (WINAPI *ss_thread_function)(LPVOID);
static bool mutex_init(ss_mutex *mutex) { InitializeCriticalSection(mutex); return true; }
static void mutex_destroy(ss_mutex *mutex) { DeleteCriticalSection(mutex); }
static void mutex_lock(ss_mutex *mutex) { EnterCriticalSection(mutex); }
static void mutex_unlock(ss_mutex *mutex) { LeaveCriticalSection(mutex); }
static bool condition_init(ss_condition *condition) { InitializeConditionVariable(condition); return true; }
static void condition_destroy(ss_condition *condition) { (void)condition; }
static void condition_broadcast(ss_condition *condition) { WakeAllConditionVariable(condition); }
static bool condition_wait_until(ss_condition *condition, ss_mutex *mutex, uint64_t deadline) {
    uint64_t now = ss_now_unix_ms();
    uint64_t ceiling = now + SS_MAX_DEADLINE_HORIZON_MS;
    DWORD timeout;
    /* Matches the POSIX branch: bound how long one wait can block. */
    if (deadline > ceiling) deadline = ceiling;
    timeout = deadline <= now ? 0 : (DWORD)(deadline - now);
    return SleepConditionVariableCS(condition, mutex, timeout) != 0;
}
static bool thread_start(ss_thread *thread, ss_thread_function function, void *context) {
    *thread = CreateThread(NULL, 0, function, context, 0, NULL);
    return *thread != NULL;
}
static void thread_interrupt(ss_thread thread) { (void)CancelSynchronousIo(thread); }
static void thread_join(ss_thread thread) { WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }
#define SS_THREAD_RETURN DWORD WINAPI
#define SS_THREAD_END return 0
#else
#include <errno.h>
#include <pthread.h>
#include <time.h>
typedef pthread_mutex_t ss_mutex;
typedef pthread_cond_t ss_condition;
typedef pthread_t ss_thread;
typedef void *(*ss_thread_function)(void *);
static bool mutex_init(ss_mutex *mutex) { return pthread_mutex_init(mutex, NULL) == 0; }
static void mutex_destroy(ss_mutex *mutex) { (void)pthread_mutex_destroy(mutex); }
static void mutex_lock(ss_mutex *mutex) { (void)pthread_mutex_lock(mutex); }
static void mutex_unlock(ss_mutex *mutex) { (void)pthread_mutex_unlock(mutex); }
static bool condition_init(ss_condition *condition) { return pthread_cond_init(condition, NULL) == 0; }
static void condition_destroy(ss_condition *condition) { (void)pthread_cond_destroy(condition); }
static void condition_broadcast(ss_condition *condition) { (void)pthread_cond_broadcast(condition); }
static bool condition_wait_until(ss_condition *condition, ss_mutex *mutex, uint64_t deadline) {
    struct timespec time;
    int outcome;
    uint64_t ceiling = ss_now_unix_ms() + SS_MAX_DEADLINE_HORIZON_MS;
    /* A far-future deadline would push tv_sec out of the range
     * pthread_cond_timedwait accepts. It would then fail with EINVAL on every
     * call, and callers that loop on this helper would spin at full CPU rather
     * than wait. Clamping keeps every wait representable. */
    if (deadline > ceiling) deadline = ceiling;
    time.tv_sec = (time_t)(deadline / UINT64_C(1000));
    time.tv_nsec = (long)((deadline % UINT64_C(1000)) * UINT64_C(1000000));
    outcome = pthread_cond_timedwait(condition, mutex, &time);
    return outcome == 0;
}
static bool thread_start(ss_thread *thread, ss_thread_function function, void *context) {
    return pthread_create(thread, NULL, function, context) == 0;
}
static void thread_interrupt(ss_thread thread) { (void)thread; }
static void thread_join(ss_thread thread) { (void)pthread_join(thread, NULL); }
#define SS_THREAD_RETURN void *
#define SS_THREAD_END return NULL
#endif

typedef struct ss_request ss_request;
typedef struct ss_outbound ss_outbound;

struct ss_outbound {
    secretspec_ipc_buffer payload;
    size_t limit;
    ss_outbound *next;
};

struct ss_request {
    uint64_t id;
    uint64_t deadline_unix_ms;
    secretspec_ipc_status status;
    secretspec_ipc_buffer result;
    secretspec_ipc_buffer error;
    ss_condition condition;
    atomic_size_t references;
    bool running;
    bool abandoned;
    bool waiter;
    bool cancel_sent;
    ss_request *next;
};

struct secretspec_ipc_call {
    struct secretspec_ipc_client *client;
    ss_request *request;
};

struct secretspec_ipc_client {
    ss_process *process;
    ss_mutex mutex;
    ss_mutex write_mutex;
    ss_condition state_changed;
    ss_condition write_ready;
    ss_thread writer_thread;
    ss_thread reader_thread;
    ss_thread stderr_thread;
    ss_thread deadline_thread;
    bool writer_started;
    bool reader_started;
    bool stderr_started;
    bool deadline_started;
    bool writer_stopping;
    bool initializing;
    bool ready;
    bool closing;
    bool closed;
    size_t max_frame_bytes;
    size_t max_in_flight;
    size_t in_flight;
    size_t entry_count;
    size_t max_stderr_bytes;
    uint64_t next_id;
    ss_request *requests;
    ss_outbound *write_head;
    ss_outbound *write_tail;
    size_t write_count;
    char **capabilities;
    size_t capability_count;
    atomic_size_t references;
    bool user_released;
};

static void request_release(ss_request *request) {
    if (request != NULL && atomic_fetch_sub(&request->references, 1) == 1) {
        secretspec_ipc_buffer_free(request->result);
        secretspec_ipc_buffer_free(request->error);
        condition_destroy(&request->condition);
        ss_secure_clear(request, sizeof(*request));
        free(request);
    }
}

static ss_request *request_new(uint64_t id, uint64_t deadline) {
    ss_request *request = (ss_request *)calloc(1, sizeof(*request));
    if (request == NULL) return NULL;
    request->id = id;
    request->deadline_unix_ms = deadline;
    request->status = SECRETSPEC_IPC_UNAVAILABLE;
    request->running = true;
    atomic_init(&request->references, 2);
    if (!condition_init(&request->condition)) {
        free(request);
        return NULL;
    }
    return request;
}

static ss_request *find_request(secretspec_ipc_client *client, uint64_t id) {
    ss_request *request;
    for (request = client->requests; request != NULL; request = request->next) {
        if (request->id == id) return request;
    }
    return NULL;
}

static void remove_request(secretspec_ipc_client *client, ss_request *request) {
    ss_request **cursor = &client->requests;
    while (*cursor != NULL) {
        if (*cursor == request) {
            *cursor = request->next;
            request->next = NULL;
            client->entry_count--;
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static bool valid_utf8(const unsigned char *data, size_t size) {
    size_t index = 0;
    while (index < size) {
        unsigned char first = data[index++];
        uint32_t code;
        uint32_t minimum;
        size_t remaining;
        if (first < 0x80) continue;
        if ((first & 0xe0) == 0xc0) { code = first & 0x1f; remaining = 1; minimum = 0x80; }
        else if ((first & 0xf0) == 0xe0) { code = first & 0x0f; remaining = 2; minimum = 0x800; }
        else if ((first & 0xf8) == 0xf0) { code = first & 0x07; remaining = 3; minimum = 0x10000; }
        else return false;
        if (remaining > size - index) return false;
        while (remaining-- != 0) {
            unsigned char next = data[index++];
            if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 0x3f);
        }
        if (code < minimum || (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff) return false;
    }
    return true;
}

static bool valid_slice(secretspec_ipc_slice slice, bool allow_empty) {
    return (slice.size == 0 ? allow_empty : slice.data != NULL) &&
           (slice.data != NULL || slice.size == 0) &&
           (slice.size == 0 || (memchr(slice.data, 0, slice.size) == NULL && valid_utf8(slice.data, slice.size)));
}

static char *copy_slice(secretspec_ipc_slice slice) {
    char *copy = (char *)malloc(slice.size + 1);
    if (copy == NULL) return NULL;
    if (slice.size != 0) memcpy(copy, slice.data, slice.size);
    copy[slice.size] = '\0';
    return copy;
}

static bool absolute_executable(const char *path) {
#ifdef _WIN32
    return (strlen(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
            path[1] == ':' && (path[2] == '\\' || path[2] == '/')) ||
           (path[0] == '\\' && path[1] == '\\');
#else
    return path[0] == '/';
#endif
}

static bool environment_entry_valid(const char *entry) {
    const char *equals = strchr(entry, '=');
    return equals != NULL && equals != entry;
}

static void launch_free(ss_launch *launch) {
    size_t index;
    if (launch == NULL) return;
    free(launch->executable);
    for (index = 0; index < launch->argument_count; index++) free(launch->arguments[index]);
    for (index = 0; index < launch->environment_count; index++) {
        if (launch->environment[index] != NULL) {
            ss_secure_clear(launch->environment[index], strlen(launch->environment[index]));
            free(launch->environment[index]);
        }
    }
    free(launch->arguments);
    free(launch->environment);
    memset(launch, 0, sizeof(*launch));
}

static secretspec_ipc_status launch_from_options(const secretspec_ipc_options *options, ss_launch *launch) {
    size_t index;
    memset(launch, 0, sizeof(*launch));
    launch->discover = (options->flags & SECRETSPEC_IPC_DISCOVER_EXECUTABLE) != 0;
    launch->inherit_environment = (options->flags & SECRETSPEC_IPC_INHERIT_ENVIRONMENT) != 0;
    launch->executable = copy_slice(options->executable);
    launch->argument_count = options->argument_count;
    launch->environment_count = options->environment_count;
    launch->arguments = (char **)calloc(launch->argument_count + 1, sizeof(char *));
    launch->environment = (char **)calloc(launch->environment_count + 1, sizeof(char *));
    if (launch->executable == NULL || launch->arguments == NULL || launch->environment == NULL) goto unavailable;
    if (!launch->discover && !absolute_executable(launch->executable)) return SECRETSPEC_IPC_INVALID_ARGUMENT;
    for (index = 0; index < launch->argument_count; index++) {
        launch->arguments[index] = copy_slice(options->arguments[index]);
        if (launch->arguments[index] == NULL) goto unavailable;
    }
    for (index = 0; index < launch->environment_count; index++) {
        launch->environment[index] = copy_slice(options->environment[index]);
        if (launch->environment[index] == NULL) goto unavailable;
        if (!environment_entry_valid(launch->environment[index])) return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    return SECRETSPEC_IPC_OK;
unavailable:
    return SECRETSPEC_IPC_UNAVAILABLE;
}

static bool write_payload(secretspec_ipc_client *client, const unsigned char *payload, size_t size) {
    ss_outbound *outbound;
    size_t limit;
    mutex_lock(&client->mutex);
    limit = client->max_frame_bytes;
    if (client->closed) {
        mutex_unlock(&client->mutex);
        return false;
    }
    mutex_unlock(&client->mutex);

    if (size == 0 || size > limit) return false;
    outbound = (ss_outbound *)calloc(1, sizeof(*outbound));
    if (outbound == NULL || !ss_buffer_copy(&outbound->payload, payload, size)) {
        free(outbound);
        return false;
    }
    outbound->limit = limit;

    mutex_lock(&client->write_mutex);
    if (client->writer_stopping || client->write_count >= SS_MAX_IN_FLIGHT * 2 + 4) {
        mutex_unlock(&client->write_mutex);
        secretspec_ipc_buffer_free(outbound->payload);
        free(outbound);
        return false;
    }
    if (client->write_tail == NULL) {
        client->write_head = outbound;
    } else {
        client->write_tail->next = outbound;
    }
    client->write_tail = outbound;
    client->write_count++;
    condition_broadcast(&client->write_ready);
    mutex_unlock(&client->write_mutex);
    return true;
}

static bool build_request(
    uint64_t id,
    const char *method,
    size_t method_size,
    uint64_t deadline,
    yyjson_val *params,
    secretspec_ipc_buffer *payload) {
    yyjson_mut_doc *document = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root;
    yyjson_mut_val *copied;
    char *json;
    size_t size;
    bool outcome;
    if (document == NULL) return false;
    root = yyjson_mut_obj(document);
    copied = yyjson_val_mut_copy(document, (yyjson_val *)params);
    if (root == NULL || copied == NULL ||
        !yyjson_mut_obj_add_str(document, root, "jsonrpc", "2.0") ||
        !yyjson_mut_obj_add_uint(document, root, "id", id) ||
        !yyjson_mut_obj_add_strncpy(document, root, "method", method, method_size) ||
        !yyjson_mut_obj_add_uint(document, root, "deadline_unix_ms", deadline) ||
        !yyjson_mut_obj_add_val(document, root, "params", copied)) {
        yyjson_mut_doc_free(document);
        return false;
    }
    yyjson_mut_doc_set_root(document, root);
    json = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &size);
    yyjson_mut_doc_free(document);
    if (json == NULL) return false;
    outcome = ss_buffer_copy(payload, (const unsigned char *)json, size);
    ss_secure_clear(json, size);
    free(json);
    return outcome;
}

static bool send_cancel(secretspec_ipc_client *client, uint64_t id) {
    char payload[128];
    int size = snprintf(payload, sizeof(payload),
                        "{\"jsonrpc\":\"2.0\",\"method\":\"rpc.cancel\",\"params\":{\"id\":%llu}}",
                        (unsigned long long)id);
    return size > 0 && (size_t)size < sizeof(payload) &&
           write_payload(client, (const unsigned char *)payload, (size_t)size);
}

static secretspec_ipc_status start_request(
    secretspec_ipc_client *client,
    const char *method,
    size_t method_size,
    yyjson_val *params,
    uint64_t deadline,
    bool application,
    secretspec_ipc_call **call) {
    uint64_t id;
    ss_request *request;
    secretspec_ipc_call *handle;
    secretspec_ipc_buffer payload = {NULL, 0};
    uint64_t ceiling = ss_now_unix_ms() + SS_MAX_DEADLINE_HORIZON_MS;
    /* Bound the tracked deadline so the request is guaranteed to expire and
     * release its in-flight slot. The wire value carries the same clamp so the
     * peer never enforces a longer deadline than this client tracks. */
    if (deadline > ceiling) deadline = ceiling;
    mutex_lock(&client->mutex);
    if (client->closed || (application && (!client->ready || client->closing))) {
        mutex_unlock(&client->mutex);
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    if (client->next_id == 0 || client->next_id > SS_MAX_ID ||
        client->in_flight >= client->max_in_flight ||
        client->entry_count >= client->max_in_flight * 2) {
        mutex_unlock(&client->mutex);
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    id = client->next_id++;
    request = request_new(id, deadline);
    handle = (secretspec_ipc_call *)calloc(1, sizeof(*handle));
    if (request == NULL || handle == NULL) {
        if (request != NULL) { request_release(request); request_release(request); }
        free(handle);
        mutex_unlock(&client->mutex);
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    request->next = client->requests;
    client->requests = request;
    client->in_flight++;
    client->entry_count++;
    handle->client = client;
    handle->request = request;
    (void)atomic_fetch_add(&client->references, 1);
    condition_broadcast(&client->state_changed);
    mutex_unlock(&client->mutex);

    if (!build_request(id, method, method_size, deadline, params, &payload) ||
        !write_payload(client, payload.data, payload.size)) {
        secretspec_ipc_buffer_free(payload);
        mutex_lock(&client->mutex);
        if (request->running) {
            request->running = false;
            request->status = SECRETSPEC_IPC_IO;
            client->in_flight--;
            remove_request(client, request);
            condition_broadcast(&request->condition);
            mutex_unlock(&client->mutex);
            request_release(request);
        } else {
            mutex_unlock(&client->mutex);
        }
        *call = handle;
        return SECRETSPEC_IPC_IO;
    }
    secretspec_ipc_buffer_free(payload);
    *call = handle;
    return SECRETSPEC_IPC_OK;
}

static bool string_equals(yyjson_val *value, const char *expected) {
    return yyjson_is_str(value) && yyjson_get_len(value) == strlen(expected) &&
           memcmp(yyjson_get_str(value), expected, yyjson_get_len(value)) == 0;
}

static bool error_kind(
    yyjson_val *error,
    secretspec_ipc_status *status,
    const char **kind_out) {
    static const char *const error_keys[] = {"code", "message", "data"};
    static const char *const data_keys[] = {"kind", "retryable", "retry_after_ms"};
    yyjson_val *code_value;
    yyjson_val *message;
    yyjson_val *data;
    yyjson_val *kind;
    yyjson_val *retryable;
    yyjson_val *retry_after;
    int64_t code;
    const char *kind_text;
    size_t kind_size;
    struct mapping { int64_t code; const char *kind; secretspec_ipc_status status; };
    static const struct mapping mappings[] = {
        {-32700, "parse_error", SECRETSPEC_IPC_PROTOCOL},
        {-32600, "invalid_request", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32601, "method_not_found", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32602, "invalid_params", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32603, "internal", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32000, "unsupported_version", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32001, "capability_required", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32002, "deadline_exceeded", SECRETSPEC_IPC_DEADLINE_EXCEEDED},
        {-32003, "cancelled", SECRETSPEC_IPC_CANCELLED},
        {-32004, "unavailable", SECRETSPEC_IPC_UNAVAILABLE},
        {-32005, "permission_denied", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32006, "interaction_required", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32007, "conflict", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32008, "operation_failed", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32009, "message_too_large", SECRETSPEC_IPC_REMOTE_ERROR},
        {-32010, "representation_mismatch", SECRETSPEC_IPC_REMOTE_ERROR}
    };
    size_t index;
    if (!ss_json_is_closed_object(error, error_keys, 3)) return false;
    code_value = yyjson_obj_get(error, "code");
    message = yyjson_obj_get(error, "message");
    data = yyjson_obj_get(error, "data");
    if (!yyjson_is_sint(code_value) || !yyjson_is_str(message) ||
        yyjson_get_len(message) == 0 || yyjson_get_len(message) > 256 ||
        !ss_json_is_closed_object(data, data_keys, 3)) return false;
    code = yyjson_get_sint(code_value);
    kind = yyjson_obj_get(data, "kind");
    retryable = yyjson_obj_get(data, "retryable");
    retry_after = yyjson_obj_get(data, "retry_after_ms");
    if (!yyjson_is_str(kind) || !yyjson_is_bool(retryable)) return false;
    kind_text = yyjson_get_str(kind);
    kind_size = yyjson_get_len(kind);
    for (index = 0; index < sizeof(mappings) / sizeof(mappings[0]); index++) {
        if (mappings[index].code == code && strlen(mappings[index].kind) == kind_size &&
            memcmp(mappings[index].kind, kind_text, kind_size) == 0) {
            if (retry_after != NULL) {
                uint64_t retry_after_ms;
                if (code != -32004 || !ss_json_u64(retry_after, &retry_after_ms) || retry_after_ms == 0) return false;
            }
            *status = mappings[index].status;
            *kind_out = mappings[index].kind;
            return true;
        }
    }
    return false;
}

static bool parse_response(
    const unsigned char *payload,
    size_t size,
    uint64_t *id,
    secretspec_ipc_status *status,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error_buffer) {
    static const char *const success_keys[] = {"jsonrpc", "id", "result"};
    static const char *const error_keys[] = {"jsonrpc", "id", "error"};
    yyjson_doc *document = NULL;
    yyjson_val *root;
    yyjson_val *id_value;
    yyjson_val *result_value;
    yyjson_val *error_value;
    const char *kind = NULL;
    bool valid = false;
    if (!ss_json_validate(payload, size, &document)) return false;
    root = yyjson_doc_get_root(document);
    if (!string_equals(yyjson_obj_get(root, "jsonrpc"), "2.0")) goto done;
    id_value = yyjson_obj_get(root, "id");
    if (!ss_json_u64(id_value, id) || *id == 0 || *id > SS_MAX_ID) goto done;
    result_value = yyjson_obj_get(root, "result");
    error_value = yyjson_obj_get(root, "error");
    if ((result_value == NULL) == (error_value == NULL)) goto done;
    if (result_value != NULL) {
        if (!ss_json_is_closed_object(root, success_keys, 3) ||
            !ss_json_write_value(result_value, result)) goto done;
        *status = SECRETSPEC_IPC_OK;
    } else {
        if (!ss_json_is_closed_object(root, error_keys, 3) ||
            !error_kind(error_value, status, &kind)) goto done;
        ss_set_error(error_buffer, kind, "remote error");
    }
    valid = true;
done:
    yyjson_doc_free(document);
    if (!valid) {
        secretspec_ipc_buffer_free(*result);
        secretspec_ipc_buffer_free(*error_buffer);
        ss_buffer_reset(result);
        ss_buffer_reset(error_buffer);
    }
    return valid;
}

static void fail_all(secretspec_ipc_client *client, secretspec_ipc_status status) {
    ss_request *request;
    ss_request *next;
    mutex_lock(&client->mutex);
    if (client->closed) {
        mutex_unlock(&client->mutex);
        return;
    }
    client->closed = true;
    client->ready = false;
    request = client->requests;
    client->requests = NULL;
    client->entry_count = 0;
    client->in_flight = 0;
    while (request != NULL) {
        next = request->next;
        request->next = NULL;
        if (request->running) {
            request->running = false;
            request->status = status;
            ss_set_error(&request->error,
                         status == SECRETSPEC_IPC_PROTOCOL ? "protocol" : "unavailable",
                         status == SECRETSPEC_IPC_PROTOCOL ? "protocol error" : "session closed");
            condition_broadcast(&request->condition);
        }
        request_release(request);
        request = next;
    }
    condition_broadcast(&client->state_changed);
    mutex_unlock(&client->mutex);
    ss_process_interrupt_io(client->process);
}

static void outbound_free(ss_outbound *outbound) {
    if (outbound == NULL) return;
    secretspec_ipc_buffer_free(outbound->payload);
    ss_secure_clear(outbound, sizeof(*outbound));
    free(outbound);
}

static SS_THREAD_RETURN writer_main(void *context) {
    secretspec_ipc_client *client = (secretspec_ipc_client *)context;
    for (;;) {
        ss_outbound *outbound;
        mutex_lock(&client->write_mutex);
        while (client->write_head == NULL && !client->writer_stopping) {
            (void)condition_wait_until(&client->write_ready, &client->write_mutex,
                                       ss_now_unix_ms() + UINT64_C(1000));
        }
        if (client->writer_stopping) {
            outbound = client->write_head;
            client->write_head = NULL;
            client->write_tail = NULL;
            client->write_count = 0;
            mutex_unlock(&client->write_mutex);
            while (outbound != NULL) {
                ss_outbound *next = outbound->next;
                outbound_free(outbound);
                outbound = next;
            }
            break;
        }
        outbound = client->write_head;
        client->write_head = outbound->next;
        if (client->write_head == NULL) client->write_tail = NULL;
        client->write_count--;
        mutex_unlock(&client->write_mutex);

        if (!ss_frame_write(client->process, outbound->payload.data,
                            outbound->payload.size, outbound->limit)) {
            outbound_free(outbound);
            fail_all(client, SECRETSPEC_IPC_IO);
            break;
        }
        outbound_free(outbound);
    }
    SS_THREAD_END;
}

static SS_THREAD_RETURN reader_main(void *context) {
    secretspec_ipc_client *client = (secretspec_ipc_client *)context;
    for (;;) {
        size_t limit;
        secretspec_ipc_buffer payload = {NULL, 0};
        secretspec_ipc_buffer result = {NULL, 0};
        secretspec_ipc_buffer error = {NULL, 0};
        secretspec_ipc_status frame_status;
        secretspec_ipc_status response_status;
        bool clean_eof = false;
        uint64_t id = 0;
        ss_request *request;
        bool release_list_reference = false;

        mutex_lock(&client->mutex);
        if (client->closed) { mutex_unlock(&client->mutex); break; }
        limit = client->max_frame_bytes;
        mutex_unlock(&client->mutex);
        frame_status = ss_frame_read(client->process, limit, &payload, &clean_eof);
        if (frame_status != SECRETSPEC_IPC_OK || clean_eof) {
            fail_all(client, clean_eof ? SECRETSPEC_IPC_UNAVAILABLE : frame_status);
            break;
        }
        if (!parse_response(payload.data, payload.size, &id, &response_status, &result, &error)) {
            secretspec_ipc_buffer_free(payload);
            fail_all(client, SECRETSPEC_IPC_PROTOCOL);
            break;
        }
        secretspec_ipc_buffer_free(payload);

        mutex_lock(&client->mutex);
        request = find_request(client, id);
        if (request == NULL) {
            mutex_unlock(&client->mutex);
            secretspec_ipc_buffer_free(result);
            secretspec_ipc_buffer_free(error);
            fail_all(client, SECRETSPEC_IPC_PROTOCOL);
            break;
        }
        if (request->abandoned) {
            remove_request(client, request);
            release_list_reference = true;
        } else if (request->running) {
            request->running = false;
            request->status = response_status;
            request->result = result;
            request->error = error;
            ss_buffer_reset(&result);
            ss_buffer_reset(&error);
            client->in_flight--;
            remove_request(client, request);
            release_list_reference = true;
            condition_broadcast(&request->condition);
        } else {
            mutex_unlock(&client->mutex);
            secretspec_ipc_buffer_free(result);
            secretspec_ipc_buffer_free(error);
            fail_all(client, SECRETSPEC_IPC_PROTOCOL);
            break;
        }
        if (id == 1) {
            while (client->initializing && !client->closed) {
                (void)condition_wait_until(&client->state_changed, &client->mutex,
                                           ss_now_unix_ms() + UINT64_C(1000));
            }
        }
        mutex_unlock(&client->mutex);
        secretspec_ipc_buffer_free(result);
        secretspec_ipc_buffer_free(error);
        if (release_list_reference) request_release(request);
    }
    SS_THREAD_END;
}

static SS_THREAD_RETURN stderr_main(void *context) {
    secretspec_ipc_client *client = (secretspec_ipc_client *)context;
    unsigned char buffer[4096];
    unsigned char *retained = NULL;
    size_t retained_size = 0;
    if (client->max_stderr_bytes != 0) {
        retained = (unsigned char *)malloc(client->max_stderr_bytes);
    }
    for (;;) {
        ptrdiff_t count = ss_process_read_stderr(client->process, buffer, sizeof(buffer));
        if (count <= 0) break;
        if (retained != NULL && retained_size < client->max_stderr_bytes) {
            size_t copy = (size_t)count;
            if (copy > client->max_stderr_bytes - retained_size) copy = client->max_stderr_bytes - retained_size;
            memcpy(retained + retained_size, buffer, copy);
            retained_size += copy;
        }
        ss_secure_clear(buffer, sizeof(buffer));
    }
    if (retained != NULL) {
        ss_secure_clear(retained, client->max_stderr_bytes);
        free(retained);
    }
    SS_THREAD_END;
}

static SS_THREAD_RETURN deadline_main(void *context) {
    secretspec_ipc_client *client = (secretspec_ipc_client *)context;
    for (;;) {
        uint64_t expired_ids[SS_MAX_IN_FLIGHT * 2];
        size_t expired_count = 0;
        uint64_t wake_at = UINT64_MAX;
        uint64_t now = ss_now_unix_ms();
        ss_request *request;

        mutex_lock(&client->mutex);
        if (client->closed) {
            mutex_unlock(&client->mutex);
            break;
        }
        for (request = client->requests; request != NULL; request = request->next) {
            if (!request->running) continue;
            if (request->deadline_unix_ms <= now) {
                request->running = false;
                request->abandoned = true;
                request->status = SECRETSPEC_IPC_DEADLINE_EXCEEDED;
                client->in_flight--;
                ss_set_error(&request->error, "deadline_exceeded", "deadline exceeded");
                condition_broadcast(&request->condition);
                if (!request->cancel_sent && expired_count < SS_MAX_IN_FLIGHT * 2) {
                    request->cancel_sent = true;
                    expired_ids[expired_count++] = request->id;
                }
            } else if (request->deadline_unix_ms < wake_at) {
                wake_at = request->deadline_unix_ms;
            }
        }
        if (expired_count == 0) {
            if (wake_at == UINT64_MAX) wake_at = now + UINT64_C(1000);
            (void)condition_wait_until(&client->state_changed, &client->mutex, wake_at);
        }
        mutex_unlock(&client->mutex);

        for (size_t index = 0; index < expired_count; index++) {
            (void)send_cancel(client, expired_ids[index]);
        }
    }
    SS_THREAD_END;
}

static bool versions_contains(yyjson_val *array, uint64_t version) {
    size_t index;
    size_t maximum;
    yyjson_val *item;
    yyjson_arr_foreach(array, index, maximum, item) {
        uint64_t value;
        if (ss_json_u64(item, &value) && value == version) return true;
    }
    return false;
}

static bool array_has_text(yyjson_val *array, const char *text) {
    size_t index;
    size_t maximum;
    yyjson_val *item;
    yyjson_arr_foreach(array, index, maximum, item) {
        if (string_equals(item, text)) return true;
    }
    return false;
}

static bool string_array_valid(yyjson_val *array, bool nonempty) {
    size_t index;
    size_t maximum;
    yyjson_val *item;
    if (!yyjson_is_arr(array) || (nonempty && yyjson_arr_size(array) == 0)) return false;
    yyjson_arr_foreach(array, index, maximum, item) {
        size_t earlier;
        yyjson_val *other;
        if (!yyjson_is_str(item) || yyjson_get_len(item) == 0 || yyjson_get_len(item) > 256) return false;
        for (earlier = 0; earlier < index; earlier++) {
            other = yyjson_arr_get(array, earlier);
            if (yyjson_get_len(other) == yyjson_get_len(item) &&
                memcmp(yyjson_get_str(other), yyjson_get_str(item), yyjson_get_len(item)) == 0) return false;
        }
    }
    return true;
}

static bool product_valid(yyjson_val *product) {
    static const char *const keys[] = {"name", "version"};
    yyjson_val *name;
    yyjson_val *version;
    if (!ss_json_is_closed_object(product, keys, 2)) return false;
    name = yyjson_obj_get(product, "name");
    version = yyjson_obj_get(product, "version");
    return yyjson_is_str(name) && yyjson_get_len(name) > 0 && yyjson_get_len(name) <= 256 &&
           yyjson_is_str(version) && yyjson_get_len(version) > 0 && yyjson_get_len(version) <= 256;
}

static bool limits_valid(yyjson_val *limits, size_t *frame, size_t *in_flight) {
    static const char *const keys[] = {"max_frame_bytes", "max_in_flight"};
    uint64_t frame_value;
    uint64_t in_flight_value;
    if (!ss_json_is_closed_object(limits, keys, 2) ||
        !ss_json_u64(yyjson_obj_get(limits, "max_frame_bytes"), &frame_value) ||
        !ss_json_u64(yyjson_obj_get(limits, "max_in_flight"), &in_flight_value) ||
        frame_value < SS_MIN_FRAME || frame_value > SS_ABSOLUTE_MAX_FRAME ||
        in_flight_value == 0 || in_flight_value > SS_MAX_IN_FLIGHT) return false;
    *frame = (size_t)frame_value;
    *in_flight = (size_t)in_flight_value;
    return true;
}

static bool initialize_offer_valid(yyjson_val *offer) {
    static const char *const keys[] = {
        "protocol", "versions", "client", "limits", "application"
    };
    yyjson_val *protocol;
    yyjson_val *versions;
    size_t index;
    size_t maximum;
    yyjson_val *version;
    size_t frame;
    size_t in_flight;
    if (!ss_json_is_closed_object(offer, keys, 5)) return false;
    protocol = yyjson_obj_get(offer, "protocol");
    versions = yyjson_obj_get(offer, "versions");
    if ((!string_equals(protocol, "secretspec.client") &&
         !string_equals(protocol, "secretspec.provider")) ||
        !yyjson_is_arr(versions) || yyjson_arr_size(versions) == 0 ||
        !product_valid(yyjson_obj_get(offer, "client")) ||
        !limits_valid(yyjson_obj_get(offer, "limits"), &frame, &in_flight) ||
        !yyjson_is_obj(yyjson_obj_get(offer, "application"))) return false;
    yyjson_arr_foreach(versions, index, maximum, version) {
        uint64_t value;
        size_t earlier;
        if (!ss_json_u64(version, &value) || value == 0 || value > UINT32_MAX) return false;
        for (earlier = 0; earlier < index; earlier++) {
            if (yyjson_get_uint(yyjson_arr_get(versions, earlier)) == value) return false;
        }
    }
    return true;
}

static void capabilities_clear(secretspec_ipc_client *client) {
    size_t index;
    for (index = 0; index < client->capability_count; index++) free(client->capabilities[index]);
    free(client->capabilities);
    client->capabilities = NULL;
    client->capability_count = 0;
}

static bool validate_initialize_result(
    secretspec_ipc_client *client,
    yyjson_val *offer,
    const unsigned char *json,
    size_t json_size) {
    static const char *const keys[] = {
        "protocol", "version", "server", "capabilities", "limits", "application"
    };
    yyjson_doc *document = NULL;
    yyjson_val *result;
    yyjson_val *protocol;
    yyjson_val *version;
    yyjson_val *capabilities;
    yyjson_val *offered_versions;
    uint64_t selected_version;
    size_t frame;
    size_t in_flight;
    size_t offered_frame;
    size_t offered_in_flight;
    size_t index;
    size_t maximum;
    yyjson_val *capability;
    bool valid = false;
    if (!ss_json_validate(json, json_size, &document)) return false;
    result = yyjson_doc_get_root(document);
    protocol = yyjson_obj_get(result, "protocol");
    version = yyjson_obj_get(result, "version");
    capabilities = yyjson_obj_get(result, "capabilities");
    offered_versions = yyjson_obj_get(offer, "versions");
    if (!ss_json_is_closed_object(result, keys, 6) ||
        !yyjson_equals_strn(protocol, yyjson_get_str(yyjson_obj_get(offer, "protocol")),
                            yyjson_get_len(yyjson_obj_get(offer, "protocol"))) ||
        !ss_json_u64(version, &selected_version) ||
        !versions_contains(offered_versions, selected_version) ||
        !product_valid(yyjson_obj_get(result, "server")) ||
        !string_array_valid(capabilities, true) ||
        !limits_valid(yyjson_obj_get(result, "limits"), &frame, &in_flight) ||
        !limits_valid(yyjson_obj_get(offer, "limits"), &offered_frame, &offered_in_flight) ||
        frame > offered_frame || in_flight > offered_in_flight ||
        !yyjson_is_obj(yyjson_obj_get(result, "application"))) goto done;
    if (string_equals(protocol, "secretspec.client")) {
        if (!array_has_text(capabilities, "client.resolve") ||
            !array_has_text(capabilities, "client.release")) goto done;
    } else {
        if (!array_has_text(capabilities, "provider.resolve_address") ||
            (!array_has_text(capabilities, "provider.get") &&
             !array_has_text(capabilities, "provider.exists") &&
             !array_has_text(capabilities, "provider.set")) ||
            (array_has_text(capabilities, "provider.get_many") &&
             !array_has_text(capabilities, "provider.get")) ||
            (array_has_text(capabilities, "provider.set_expiring") &&
             !array_has_text(capabilities, "provider.set"))) goto done;
    }
    client->capabilities = (char **)calloc(yyjson_arr_size(capabilities), sizeof(char *));
    if (client->capabilities == NULL) goto done;
    yyjson_arr_foreach(capabilities, index, maximum, capability) {
        size_t size = yyjson_get_len(capability);
        client->capabilities[index] = (char *)malloc(size + 1);
        if (client->capabilities[index] == NULL) {
            client->capability_count = index;
            capabilities_clear(client);
            goto done;
        }
        memcpy(client->capabilities[index], yyjson_get_str(capability), size);
        client->capabilities[index][size] = '\0';
    }
    client->capability_count = yyjson_arr_size(capabilities);
    client->max_frame_bytes = frame;
    client->max_in_flight = in_flight;
    valid = true;
done:
    yyjson_doc_free(document);
    return valid;
}

static bool method_advertised(secretspec_ipc_client *client, const char *method, size_t size) {
    size_t index;
    for (index = 0; index < client->capability_count; index++) {
        if (strlen(client->capabilities[index]) == size &&
            memcmp(client->capabilities[index], method, size) == 0) return true;
    }
    return false;
}

static secretspec_ipc_status wait_call(
    secretspec_ipc_call *call,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error) {
    secretspec_ipc_client *client = call->client;
    ss_request *request = call->request;
    secretspec_ipc_status status;
    bool timed_out = false;
    mutex_lock(&client->mutex);
    if (request->waiter) {
        mutex_unlock(&client->mutex);
        ss_set_error(error, "invalid_argument", "call already has a waiter");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    request->waiter = true;
    while (request->running) {
        if (request->deadline_unix_ms <= ss_now_unix_ms() ||
            !condition_wait_until(&request->condition, &client->mutex, request->deadline_unix_ms)) {
            if (request->running) {
                request->running = false;
                request->abandoned = true;
                request->status = SECRETSPEC_IPC_DEADLINE_EXCEEDED;
                client->in_flight--;
                ss_set_error(&request->error, "deadline_exceeded", "deadline exceeded");
                request->cancel_sent = true;
                timed_out = true;
            }
            break;
        }
    }
    status = request->status;
    if (status == SECRETSPEC_IPC_OK && result != NULL) {
        *result = request->result;
        ss_buffer_reset(&request->result);
    } else if (status != SECRETSPEC_IPC_OK && error != NULL) {
        *error = request->error;
        ss_buffer_reset(&request->error);
    }
    mutex_unlock(&client->mutex);
    if (timed_out) (void)send_cancel(client, request->id);
    return status;
}

static void client_destroy(secretspec_ipc_client *client) {
    if (client == NULL) return;
    capabilities_clear(client);
    condition_destroy(&client->write_ready);
    condition_destroy(&client->state_changed);
    mutex_destroy(&client->write_mutex);
    mutex_destroy(&client->mutex);
    ss_secure_clear(client, sizeof(*client));
    free(client);
}

static void client_release(secretspec_ipc_client *client) {
    if (atomic_fetch_sub(&client->references, 1) == 1) client_destroy(client);
}

static void cleanup_process(secretspec_ipc_client *client, uint64_t deadline) {
    ss_outbound *outbound;
    uint64_t cap = ss_now_unix_ms() + UINT64_C(5000);
    if (deadline > cap) deadline = cap;
    mutex_lock(&client->write_mutex);
    client->writer_stopping = true;
    condition_broadcast(&client->write_ready);
    mutex_unlock(&client->write_mutex);
    fail_all(client, SECRETSPEC_IPC_UNAVAILABLE);
    ss_process_interrupt_io(client->process);
    if (client->writer_started) thread_interrupt(client->writer_thread);
    if (client->reader_started) thread_interrupt(client->reader_thread);
    if (client->stderr_started) thread_interrupt(client->stderr_thread);
    ss_process_close_stdin(client->process);
    if (!ss_process_wait(client->process, deadline)) ss_process_terminate(client->process);
    if (client->writer_started) thread_interrupt(client->writer_thread);
    if (client->reader_started) thread_interrupt(client->reader_thread);
    if (client->stderr_started) thread_interrupt(client->stderr_thread);
    if (client->writer_started) {
        thread_join(client->writer_thread);
        client->writer_started = false;
    }
    if (client->deadline_started) {
        thread_join(client->deadline_thread);
        client->deadline_started = false;
    }
    mutex_lock(&client->write_mutex);
    outbound = client->write_head;
    client->write_head = NULL;
    client->write_tail = NULL;
    client->write_count = 0;
    mutex_unlock(&client->write_mutex);
    while (outbound != NULL) {
        ss_outbound *next = outbound->next;
        outbound_free(outbound);
        outbound = next;
    }
    if (client->reader_started) {
        thread_join(client->reader_thread);
        client->reader_started = false;
    }
    if (client->stderr_started) {
        thread_join(client->stderr_thread);
        client->stderr_started = false;
    }
    ss_process_free(client->process);
    client->process = NULL;
}

static bool options_valid(const secretspec_ipc_options *options) {
    size_t minimum_size = offsetof(secretspec_ipc_options, max_stderr_bytes);
    size_t index;
    if (options == NULL || options->struct_size < minimum_size ||
        options->struct_size > sizeof(*options) ||
        options->abi_version != SECRETSPEC_IPC_ABI_VERSION ||
        (options->flags & ~SS_KNOWN_FLAGS) != 0 || options->reserved != 0 ||
        !valid_slice(options->executable, false) ||
        !valid_slice(options->initialize_params_json, false) ||
        (options->argument_count != 0 && options->arguments == NULL) ||
        (options->environment_count != 0 && options->environment == NULL) ||
        options->argument_count > 4096 || options->environment_count > 4096) return false;
    for (index = 0; index < options->argument_count; index++) {
        if (!valid_slice(options->arguments[index], true)) return false;
    }
    for (index = 0; index < options->environment_count; index++) {
        if (!valid_slice(options->environment[index], false)) return false;
    }
    if (options->struct_size >= sizeof(*options) && options->max_stderr_bytes > SS_ABSOLUTE_MAX_FRAME) return false;
    return true;
}

secretspec_ipc_status secretspec_ipc_client_open(
    const secretspec_ipc_options *options,
    uint64_t deadline_unix_ms,
    secretspec_ipc_client **client_out,
    secretspec_ipc_buffer *server_info,
    secretspec_ipc_buffer *error) {
    ss_launch launch;
    secretspec_ipc_client *client = NULL;
    yyjson_doc *initialize_document = NULL;
    yyjson_val *initialize_root;
    secretspec_ipc_call *initialize_call = NULL;
    secretspec_ipc_buffer initialize_result = {NULL, 0};
    secretspec_ipc_status status;

    if (client_out != NULL) *client_out = NULL;
    ss_buffer_reset(server_info);
    ss_buffer_reset(error);
    if (client_out == NULL || server_info == NULL || error == NULL ||
        !options_valid(options) || deadline_unix_ms <= ss_now_unix_ms()) {
        ss_set_error(error, "invalid_argument", "invalid client options");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    if (!ss_json_validate(options->initialize_params_json.data,
                          options->initialize_params_json.size,
                          &initialize_document)) {
        ss_set_error(error, "invalid_argument", "invalid initialization JSON");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    initialize_root = yyjson_doc_get_root(initialize_document);
    if (!initialize_offer_valid(initialize_root)) {
        yyjson_doc_free(initialize_document);
        ss_set_error(error, "invalid_argument", "invalid initialization params");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    status = launch_from_options(options, &launch);
    if (status != SECRETSPEC_IPC_OK) {
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, status == SECRETSPEC_IPC_INVALID_ARGUMENT ? "invalid_argument" : "unavailable",
                     status == SECRETSPEC_IPC_INVALID_ARGUMENT ? "invalid launch options" : "allocation failed");
        return status;
    }
    client = (secretspec_ipc_client *)calloc(1, sizeof(*client));
    if (client == NULL) {
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    if (!mutex_init(&client->mutex)) {
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    if (!mutex_init(&client->write_mutex)) {
        mutex_destroy(&client->mutex);
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    if (!condition_init(&client->state_changed)) {
        mutex_destroy(&client->write_mutex);
        mutex_destroy(&client->mutex);
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    if (!condition_init(&client->write_ready)) {
        condition_destroy(&client->state_changed);
        mutex_destroy(&client->write_mutex);
        mutex_destroy(&client->mutex);
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    atomic_init(&client->references, 1);
    client->initializing = true;
    client->max_frame_bytes = SS_ABSOLUTE_MAX_FRAME;
    client->max_in_flight = 1;
    client->next_id = 1;
    client->max_stderr_bytes = options->struct_size >= sizeof(*options) ? options->max_stderr_bytes : 65536;
    status = ss_process_spawn(&launch, &client->process);
    launch_free(&launch);
    if (status != SECRETSPEC_IPC_OK) {
        yyjson_doc_free(initialize_document);
        client_destroy(client);
        ss_set_error(error, "unavailable", "child launch failed");
        return status;
    }
    if (!thread_start(&client->writer_thread, writer_main, client)) {
        yyjson_doc_free(initialize_document);
        cleanup_process(client, ss_now_unix_ms());
        client_destroy(client);
        ss_set_error(error, "unavailable", "writer worker failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    client->writer_started = true;
    if (!thread_start(&client->reader_thread, reader_main, client)) {
        yyjson_doc_free(initialize_document);
        cleanup_process(client, ss_now_unix_ms());
        client_destroy(client);
        ss_set_error(error, "unavailable", "reader worker failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    client->reader_started = true;
    if (!thread_start(&client->stderr_thread, stderr_main, client)) {
        yyjson_doc_free(initialize_document);
        cleanup_process(client, ss_now_unix_ms());
        client_destroy(client);
        ss_set_error(error, "unavailable", "stderr worker failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    client->stderr_started = true;
    if (!thread_start(&client->deadline_thread, deadline_main, client)) {
        yyjson_doc_free(initialize_document);
        cleanup_process(client, ss_now_unix_ms());
        client_destroy(client);
        ss_set_error(error, "unavailable", "deadline worker failed");
        return SECRETSPEC_IPC_UNAVAILABLE;
    }
    client->deadline_started = true;

    status = start_request(client, "rpc.initialize", strlen("rpc.initialize"),
                           initialize_root, deadline_unix_ms, false, &initialize_call);
    if (status == SECRETSPEC_IPC_OK) {
        status = wait_call(initialize_call, &initialize_result, error);
    }
    if (initialize_call != NULL) secretspec_ipc_call_free(initialize_call);
    if (status == SECRETSPEC_IPC_OK &&
        !validate_initialize_result(client, initialize_root,
                                    initialize_result.data, initialize_result.size)) {
        status = SECRETSPEC_IPC_PROTOCOL;
        ss_set_error(error, "protocol", "invalid initialization response");
    }
    yyjson_doc_free(initialize_document);
    if (status != SECRETSPEC_IPC_OK) {
        secretspec_ipc_buffer_free(initialize_result);
        mutex_lock(&client->mutex);
        client->initializing = false;
        condition_broadcast(&client->state_changed);
        mutex_unlock(&client->mutex);
        cleanup_process(client, deadline_unix_ms);
        client_destroy(client);
        return status;
    }

    *server_info = initialize_result;
    mutex_lock(&client->mutex);
    client->initializing = false;
    client->ready = true;
    condition_broadcast(&client->state_changed);
    mutex_unlock(&client->mutex);
    *client_out = client;
    return SECRETSPEC_IPC_OK;
}

secretspec_ipc_status secretspec_ipc_call_start(
    secretspec_ipc_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_ipc_call **call,
    secretspec_ipc_buffer *error) {
    yyjson_doc *document = NULL;
    yyjson_val *root;
    secretspec_ipc_status status;
    ss_buffer_reset(error);
    if (call != NULL) *call = NULL;
    if (client == NULL || call == NULL || error == NULL || method == NULL || method_size == 0 ||
        method_size > 256 || params_json == NULL || params_size == 0 ||
        memchr(method, 0, method_size) != NULL || !valid_utf8(method, method_size) ||
        deadline_unix_ms <= ss_now_unix_ms() ||
        !ss_json_validate(params_json, params_size, &document)) {
        ss_set_error(error, "invalid_argument", "invalid call arguments");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    root = yyjson_doc_get_root(document);
    mutex_lock(&client->mutex);
    if (!method_advertised(client, (const char *)method, method_size)) {
        mutex_unlock(&client->mutex);
        yyjson_doc_free(document);
        ss_set_error(error, "protocol", "method was not advertised");
        return SECRETSPEC_IPC_PROTOCOL;
    }
    mutex_unlock(&client->mutex);
    status = start_request(client, (const char *)method, method_size, root,
                           deadline_unix_ms, true, call);
    yyjson_doc_free(document);
    if (status != SECRETSPEC_IPC_OK) {
        if (*call != NULL) {
            secretspec_ipc_call_free(*call);
            *call = NULL;
        }
        ss_set_error(error, status == SECRETSPEC_IPC_UNAVAILABLE ? "unavailable" : "io",
                     status == SECRETSPEC_IPC_UNAVAILABLE ? "session capacity unavailable" : "request write failed");
    }
    return status;
}

secretspec_ipc_status secretspec_ipc_client_call(
    secretspec_ipc_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error) {
    secretspec_ipc_call *call = NULL;
    secretspec_ipc_status status;
    if (result == NULL || error == NULL) {
        if (error != NULL) ss_set_error(error, "invalid_argument", "invalid call outputs");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    ss_buffer_reset(result);
    ss_buffer_reset(error);
    status = secretspec_ipc_call_start(client, method, method_size, params_json, params_size,
                                       deadline_unix_ms, &call, error);
    if (status == SECRETSPEC_IPC_OK) status = secretspec_ipc_call_wait(call, result, error);
    secretspec_ipc_call_free(call);
    return status;
}

secretspec_ipc_status secretspec_ipc_call_wait(
    secretspec_ipc_call *call,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error) {
    ss_buffer_reset(result);
    ss_buffer_reset(error);
    if (call == NULL || result == NULL || error == NULL) {
        ss_set_error(error, "invalid_argument", "invalid call handle");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    return wait_call(call, result, error);
}

void secretspec_ipc_call_cancel(secretspec_ipc_call *call) {
    bool send = false;
    if (call == NULL) return;
    mutex_lock(&call->client->mutex);
    if (call->request->running && !call->request->cancel_sent) {
        call->request->cancel_sent = true;
        send = true;
    }
    mutex_unlock(&call->client->mutex);
    if (send) (void)send_cancel(call->client, call->request->id);
}

void secretspec_ipc_call_free(secretspec_ipc_call *call) {
    secretspec_ipc_client *client;
    if (call == NULL) return;
    client = call->client;
    secretspec_ipc_call_cancel(call);
    request_release(call->request);
    ss_secure_clear(call, sizeof(*call));
    free(call);
    client_release(client);
}

secretspec_ipc_status secretspec_ipc_client_close(
    secretspec_ipc_client *client,
    uint64_t deadline_unix_ms,
    secretspec_ipc_buffer *error) {
    static const unsigned char params[] = "{}";
    yyjson_doc *document = NULL;
    secretspec_ipc_call *shutdown_call = NULL;
    secretspec_ipc_buffer result = {NULL, 0};
    secretspec_ipc_status status = SECRETSPEC_IPC_OK;
    ss_buffer_reset(error);
    if (client == NULL || error == NULL || deadline_unix_ms <= ss_now_unix_ms()) {
        ss_set_error(error, "invalid_argument", "invalid close arguments");
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    mutex_lock(&client->mutex);
    if (client->closing) {
        mutex_unlock(&client->mutex);
        return SECRETSPEC_IPC_INVALID_ARGUMENT;
    }
    if (client->closed) {
        mutex_unlock(&client->mutex);
        cleanup_process(client, deadline_unix_ms);
        return SECRETSPEC_IPC_OK;
    }
    client->closing = true;
    mutex_unlock(&client->mutex);
    if (!ss_json_validate(params, sizeof(params) - 1, &document)) {
        status = SECRETSPEC_IPC_PROTOCOL;
    } else {
        status = start_request(client, "rpc.shutdown", strlen("rpc.shutdown"),
                               yyjson_doc_get_root(document), deadline_unix_ms, false,
                               &shutdown_call);
        if (status == SECRETSPEC_IPC_OK) status = wait_call(shutdown_call, &result, error);
    }
    yyjson_doc_free(document);
    if (shutdown_call != NULL) secretspec_ipc_call_free(shutdown_call);
    if (status == SECRETSPEC_IPC_OK) {
        yyjson_doc *result_document = NULL;
        if (!ss_json_validate(result.data, result.size, &result_document) ||
            !yyjson_is_obj(yyjson_doc_get_root(result_document)) ||
            yyjson_obj_size(yyjson_doc_get_root(result_document)) != 0) {
            status = SECRETSPEC_IPC_PROTOCOL;
            ss_set_error(error, "protocol", "invalid shutdown response");
        }
        yyjson_doc_free(result_document);
    }
    secretspec_ipc_buffer_free(result);
    cleanup_process(client, deadline_unix_ms);
    return status;
}

void secretspec_ipc_client_free(secretspec_ipc_client *client) {
    secretspec_ipc_buffer error = {NULL, 0};
    bool needs_cleanup;
    bool orderly_close;
    if (client == NULL) return;
    mutex_lock(&client->mutex);
    if (client->user_released) {
        mutex_unlock(&client->mutex);
        return;
    }
    client->user_released = true;
    needs_cleanup = client->process != NULL;
    orderly_close = client->ready && !client->closing && !client->closed;
    mutex_unlock(&client->mutex);
    if (needs_cleanup) {
        if (orderly_close) {
            (void)secretspec_ipc_client_close(client, ss_now_unix_ms() + UINT64_C(5000), &error);
            secretspec_ipc_buffer_free(error);
        } else {
            cleanup_process(client, ss_now_unix_ms() + UINT64_C(5000));
        }
    }
    client_release(client);
}

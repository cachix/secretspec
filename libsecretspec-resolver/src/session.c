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
typedef struct ss_prompt ss_prompt;

/* One inbound client.prompt the endpoint is waiting on. Held by the session
 * until a caller takes it, so a prompt that arrives while nothing is waiting is
 * not lost and is not answered by the wrong thread. */
struct ss_prompt {
    struct secretspec_resolver_client *client;
    uint64_t id;
    uint64_t parent_request_id;
    uint64_t deadline_unix_ms;
    secretspec_resolver_buffer params;
    bool answered;
    ss_prompt *next;
};

struct ss_outbound {
    secretspec_resolver_buffer payload;
    size_t limit;
    ss_outbound *next;
};

struct ss_request {
    uint64_t id;
    uint64_t deadline_unix_ms;
    secretspec_resolver_status status;
    secretspec_resolver_buffer result;
    secretspec_resolver_buffer error;
    ss_condition condition;
    atomic_size_t references;
    bool running;
    bool abandoned;
    bool waiter;
    bool cancel_sent;
    ss_request *next;
};

struct secretspec_resolver_call {
    struct secretspec_resolver_client *client;
    ss_request *request;
};

struct secretspec_resolver_client {
    ss_process *process;
    ss_frame_reader frame_reader;
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
    uint64_t last_callback_id;
    ss_request *requests;
    ss_outbound *write_head;
    ss_outbound *write_tail;
    size_t write_count;
    char **capabilities;
    size_t capability_count;
    /* Set from SECRETSPEC_RESOLVER_ANSWER_PROMPTS. When false an inbound request is
     * the protocol violation it has always been, because the endpoint was never
     * told this client could answer one. */
    bool answer_prompts;
    ss_prompt *prompts;
    size_t prompt_count;
    atomic_size_t references;
    bool user_released;
};

static void request_release(ss_request *request) {
    if (request != NULL && atomic_fetch_sub(&request->references, 1) == 1) {
        secretspec_resolver_buffer_free(request->result);
        secretspec_resolver_buffer_free(request->error);
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
    request->status = SECRETSPEC_RESOLVER_UNAVAILABLE;
    request->running = true;
    atomic_init(&request->references, 2);
    if (!condition_init(&request->condition)) {
        free(request);
        return NULL;
    }
    return request;
}

static ss_request *find_request(secretspec_resolver_client *client, uint64_t id) {
    ss_request *request;
    for (request = client->requests; request != NULL; request = request->next) {
        if (request->id == id) return request;
    }
    return NULL;
}

static void remove_request(secretspec_resolver_client *client, ss_request *request) {
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

static bool valid_slice(secretspec_resolver_slice slice, bool allow_empty) {
    return (slice.size == 0 ? allow_empty : slice.data != NULL) &&
           (slice.data != NULL || slice.size == 0) &&
           (slice.size == 0 || (memchr(slice.data, 0, slice.size) == NULL && valid_utf8(slice.data, slice.size)));
}

static char *copy_slice(secretspec_resolver_slice slice) {
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

static secretspec_resolver_status launch_from_options(const secretspec_resolver_options *options, ss_launch *launch) {
    size_t index;
    memset(launch, 0, sizeof(*launch));
    launch->discover = (options->flags & SECRETSPEC_RESOLVER_DISCOVER_EXECUTABLE) != 0;
    launch->inherit_environment = (options->flags & SECRETSPEC_RESOLVER_INHERIT_ENVIRONMENT) != 0;
    launch->executable = copy_slice(options->executable);
    launch->argument_count = options->argument_count;
    launch->environment_count = options->environment_count;
    launch->arguments = (char **)calloc(launch->argument_count + 1, sizeof(char *));
    launch->environment = (char **)calloc(launch->environment_count + 1, sizeof(char *));
    if (launch->executable == NULL || launch->arguments == NULL || launch->environment == NULL) goto unavailable;
    if (!launch->discover && !absolute_executable(launch->executable)) return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    for (index = 0; index < launch->argument_count; index++) {
        launch->arguments[index] = copy_slice(options->arguments[index]);
        if (launch->arguments[index] == NULL) goto unavailable;
    }
    for (index = 0; index < launch->environment_count; index++) {
        launch->environment[index] = copy_slice(options->environment[index]);
        if (launch->environment[index] == NULL) goto unavailable;
        if (!environment_entry_valid(launch->environment[index])) return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    return SECRETSPEC_RESOLVER_OK;
unavailable:
    return SECRETSPEC_RESOLVER_UNAVAILABLE;
}

/* Queue while client->mutex is held. This lets callback answers validate their
 * parent and enqueue atomically with respect to the reader making it terminal. */
static bool write_payload_locked(secretspec_resolver_client *client, const unsigned char *payload, size_t size) {
    ss_outbound *outbound;
    size_t limit = client->max_frame_bytes;
    if (client->closed) return false;

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
        secretspec_resolver_buffer_free(outbound->payload);
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

static bool write_payload(secretspec_resolver_client *client, const unsigned char *payload, size_t size) {
    bool written;
    mutex_lock(&client->mutex);
    written = write_payload_locked(client, payload, size);
    mutex_unlock(&client->mutex);
    return written;
}

static bool build_request(
    uint64_t id,
    const char *method,
    size_t method_size,
    uint64_t deadline,
    yyjson_val *params,
    secretspec_resolver_buffer *payload) {
    yyjson_mut_doc *document = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root;
    yyjson_mut_val *meta;
    yyjson_mut_val *copied;
    char *json;
    size_t size;
    bool outcome;
    if (document == NULL) return false;
    root = yyjson_mut_obj(document);
    copied = yyjson_val_mut_copy(document, (yyjson_val *)params);
    meta = yyjson_mut_obj(document);
    if (root == NULL || meta == NULL || copied == NULL ||
        !yyjson_mut_obj_add_str(document, root, "jsonrpc", "2.0") ||
        !yyjson_mut_obj_add_uint(document, root, "id", id) ||
        !yyjson_mut_obj_add_strncpy(document, root, "method", method, method_size) ||
        !yyjson_mut_obj_add_uint(document, meta, "deadline_unix_ms", deadline) ||
        !yyjson_mut_obj_add_val(document, root, "_meta", meta) ||
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

static bool send_cancel(secretspec_resolver_client *client, uint64_t id) {
    char payload[128];
    int size = snprintf(payload, sizeof(payload),
                        "{\"jsonrpc\":\"2.0\",\"method\":\"rpc.cancel\",\"params\":{\"id\":%llu}}",
                        (unsigned long long)id);
    return size > 0 && (size_t)size < sizeof(payload) &&
           write_payload(client, (const unsigned char *)payload, (size_t)size);
}

static secretspec_resolver_status start_request(
    secretspec_resolver_client *client,
    const char *method,
    size_t method_size,
    yyjson_val *params,
    uint64_t deadline,
    bool application,
    secretspec_resolver_call **call) {
    uint64_t id;
    ss_request *request;
    secretspec_resolver_call *handle;
    secretspec_resolver_buffer payload = {NULL, 0};
    uint64_t ceiling = ss_now_unix_ms() + SS_MAX_DEADLINE_HORIZON_MS;
    /* Bound the tracked deadline so the request is guaranteed to expire and
     * release its in-flight slot. The wire value carries the same clamp so the
     * peer never enforces a longer deadline than this client tracks. */
    if (deadline > ceiling) deadline = ceiling;
    mutex_lock(&client->mutex);
    if (client->closed || (application && (!client->ready || client->closing))) {
        mutex_unlock(&client->mutex);
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    if (client->next_id == 0 || client->next_id > SS_MAX_ID ||
        client->in_flight >= client->max_in_flight ||
        client->entry_count >= client->max_in_flight * 2) {
        mutex_unlock(&client->mutex);
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    id = client->next_id++;
    request = request_new(id, deadline);
    handle = (secretspec_resolver_call *)calloc(1, sizeof(*handle));
    if (request == NULL || handle == NULL) {
        if (request != NULL) { request_release(request); request_release(request); }
        free(handle);
        mutex_unlock(&client->mutex);
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
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
        secretspec_resolver_buffer_free(payload);
        mutex_lock(&client->mutex);
        if (request->running) {
            request->running = false;
            request->status = SECRETSPEC_RESOLVER_IO;
            client->in_flight--;
            remove_request(client, request);
            condition_broadcast(&request->condition);
            mutex_unlock(&client->mutex);
            request_release(request);
        } else {
            mutex_unlock(&client->mutex);
        }
        *call = handle;
        return SECRETSPEC_RESOLVER_IO;
    }
    secretspec_resolver_buffer_free(payload);
    *call = handle;
    return SECRETSPEC_RESOLVER_OK;
}

static void prompts_clear(secretspec_resolver_client *client);

/* Drop queued callbacks once the endpoint no longer accepts an answer. Must be
 * called with client->mutex held. A taken prompt is guarded separately in
 * answer_prompt because it is no longer part of this list. */
static void prompts_expire(secretspec_resolver_client *client, uint64_t now_unix_ms) {
    ss_prompt **cursor = &client->prompts;
    while (*cursor != NULL) {
        ss_prompt *prompt = *cursor;
        if (prompt->deadline_unix_ms > now_unix_ms) {
            cursor = &prompt->next;
            continue;
        }
        *cursor = prompt->next;
        client->prompt_count--;
        secretspec_resolver_buffer_free(prompt->params);
        ss_secure_clear(prompt, sizeof(*prompt));
        free(prompt);
    }
}

/* A callback is a child of exactly one active request. Remove queued children
 * as soon as that parent is cancelled or terminal. A prompt already handed to
 * the caller is checked again by answer_prompt. Must hold client->mutex. */
static void prompts_cancel_parent(secretspec_resolver_client *client, uint64_t parent_request_id) {
    ss_prompt **cursor = &client->prompts;
    while (*cursor != NULL) {
        ss_prompt *prompt = *cursor;
        if (prompt->parent_request_id != parent_request_id) {
            cursor = &prompt->next;
            continue;
        }
        *cursor = prompt->next;
        client->prompt_count--;
        secretspec_resolver_buffer_free(prompt->params);
        ss_secure_clear(prompt, sizeof(*prompt));
        free(prompt);
    }
}

static bool string_equals(yyjson_val *value, const char *expected) {
    return yyjson_is_str(value) && yyjson_get_len(value) == strlen(expected) &&
           memcmp(yyjson_get_str(value), expected, yyjson_get_len(value)) == 0;
}

static bool ignorable_notification(yyjson_val *root) {
    static const char *const keys[] = {"jsonrpc", "method", "params"};
    yyjson_val *method = yyjson_obj_get(root, "method");
    size_t method_size = yyjson_is_str(method) ? yyjson_get_len(method) : 0;
    return ss_json_is_closed_object(root, keys, 3) &&
           yyjson_obj_size(root) == 3 &&
           string_equals(yyjson_obj_get(root, "jsonrpc"), "2.0") &&
           method_size > 0 && method_size <= 256 &&
           yyjson_is_obj(yyjson_obj_get(root, "params"));
}

static bool error_kind(
    yyjson_val *error,
    secretspec_resolver_status *status,
    const char **kind_out) {
    yyjson_val *code_value;
    yyjson_val *message;
    yyjson_val *data;
    yyjson_val *kind;
    yyjson_val *retryable;
    yyjson_val *retry_after;
    int64_t code;
    const char *kind_text;
    size_t kind_size;
    struct mapping { int64_t code; const char *kind; secretspec_resolver_status status; };
    static const struct mapping mappings[] = {
        {-32700, "parse_error", SECRETSPEC_RESOLVER_PROTOCOL},
        {-32600, "invalid_request", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32601, "method_not_found", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32602, "invalid_params", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32603, "internal", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32000, "unsupported_version", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32001, "capability_required", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32002, "deadline_exceeded", SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED},
        {-32003, "cancelled", SECRETSPEC_RESOLVER_CANCELLED},
        {-32004, "unavailable", SECRETSPEC_RESOLVER_UNAVAILABLE},
        {-32005, "permission_denied", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32006, "interaction_required", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32007, "conflict", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32008, "operation_failed", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32009, "message_too_large", SECRETSPEC_RESOLVER_REMOTE_ERROR},
        {-32010, "representation_mismatch", SECRETSPEC_RESOLVER_REMOTE_ERROR}
    };
    size_t index;
    bool code_is_defined = false;
    code_value = yyjson_obj_get(error, "code");
    message = yyjson_obj_get(error, "message");
    data = yyjson_obj_get(error, "data");
    if (!yyjson_is_sint(code_value) || !yyjson_is_str(message) ||
        yyjson_get_len(message) == 0 || yyjson_get_len(message) > 256 ||
        !yyjson_is_obj(data)) return false;
    code = yyjson_get_sint(code_value);
    kind = yyjson_obj_get(data, "kind");
    retryable = yyjson_obj_get(data, "retryable");
    retry_after = yyjson_obj_get(data, "retry_after_ms");
    if (!yyjson_is_str(kind) || !yyjson_is_bool(retryable)) return false;
    kind_text = yyjson_get_str(kind);
    kind_size = yyjson_get_len(kind);
    for (index = 0; index < sizeof(mappings) / sizeof(mappings[0]); index++) {
        if (mappings[index].code != code) continue;
        code_is_defined = true;
        if (strlen(mappings[index].kind) == kind_size &&
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
    /* A code this revision has never heard of, from a peer speaking a later
     * revision. Refusing it would kill the session, and the error set could
     * then never grow without a new protocol version, so it is reported as a
     * generic remote failure instead. A code this revision *does* define must
     * still arrive with the kind that belongs to it: that is a peer defect, not
     * a version difference. */
    if (!code_is_defined) {
        if (retry_after != NULL) {
            uint64_t retry_after_ms;
            if (!ss_json_u64(retry_after, &retry_after_ms) || retry_after_ms == 0) return false;
        }
        *status = SECRETSPEC_RESOLVER_REMOTE_ERROR;
        *kind_out = "unrecognized";
        return true;
    }
    return false;
}

static bool parse_response(
    const unsigned char *payload,
    size_t size,
    uint64_t *id,
    secretspec_resolver_status *status,
    secretspec_resolver_buffer *result,
    secretspec_resolver_buffer *error_buffer) {
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
        if (!ss_json_write_value(result_value, result)) goto done;
        *status = SECRETSPEC_RESOLVER_OK;
    } else {
        if (!error_kind(error_value, status, &kind)) goto done;
        ss_set_error(error_buffer, kind, "remote error");
    }
    valid = true;
done:
    yyjson_doc_free(document);
    if (!valid) {
        secretspec_resolver_buffer_free(*result);
        secretspec_resolver_buffer_free(*error_buffer);
        ss_buffer_reset(result);
        ss_buffer_reset(error_buffer);
    }
    return valid;
}

static void fail_all(
    secretspec_resolver_client *client,
    secretspec_resolver_status status,
    const char *message) {
    ss_request *request;
    ss_request *next;
    mutex_lock(&client->mutex);
    if (client->closed) {
        mutex_unlock(&client->mutex);
        return;
    }
    client->closed = true;
    client->ready = false;
    /* A prompt nobody will now answer must not outlive the session that owed
     * the endpoint a response for it. */
    prompts_clear(client);
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
                         status == SECRETSPEC_RESOLVER_PROTOCOL ? "protocol" : "unavailable",
                         message != NULL
                             ? message
                             : (status == SECRETSPEC_RESOLVER_PROTOCOL ? "protocol error"
                                                                  : "session closed"));
            condition_broadcast(&request->condition);
        }
        request_release(request);
        request = next;
    }
    condition_broadcast(&client->state_changed);
    mutex_unlock(&client->mutex);
    ss_process_interrupt_io(client->process);
}

/* Accept one inbound request as a prompt.
 *
 * Returns false for anything this session must not accept: a request at all
 * when no callback was advertised, a method other than the one that was, a
 * malformed envelope, or more outstanding prompts than the negotiated in-flight
 * bound allows. Each of those means the endpoint is not tracking the session
 * state this side is, which is a protocol violation rather than a prompt. */
static bool accept_prompt(secretspec_resolver_client *client, yyjson_val *root) {
    static const char *const keys[] = {"jsonrpc", "id", "method", "_meta", "params"};
    static const char *const meta_keys[] = {"deadline_unix_ms", "parent_request_id"};
    yyjson_val *method;
    yyjson_val *id_value;
    yyjson_val *meta;
    yyjson_val *deadline;
    yyjson_val *parent;
    yyjson_val *params;
    ss_prompt *prompt;
    uint64_t id;
    uint64_t deadline_unix_ms;
    if (!client->answer_prompts || !ss_json_is_closed_object(root, keys, 5)) return false;
    method = yyjson_obj_get(root, "method");
    id_value = yyjson_obj_get(root, "id");
    meta = yyjson_obj_get(root, "_meta");
    deadline = meta == NULL ? NULL : yyjson_obj_get(meta, "deadline_unix_ms");
    parent = meta == NULL ? NULL : yyjson_obj_get(meta, "parent_request_id");
    params = yyjson_obj_get(root, "params");
    if (!string_equals(yyjson_obj_get(root, "jsonrpc"), "2.0") ||
        !string_equals(method, "client.prompt") || !ss_json_is_closed_object(meta, meta_keys, 2) ||
        !ss_json_u64(id_value, &id) || id == 0 || id > SS_MAX_ID ||
        !ss_json_u64(deadline, &deadline_unix_ms) || !yyjson_is_uint(parent) || !yyjson_is_obj(params)) return false;

    prompt = (ss_prompt *)calloc(1, sizeof(*prompt));
    if (prompt == NULL) return false;
    if (!ss_json_write_value(params, &prompt->params)) {
        free(prompt);
        return false;
    }
    prompt->client = client;
    prompt->id = id;
    prompt->parent_request_id = yyjson_get_uint(parent);
    prompt->deadline_unix_ms = deadline_unix_ms;
    mutex_lock(&client->mutex);
    {
        ss_request *parent_request = find_request(client, prompt->parent_request_id);
        if (parent_request == NULL || !parent_request->running || parent_request->cancel_sent ||
            deadline_unix_ms > parent_request->deadline_unix_ms) {
            mutex_unlock(&client->mutex);
            secretspec_resolver_buffer_free(prompt->params);
            ss_secure_clear(prompt, sizeof(*prompt));
            free(prompt);
            return false;
        }
    }
    prompts_expire(client, ss_now_unix_ms());
    if (deadline_unix_ms <= ss_now_unix_ms()) {
        mutex_unlock(&client->mutex);
        secretspec_resolver_buffer_free(prompt->params);
        ss_secure_clear(prompt, sizeof(*prompt));
        free(prompt);
        return true;
    }
    if (client->closed || id <= client->last_callback_id ||
        client->prompt_count >= client->max_in_flight) {
        mutex_unlock(&client->mutex);
        secretspec_resolver_buffer_free(prompt->params);
        free(prompt);
        return false;
    }
    client->last_callback_id = id;
    prompt->next = client->prompts;
    client->prompts = prompt;
    client->prompt_count++;
    /* Wake every waiting call: a prompt blocks whichever one raised it, and the
     * caller cannot know which that was. */
    condition_broadcast(&client->state_changed);
    {
        ss_request *request;
        for (request = client->requests; request != NULL; request = request->next) {
            condition_broadcast(&request->condition);
        }
    }
    mutex_unlock(&client->mutex);
    return true;
}

static void prompts_clear(secretspec_resolver_client *client) {
    ss_prompt *prompt = client->prompts;
    client->prompts = NULL;
    client->prompt_count = 0;
    while (prompt != NULL) {
        ss_prompt *next = prompt->next;
        secretspec_resolver_buffer_free(prompt->params);
        ss_secure_clear(prompt, sizeof(*prompt));
        free(prompt);
        prompt = next;
    }
}

static void outbound_free(ss_outbound *outbound) {
    if (outbound == NULL) return;
    secretspec_resolver_buffer_free(outbound->payload);
    ss_secure_clear(outbound, sizeof(*outbound));
    free(outbound);
}

static SS_THREAD_RETURN writer_main(void *context) {
    secretspec_resolver_client *client = (secretspec_resolver_client *)context;
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
            fail_all(client, SECRETSPEC_RESOLVER_IO, NULL);
            break;
        }
        outbound_free(outbound);
    }
    SS_THREAD_END;
}

static SS_THREAD_RETURN reader_main(void *context) {
    secretspec_resolver_client *client = (secretspec_resolver_client *)context;
    for (;;) {
        size_t limit;
        secretspec_resolver_buffer payload = {NULL, 0};
        secretspec_resolver_buffer result = {NULL, 0};
        secretspec_resolver_buffer error = {NULL, 0};
        secretspec_resolver_status frame_status;
        secretspec_resolver_status response_status;
        bool clean_eof = false;
        bool non_protocol_text = false;
        uint64_t id = 0;
        ss_request *request;
        bool release_list_reference = false;

        mutex_lock(&client->mutex);
        if (client->closed) { mutex_unlock(&client->mutex); break; }
        limit = client->max_frame_bytes;
        mutex_unlock(&client->mutex);
        frame_status =
            ss_frame_read(client->process, &client->frame_reader, limit, &payload,
                          &clean_eof, &non_protocol_text);
        if (frame_status != SECRETSPEC_RESOLVER_OK || clean_eof) {
            fail_all(client,
                     clean_eof ? SECRETSPEC_RESOLVER_UNAVAILABLE : frame_status,
                     non_protocol_text
                         ? "peer wrote non-protocol text to the stream reserved for frames"
                         : NULL);
            break;
        }
        if (!parse_response(payload.data, payload.size, &id, &response_status, &result, &error)) {
            /* Not a response. The one other thing it may be is a prompt this
             * session advertised it could answer; anything else is the protocol
             * violation an inbound envelope has always been. */
            yyjson_doc *document = NULL;
            bool prompted = false;
            bool notification = false;
            if (ss_json_validate(payload.data, payload.size, &document)) {
                yyjson_val *root = yyjson_doc_get_root(document);
                prompted = accept_prompt(client, root);
                /* Notifications have no response path. Ignore structurally
                 * valid unknown methods and malformed cancellation params so
                 * a cancellation race cannot kill a useful resolver session.
                 * The envelope itself stays strict. */
                notification = ignorable_notification(root);
                yyjson_doc_free(document);
            }
            secretspec_resolver_buffer_free(payload);
            if (prompted || notification) continue;
            fail_all(client, SECRETSPEC_RESOLVER_PROTOCOL, NULL);
            break;
        }
        secretspec_resolver_buffer_free(payload);

        mutex_lock(&client->mutex);
        request = find_request(client, id);
        if (request == NULL) {
            mutex_unlock(&client->mutex);
            secretspec_resolver_buffer_free(result);
            secretspec_resolver_buffer_free(error);
            fail_all(client, SECRETSPEC_RESOLVER_PROTOCOL, NULL);
            break;
        }
        if (request->abandoned) {
            prompts_cancel_parent(client, id);
            remove_request(client, request);
            release_list_reference = true;
        } else if (request->running) {
            request->running = false;
            prompts_cancel_parent(client, id);
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
            secretspec_resolver_buffer_free(result);
            secretspec_resolver_buffer_free(error);
            fail_all(client, SECRETSPEC_RESOLVER_PROTOCOL, NULL);
            break;
        }
        if (id == 1) {
            while (client->initializing && !client->closed) {
                (void)condition_wait_until(&client->state_changed, &client->mutex,
                                           ss_now_unix_ms() + UINT64_C(1000));
            }
        }
        mutex_unlock(&client->mutex);
        secretspec_resolver_buffer_free(result);
        secretspec_resolver_buffer_free(error);
        if (release_list_reference) request_release(request);
    }
    SS_THREAD_END;
}

static SS_THREAD_RETURN stderr_main(void *context) {
    secretspec_resolver_client *client = (secretspec_resolver_client *)context;
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
    secretspec_resolver_client *client = (secretspec_resolver_client *)context;
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
                prompts_cancel_parent(client, request->id);
                request->status = SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED;
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

/* Re-emit the caller's initialization offer with the prompt capability added.
 *
 * The offer is a small validated object, so it is rewritten as text and parsed
 * back rather than threading a mutable document through the request path. */
static bool offer_with_prompt_capability(yyjson_val *offer, yyjson_doc **out) {
    yyjson_mut_doc *document = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root;
    yyjson_mut_val *capabilities;
    char *json = NULL;
    size_t size = 0;
    bool built = false;
    *out = NULL;
    if (document == NULL) return false;
    root = yyjson_val_mut_copy(document, offer);
    capabilities = yyjson_mut_arr(document);
    if (root != NULL && capabilities != NULL &&
        yyjson_mut_arr_add_str(document, capabilities, "client.prompt") &&
        yyjson_mut_obj_add_val(document, root, "client_methods", capabilities)) {
        yyjson_mut_doc_set_root(document, root);
        json = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &size);
    }
    yyjson_mut_doc_free(document);
    if (json == NULL) return false;
    built = ss_json_validate((const unsigned char *)json, size, out);
    free(json);
    return built;
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
    /* Resolver only. The provider protocol's client is always the SecretSpec
     * resolver, which is Rust, so a C client for it would serve nobody. */
    if (!string_equals(protocol, "secretspec.resolver") ||
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

static void capabilities_clear(secretspec_resolver_client *client) {
    size_t index;
    for (index = 0; index < client->capability_count; index++) free(client->capabilities[index]);
    free(client->capabilities);
    client->capabilities = NULL;
    client->capability_count = 0;
}

static bool validate_initialize_result(
    secretspec_resolver_client *client,
    yyjson_val *offer,
    const unsigned char *json,
    size_t json_size) {
    static const char *const keys[] = {
        "protocol", "version", "server", "methods", "capabilities", "limits", "application"
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
    capabilities = yyjson_obj_get(result, "methods");
    offered_versions = yyjson_obj_get(offer, "versions");
    if (!ss_json_is_closed_object(result, keys, 7) ||
        !yyjson_equals_strn(protocol, yyjson_get_str(yyjson_obj_get(offer, "protocol")),
                            yyjson_get_len(yyjson_obj_get(offer, "protocol"))) ||
        !ss_json_u64(version, &selected_version) ||
        !versions_contains(offered_versions, selected_version) ||
        !product_valid(yyjson_obj_get(result, "server")) ||
        !string_array_valid(capabilities, true) || !yyjson_is_obj(yyjson_obj_get(result, "capabilities")) ||
        !limits_valid(yyjson_obj_get(result, "limits"), &frame, &in_flight) ||
        !limits_valid(yyjson_obj_get(offer, "limits"), &offered_frame, &offered_in_flight) ||
        frame > offered_frame || in_flight > offered_in_flight ||
        !yyjson_is_obj(yyjson_obj_get(result, "application"))) goto done;
    if (!array_has_text(capabilities, "resolver.get") ||
        !array_has_text(capabilities, "resolver.release")) goto done;
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

static bool method_advertised(secretspec_resolver_client *client, const char *method, size_t size) {
    size_t index;
    for (index = 0; index < client->capability_count; index++) {
        if (strlen(client->capabilities[index]) == size &&
            memcmp(client->capabilities[index], method, size) == 0) return true;
    }
    return false;
}

static secretspec_resolver_status wait_call(
    secretspec_resolver_call *call,
    secretspec_resolver_buffer *result,
    secretspec_resolver_buffer *error) {
    secretspec_resolver_client *client = call->client;
    ss_request *request = call->request;
    secretspec_resolver_status status;
    bool timed_out = false;
    mutex_lock(&client->mutex);
    if (request->waiter) {
        mutex_unlock(&client->mutex);
        ss_set_error(error, "invalid_argument", "call already has a waiter");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    request->waiter = true;
    while (request->running) {
        /* The endpoint is waiting on this client before it can finish any call,
         * so hand the prompt back rather than blocking until the deadline. The
         * waiter slot is released first: the caller answers and then waits
         * again on the same call. */
        prompts_expire(client, ss_now_unix_ms());
        if (client->prompts != NULL) {
            request->waiter = false;
            mutex_unlock(&client->mutex);
            return SECRETSPEC_RESOLVER_PROMPT_PENDING;
        }
        if (request->deadline_unix_ms <= ss_now_unix_ms() ||
            !condition_wait_until(&request->condition, &client->mutex, request->deadline_unix_ms)) {
            if (request->running) {
                request->running = false;
                request->abandoned = true;
                prompts_cancel_parent(client, request->id);
                request->status = SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED;
                client->in_flight--;
                ss_set_error(&request->error, "deadline_exceeded", "deadline exceeded");
                request->cancel_sent = true;
                timed_out = true;
            }
            break;
        }
    }
    status = request->status;
    if (status == SECRETSPEC_RESOLVER_OK && result != NULL) {
        *result = request->result;
        ss_buffer_reset(&request->result);
    } else if (status != SECRETSPEC_RESOLVER_OK && error != NULL) {
        *error = request->error;
        ss_buffer_reset(&request->error);
    }
    mutex_unlock(&client->mutex);
    if (timed_out) (void)send_cancel(client, request->id);
    return status;
}

static void client_destroy(secretspec_resolver_client *client) {
    if (client == NULL) return;
    capabilities_clear(client);
    condition_destroy(&client->write_ready);
    condition_destroy(&client->state_changed);
    mutex_destroy(&client->write_mutex);
    mutex_destroy(&client->mutex);
    ss_secure_clear(client, sizeof(*client));
    free(client);
}

static void client_release(secretspec_resolver_client *client) {
    if (atomic_fetch_sub(&client->references, 1) == 1) client_destroy(client);
}

static void cleanup_process(secretspec_resolver_client *client, uint64_t deadline) {
    ss_outbound *outbound;
    uint64_t cap = ss_now_unix_ms() + UINT64_C(5000);
    if (deadline > cap) deadline = cap;
    mutex_lock(&client->write_mutex);
    client->writer_stopping = true;
    condition_broadcast(&client->write_ready);
    mutex_unlock(&client->write_mutex);
    fail_all(client, SECRETSPEC_RESOLVER_UNAVAILABLE, NULL);
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

static bool options_valid(const secretspec_resolver_options *options) {
    size_t minimum_size = offsetof(secretspec_resolver_options, max_stderr_bytes);
    size_t index;
    if (options == NULL || options->struct_size < minimum_size ||
        options->struct_size > sizeof(*options) ||
        options->abi_version != SECRETSPEC_RESOLVER_ABI_VERSION ||
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

secretspec_resolver_status secretspec_resolver_client_open(
    const secretspec_resolver_options *options,
    uint64_t deadline_unix_ms,
    secretspec_resolver_client **client_out,
    secretspec_resolver_buffer *server_info,
    secretspec_resolver_buffer *error) {
    ss_launch launch;
    secretspec_resolver_client *client = NULL;
    yyjson_doc *initialize_document = NULL;
    yyjson_val *initialize_root;
    secretspec_resolver_call *initialize_call = NULL;
    secretspec_resolver_buffer initialize_result = {NULL, 0};
    secretspec_resolver_status status;

    if (client_out != NULL) *client_out = NULL;
    ss_buffer_reset(server_info);
    ss_buffer_reset(error);
    if (client_out == NULL || server_info == NULL || error == NULL || !options_valid(options)) {
        ss_set_error(error, "invalid_argument", "invalid client options");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    /* A deadline that has already passed is a timing outcome, not a malformed
     * argument, and the Rust client reports it as one. Reporting it here as
     * invalid_argument would put a cliff at the current instant: the same call
     * a millisecond earlier returns a different kind. */
    if (deadline_unix_ms <= ss_now_unix_ms()) {
        ss_set_error(error, "deadline_exceeded", "request deadline already elapsed");
        return SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED;
    }
    if (!ss_json_validate(options->initialize_params_json.data,
                          options->initialize_params_json.size,
                          &initialize_document)) {
        ss_set_error(error, "invalid_argument", "invalid initialization JSON");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    initialize_root = yyjson_doc_get_root(initialize_document);
    if (!initialize_offer_valid(initialize_root)) {
        yyjson_doc_free(initialize_document);
        ss_set_error(error, "invalid_argument", "invalid initialization params");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    /* The library owns what it advertises, so the caller cannot claim a
     * capability this build could not answer. `initialize_offer_valid` already
     * rejects a caller-supplied `client_methods`, which is what makes
     * adding it here unambiguous. */
    if ((options->flags & SECRETSPEC_RESOLVER_ANSWER_PROMPTS) != 0) {
        yyjson_doc *advertised = NULL;
        if (!offer_with_prompt_capability(initialize_root, &advertised)) {
            yyjson_doc_free(initialize_document);
            ss_set_error(error, "unavailable", "allocation failed");
            return SECRETSPEC_RESOLVER_UNAVAILABLE;
        }
        yyjson_doc_free(initialize_document);
        initialize_document = advertised;
        initialize_root = yyjson_doc_get_root(initialize_document);
    }
    status = launch_from_options(options, &launch);
    if (status != SECRETSPEC_RESOLVER_OK) {
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, status == SECRETSPEC_RESOLVER_INVALID_ARGUMENT ? "invalid_argument" : "unavailable",
                     status == SECRETSPEC_RESOLVER_INVALID_ARGUMENT ? "invalid launch options" : "allocation failed");
        return status;
    }
    client = (secretspec_resolver_client *)calloc(1, sizeof(*client));
    if (client == NULL) {
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    if (!mutex_init(&client->mutex)) {
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    if (!mutex_init(&client->write_mutex)) {
        mutex_destroy(&client->mutex);
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    if (!condition_init(&client->state_changed)) {
        mutex_destroy(&client->write_mutex);
        mutex_destroy(&client->mutex);
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    if (!condition_init(&client->write_ready)) {
        condition_destroy(&client->state_changed);
        mutex_destroy(&client->write_mutex);
        mutex_destroy(&client->mutex);
        free(client);
        yyjson_doc_free(initialize_document);
        launch_free(&launch);
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    atomic_init(&client->references, 1);
    client->initializing = true;
    client->max_frame_bytes = SS_ABSOLUTE_MAX_FRAME;
    client->max_in_flight = 1;
    client->next_id = 1;
    client->answer_prompts = (options->flags & SECRETSPEC_RESOLVER_ANSWER_PROMPTS) != 0;
    client->max_stderr_bytes = options->struct_size >= sizeof(*options) ? options->max_stderr_bytes : 65536;
    status = ss_process_spawn(&launch, &client->process);
    launch_free(&launch);
    if (status != SECRETSPEC_RESOLVER_OK) {
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
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    client->writer_started = true;
    if (!thread_start(&client->reader_thread, reader_main, client)) {
        yyjson_doc_free(initialize_document);
        cleanup_process(client, ss_now_unix_ms());
        client_destroy(client);
        ss_set_error(error, "unavailable", "reader worker failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    client->reader_started = true;
    if (!thread_start(&client->stderr_thread, stderr_main, client)) {
        yyjson_doc_free(initialize_document);
        cleanup_process(client, ss_now_unix_ms());
        client_destroy(client);
        ss_set_error(error, "unavailable", "stderr worker failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    client->stderr_started = true;
    if (!thread_start(&client->deadline_thread, deadline_main, client)) {
        yyjson_doc_free(initialize_document);
        cleanup_process(client, ss_now_unix_ms());
        client_destroy(client);
        ss_set_error(error, "unavailable", "deadline worker failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    client->deadline_started = true;

    status = start_request(client, "rpc.initialize", strlen("rpc.initialize"),
                           initialize_root, deadline_unix_ms, false, &initialize_call);
    if (status == SECRETSPEC_RESOLVER_OK) {
        status = wait_call(initialize_call, &initialize_result, error);
    }
    if (initialize_call != NULL) secretspec_resolver_call_free(initialize_call);
    if (status == SECRETSPEC_RESOLVER_OK &&
        !validate_initialize_result(client, initialize_root,
                                    initialize_result.data, initialize_result.size)) {
        status = SECRETSPEC_RESOLVER_PROTOCOL;
        ss_set_error(error, "protocol", "invalid initialization response");
    }
    yyjson_doc_free(initialize_document);
    if (status != SECRETSPEC_RESOLVER_OK) {
        secretspec_resolver_buffer_free(initialize_result);
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
    return SECRETSPEC_RESOLVER_OK;
}

secretspec_resolver_status secretspec_resolver_call_start(
    secretspec_resolver_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_resolver_call **call,
    secretspec_resolver_buffer *error) {
    yyjson_doc *document = NULL;
    yyjson_val *root;
    secretspec_resolver_status status;
    ss_buffer_reset(error);
    if (call != NULL) *call = NULL;
    if (client == NULL || call == NULL || error == NULL || method == NULL || method_size == 0 ||
        method_size > 256 || params_json == NULL || params_size == 0 ||
        memchr(method, 0, method_size) != NULL || !valid_utf8(method, method_size)) {
        ss_set_error(error, "invalid_argument", "invalid call arguments");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    /* See the note in the open path: an elapsed deadline is a timing outcome. */
    if (deadline_unix_ms <= ss_now_unix_ms()) {
        ss_set_error(error, "deadline_exceeded", "request deadline already elapsed");
        return SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED;
    }
    if (!ss_json_validate(params_json, params_size, &document)) {
        ss_set_error(error, "invalid_argument", "invalid call arguments");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    root = yyjson_doc_get_root(document);
    mutex_lock(&client->mutex);
    if (!method_advertised(client, (const char *)method, method_size)) {
        mutex_unlock(&client->mutex);
        yyjson_doc_free(document);
        ss_set_error(error, "protocol", "method was not advertised");
        return SECRETSPEC_RESOLVER_PROTOCOL;
    }
    mutex_unlock(&client->mutex);
    status = start_request(client, (const char *)method, method_size, root,
                           deadline_unix_ms, true, call);
    yyjson_doc_free(document);
    if (status != SECRETSPEC_RESOLVER_OK) {
        if (*call != NULL) {
            secretspec_resolver_call_free(*call);
            *call = NULL;
        }
        ss_set_error(error, status == SECRETSPEC_RESOLVER_UNAVAILABLE ? "unavailable" : "io",
                     status == SECRETSPEC_RESOLVER_UNAVAILABLE ? "session capacity unavailable" : "request write failed");
    }
    return status;
}

secretspec_resolver_status secretspec_resolver_client_call(
    secretspec_resolver_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_resolver_buffer *result,
    secretspec_resolver_buffer *error) {
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_status status;
    if (result == NULL || error == NULL) {
        if (error != NULL) ss_set_error(error, "invalid_argument", "invalid call outputs");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    ss_buffer_reset(result);
    ss_buffer_reset(error);
    /* This form returns the result and drops the handle, so it has no way to
     * resume a call that stopped for a prompt. A prompt-answering session must
     * drive calls with call_start and call_wait, which can. */
    if (client != NULL && client->answer_prompts) {
        ss_set_error(error, "invalid_argument",
                     "a prompt-answering session must use call_start and call_wait");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    status = secretspec_resolver_call_start(client, method, method_size, params_json, params_size,
                                       deadline_unix_ms, &call, error);
    if (status == SECRETSPEC_RESOLVER_OK) status = secretspec_resolver_call_wait(call, result, error);
    secretspec_resolver_call_free(call);
    return status;
}

secretspec_resolver_status secretspec_resolver_call_wait(
    secretspec_resolver_call *call,
    secretspec_resolver_buffer *result,
    secretspec_resolver_buffer *error) {
    ss_buffer_reset(result);
    ss_buffer_reset(error);
    if (call == NULL || result == NULL || error == NULL) {
        ss_set_error(error, "invalid_argument", "invalid call handle");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    return wait_call(call, result, error);
}

void secretspec_resolver_call_cancel(secretspec_resolver_call *call) {
    bool send = false;
    if (call == NULL) return;
    mutex_lock(&call->client->mutex);
    if (call->request->running && !call->request->cancel_sent) {
        call->request->cancel_sent = true;
        prompts_cancel_parent(call->client, call->request->id);
        send = true;
    }
    mutex_unlock(&call->client->mutex);
    if (send) (void)send_cancel(call->client, call->request->id);
}

void secretspec_resolver_call_free(secretspec_resolver_call *call) {
    secretspec_resolver_client *client;
    if (call == NULL) return;
    client = call->client;
    secretspec_resolver_call_cancel(call);
    request_release(call->request);
    ss_secure_clear(call, sizeof(*call));
    free(call);
    client_release(client);
}

secretspec_resolver_status secretspec_resolver_prompt_take(
    secretspec_resolver_client *client,
    secretspec_resolver_prompt **prompt,
    secretspec_resolver_buffer *error) {
    ss_prompt *taken;
    if (client == NULL || prompt == NULL || error == NULL) {
        ss_set_error(error, "invalid_argument", "invalid prompt arguments");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    *prompt = NULL;
    ss_buffer_reset(error);
    mutex_lock(&client->mutex);
    if (client->closed) {
        mutex_unlock(&client->mutex);
        ss_set_error(error, "unavailable", "session closed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    prompts_expire(client, ss_now_unix_ms());
    taken = client->prompts;
    if (taken != NULL) {
        client->prompts = taken->next;
        client->prompt_count--;
        taken->next = NULL;
        /* The prompt holds the session open while the caller decides: the
         * answer still has to be written on this transport. */
        (void)atomic_fetch_add(&client->references, 1);
    }
    mutex_unlock(&client->mutex);
    *prompt = (secretspec_resolver_prompt *)taken;
    return SECRETSPEC_RESOLVER_OK;
}

secretspec_resolver_slice secretspec_resolver_prompt_params(const secretspec_resolver_prompt *prompt) {
    secretspec_resolver_slice slice = {NULL, 0};
    const ss_prompt *inner = (const ss_prompt *)prompt;
    if (inner == NULL) return slice;
    slice.data = inner->params.data;
    slice.size = inner->params.size;
    return slice;
}

/* Write one terminal response for a prompt. `value` is the answer, or NULL to
 * decline with interaction_required. Marks the prompt answered first so a
 * second call cannot put two responses on the wire for one request. */
static secretspec_resolver_status answer_prompt(
    ss_prompt *prompt,
    const unsigned char *value,
    size_t value_size,
    secretspec_resolver_buffer *error) {
    secretspec_resolver_client *client;
    yyjson_mut_doc *document;
    yyjson_mut_val *root;
    yyjson_mut_val *body;
    char *json = NULL;
    size_t size = 0;
    bool written = false;
    if (prompt == NULL || error == NULL) {
        ss_set_error(error, "invalid_argument", "invalid prompt arguments");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    ss_buffer_reset(error);
    client = prompt->client;
    mutex_lock(&client->mutex);
    if (prompt->answered) {
        mutex_unlock(&client->mutex);
        ss_set_error(error, "invalid_argument", "prompt was already answered");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    prompt->answered = true;
    if (client->closed) {
        mutex_unlock(&client->mutex);
        ss_set_error(error, "unavailable", "session closed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    {
        ss_request *parent = find_request(client, prompt->parent_request_id);
        if (parent == NULL || !parent->running || parent->cancel_sent ||
            prompt->deadline_unix_ms > parent->deadline_unix_ms) {
            mutex_unlock(&client->mutex);
            ss_set_error(error, "cancelled", "prompt parent is no longer active");
            return SECRETSPEC_RESOLVER_CANCELLED;
        }
    }
    if (prompt->deadline_unix_ms <= ss_now_unix_ms()) {
        mutex_unlock(&client->mutex);
        ss_set_error(error, "deadline_exceeded", "prompt deadline exceeded");
        return SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED;
    }
    mutex_unlock(&client->mutex);

    document = yyjson_mut_doc_new(NULL);
    if (document == NULL) {
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    root = yyjson_mut_obj(document);
    body = yyjson_mut_obj(document);
    if (root != NULL && body != NULL &&
        yyjson_mut_obj_add_str(document, root, "jsonrpc", "2.0") &&
        yyjson_mut_obj_add_uint(document, root, "id", prompt->id)) {
        if (value != NULL) {
            written = yyjson_mut_obj_add_strncpy(document, body, "value",
                                                 (const char *)value, value_size) &&
                      yyjson_mut_obj_add_val(document, root, "result", body);
        } else {
            yyjson_mut_val *data = yyjson_mut_obj(document);
            written = data != NULL &&
                      yyjson_mut_obj_add_str(document, body, "kind", "interaction_required") &&
                      yyjson_mut_obj_add_bool(document, body, "retryable", false) &&
                      yyjson_mut_obj_add_int(document, data, "code", -32006) &&
                      yyjson_mut_obj_add_str(document, data, "message", "interaction required") &&
                      yyjson_mut_obj_add_val(document, data, "data", body) &&
                      yyjson_mut_obj_add_val(document, root, "error", data);
        }
    }
    if (written) {
        yyjson_mut_doc_set_root(document, root);
        json = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &size);
    }
    yyjson_mut_doc_free(document);
    if (json == NULL) {
        ss_set_error(error, "unavailable", "allocation failed");
        return SECRETSPEC_RESOLVER_UNAVAILABLE;
    }
    /* Recheck after serialization and queue under the same lock. The reader
     * cannot make the parent terminal between this check and the enqueue. */
    mutex_lock(&client->mutex);
    {
        ss_request *parent = find_request(client, prompt->parent_request_id);
        if (parent == NULL || !parent->running || parent->cancel_sent ||
            prompt->deadline_unix_ms > parent->deadline_unix_ms) {
            mutex_unlock(&client->mutex);
            ss_secure_clear(json, size);
            free(json);
            ss_set_error(error, "cancelled", "prompt parent is no longer active");
            return SECRETSPEC_RESOLVER_CANCELLED;
        }
    }
    written = write_payload_locked(client, (const unsigned char *)json, size);
    mutex_unlock(&client->mutex);
    /* The answer is a secret, so this copy goes before the pointer does. */
    ss_secure_clear(json, size);
    free(json);
    if (!written) {
        ss_set_error(error, "io", "failed to write the prompt answer");
        return SECRETSPEC_RESOLVER_IO;
    }
    return SECRETSPEC_RESOLVER_OK;
}

secretspec_resolver_status secretspec_resolver_prompt_answer(
    secretspec_resolver_prompt *prompt,
    const unsigned char *value,
    size_t value_size,
    secretspec_resolver_buffer *error) {
    /* An empty answer means different things to different stores, exactly as it
     * does for resolver.set, so it never travels. A person who wants to refuse
     * declines instead. */
    if (value == NULL || value_size == 0 || value_size > SS_ABSOLUTE_MAX_FRAME ||
        !valid_utf8(value, value_size)) {
        ss_set_error(error, "invalid_argument", "prompt answer must be nonempty valid UTF-8");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    return answer_prompt((ss_prompt *)prompt, value, value_size, error);
}

secretspec_resolver_status secretspec_resolver_prompt_decline(
    secretspec_resolver_prompt *prompt,
    secretspec_resolver_buffer *error) {
    return answer_prompt((ss_prompt *)prompt, NULL, 0, error);
}

void secretspec_resolver_prompt_free(secretspec_resolver_prompt *prompt) {
    ss_prompt *inner = (ss_prompt *)prompt;
    secretspec_resolver_client *client;
    if (inner == NULL) return;
    client = inner->client;
    /* Freeing without answering would leave the endpoint waiting out its
     * deadline, so decline on the caller's behalf rather than going silent. */
    if (!inner->answered) {
        secretspec_resolver_buffer ignored = {NULL, 0};
        (void)answer_prompt(inner, NULL, 0, &ignored);
        secretspec_resolver_buffer_free(ignored);
    }
    secretspec_resolver_buffer_free(inner->params);
    ss_secure_clear(inner, sizeof(*inner));
    free(inner);
    client_release(client);
}

secretspec_resolver_status secretspec_resolver_client_close(
    secretspec_resolver_client *client,
    uint64_t deadline_unix_ms,
    secretspec_resolver_buffer *error) {
    static const unsigned char params[] = "{}";
    yyjson_doc *document = NULL;
    secretspec_resolver_call *shutdown_call = NULL;
    secretspec_resolver_buffer result = {NULL, 0};
    secretspec_resolver_status status = SECRETSPEC_RESOLVER_OK;
    ss_buffer_reset(error);
    if (client == NULL || error == NULL || deadline_unix_ms <= ss_now_unix_ms()) {
        ss_set_error(error, "invalid_argument", "invalid close arguments");
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    mutex_lock(&client->mutex);
    if (client->closing) {
        mutex_unlock(&client->mutex);
        return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    }
    if (client->closed) {
        mutex_unlock(&client->mutex);
        cleanup_process(client, deadline_unix_ms);
        return SECRETSPEC_RESOLVER_OK;
    }
    client->closing = true;
    mutex_unlock(&client->mutex);
    if (!ss_json_validate(params, sizeof(params) - 1, &document)) {
        status = SECRETSPEC_RESOLVER_PROTOCOL;
    } else {
        status = start_request(client, "rpc.shutdown", strlen("rpc.shutdown"),
                               yyjson_doc_get_root(document), deadline_unix_ms, false,
                               &shutdown_call);
        if (status == SECRETSPEC_RESOLVER_OK) status = wait_call(shutdown_call, &result, error);
    }
    yyjson_doc_free(document);
    if (shutdown_call != NULL) secretspec_resolver_call_free(shutdown_call);
    if (status == SECRETSPEC_RESOLVER_OK) {
        yyjson_doc *result_document = NULL;
        if (!ss_json_validate(result.data, result.size, &result_document) ||
            !yyjson_is_obj(yyjson_doc_get_root(result_document)) ||
            yyjson_obj_size(yyjson_doc_get_root(result_document)) != 0) {
            status = SECRETSPEC_RESOLVER_PROTOCOL;
            ss_set_error(error, "protocol", "invalid shutdown response");
        }
        yyjson_doc_free(result_document);
    }
    secretspec_resolver_buffer_free(result);
    cleanup_process(client, deadline_unix_ms);
    return status;
}

void secretspec_resolver_client_free(secretspec_resolver_client *client) {
    secretspec_resolver_buffer error = {NULL, 0};
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
            (void)secretspec_resolver_client_close(client, ss_now_unix_ms() + UINT64_C(5000), &error);
            secretspec_resolver_buffer_free(error);
        } else {
            cleanup_process(client, ss_now_unix_ms() + UINT64_C(5000));
        }
    }
    client_release(client);
}

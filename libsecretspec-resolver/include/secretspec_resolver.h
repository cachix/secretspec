#ifndef SECRETSPEC_RESOLVER_H
#define SECRETSPEC_RESOLVER_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(SECRETSPEC_RESOLVER_SHARED)
#  if defined(SECRETSPEC_RESOLVER_BUILDING)
#    define SECRETSPEC_RESOLVER_API __declspec(dllexport)
#  else
#    define SECRETSPEC_RESOLVER_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define SECRETSPEC_RESOLVER_API __attribute__((visibility("default")))
#else
#  define SECRETSPEC_RESOLVER_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SECRETSPEC_RESOLVER_ABI_VERSION ((1u << 16) | 0u)

typedef struct secretspec_resolver_client secretspec_resolver_client;
typedef struct secretspec_resolver_call secretspec_resolver_call;
typedef struct secretspec_resolver_prompt secretspec_resolver_prompt;

typedef struct {
    const unsigned char *data;
    size_t size;
} secretspec_resolver_slice;

enum {
    SECRETSPEC_RESOLVER_DISCOVER_EXECUTABLE = 1u << 0,
    SECRETSPEC_RESOLVER_INHERIT_ENVIRONMENT = 1u << 1,
    /* Advertise that this client can obtain a secret value from a person, so
     * the endpoint may ask it to (0.20+). The library adds the capability to
     * the initialization it sends; do not put client_methods in
     * initialize_params_json yourself.
     *
     * A session with this flag answers prompts through
     * secretspec_resolver_prompt_take and secretspec_resolver_prompt_answer, and its
     * calls must be driven with secretspec_resolver_call_start and
     * secretspec_resolver_call_wait rather than secretspec_resolver_client_call, which
     * has no handle to resume after a prompt. */
    SECRETSPEC_RESOLVER_ANSWER_PROMPTS = 1u << 2
};

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t flags;
    uint32_t reserved;
    secretspec_resolver_slice executable;
    const secretspec_resolver_slice *arguments;
    size_t argument_count;
    const secretspec_resolver_slice *environment;
    size_t environment_count;
    secretspec_resolver_slice initialize_params_json;
    size_t max_stderr_bytes;
} secretspec_resolver_options;

typedef enum {
    SECRETSPEC_RESOLVER_OK = 0,
    SECRETSPEC_RESOLVER_INVALID_ARGUMENT = 1,
    SECRETSPEC_RESOLVER_UNAVAILABLE = 2,
    SECRETSPEC_RESOLVER_IO = 3,
    SECRETSPEC_RESOLVER_PROTOCOL = 4,
    SECRETSPEC_RESOLVER_REMOTE_ERROR = 5,
    SECRETSPEC_RESOLVER_CANCELLED = 6,
    SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED = 7,
    /* A call cannot finish until a prompt is answered (0.20+). Take it with
     * secretspec_resolver_prompt_take, answer or decline it, then wait again. Only
     * a session opened with SECRETSPEC_RESOLVER_ANSWER_PROMPTS can see this. */
    SECRETSPEC_RESOLVER_PROMPT_PENDING = 8
} secretspec_resolver_status;

typedef struct {
    unsigned char *data;
    size_t size;
} secretspec_resolver_buffer;

SECRETSPEC_RESOLVER_API uint32_t secretspec_resolver_abi_version(void);

SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_client_open(
    const secretspec_resolver_options *options,
    uint64_t deadline_unix_ms,
    secretspec_resolver_client **client,
    secretspec_resolver_buffer *server_info,
    secretspec_resolver_buffer *error);

SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_call_start(
    secretspec_resolver_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_resolver_call **call,
    secretspec_resolver_buffer *error);

/* Convenience form for callers that do not need cancellation or multiplexing. */
SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_client_call(
    secretspec_resolver_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_resolver_buffer *result,
    secretspec_resolver_buffer *error);

SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_call_wait(
    secretspec_resolver_call *call,
    secretspec_resolver_buffer *result,
    secretspec_resolver_buffer *error);

SECRETSPEC_RESOLVER_API void secretspec_resolver_call_cancel(secretspec_resolver_call *call);
SECRETSPEC_RESOLVER_API void secretspec_resolver_call_free(secretspec_resolver_call *call);

/* Prompts (0.20+).
 *
 * The endpoint asks this client for a value only when the session advertised
 * SECRETSPEC_RESOLVER_ANSWER_PROMPTS. There is deliberately no callback: a binding
 * for another language must not have to hand a C function pointer to a foreign
 * runtime, so the answer is driven by the caller instead.
 *
 * The loop is:
 *
 *   status = secretspec_resolver_call_wait(call, &result, &error);
 *   while (status == SECRETSPEC_RESOLVER_PROMPT_PENDING) {
 *       secretspec_resolver_prompt *prompt = NULL;
 *       if (secretspec_resolver_prompt_take(client, &prompt, &error)) break;
 *       ... read a value from the person, using secretspec_resolver_prompt_params ...
 *       secretspec_resolver_prompt_answer(prompt, value, value_size, &error);
 *       secretspec_resolver_prompt_free(prompt);
 *       status = secretspec_resolver_call_wait(call, &result, &error);
 *   }
 *
 * A prompt belongs to the session, not to one call, so any waiting call may be
 * the one that surfaces it. Every taken prompt must be answered or declined:
 * one left unanswered blocks the endpoint until its deadline elapses. */

/* Take the prompt the endpoint is waiting on. Sets *prompt to NULL and returns
 * OK when none is pending. */
SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_prompt_take(
    secretspec_resolver_client *client,
    secretspec_resolver_prompt **prompt,
    secretspec_resolver_buffer *error);

/* The prompt's parameters as JSON: the declared name, the profile, and the
 * credential-free provider URI the answer will be stored at, if any. Borrowed
 * from the prompt and valid until it is freed. */
SECRETSPEC_RESOLVER_API secretspec_resolver_slice secretspec_resolver_prompt_params(
    const secretspec_resolver_prompt *prompt);

/* Answer with the value a person supplied. It is a secret: the library clears
 * its own copy after writing, and the caller should clear the buffer it owns.
 * An empty value is refused; decline instead. */
SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_prompt_answer(
    secretspec_resolver_prompt *prompt,
    const unsigned char *value,
    size_t value_size,
    secretspec_resolver_buffer *error);

/* Refuse the prompt. The resolution that raised it fails as
 * interaction_required rather than waiting out its deadline. */
SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_prompt_decline(
    secretspec_resolver_prompt *prompt,
    secretspec_resolver_buffer *error);

SECRETSPEC_RESOLVER_API void secretspec_resolver_prompt_free(secretspec_resolver_prompt *prompt);

SECRETSPEC_RESOLVER_API secretspec_resolver_status secretspec_resolver_client_close(
    secretspec_resolver_client *client,
    uint64_t deadline_unix_ms,
    secretspec_resolver_buffer *error);

SECRETSPEC_RESOLVER_API void secretspec_resolver_client_free(secretspec_resolver_client *client);
SECRETSPEC_RESOLVER_API void secretspec_resolver_buffer_free(secretspec_resolver_buffer buffer);

#ifdef __cplusplus
}
#endif

#endif

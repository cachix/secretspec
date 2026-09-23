#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "secretspec_resolver.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

static const char client_initialize[] =
    "{\"protocol\":\"secretspec.resolver\",\"versions\":[1],"
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

/* A deadline no check means to reach. Anything a check expects to finish is
 * given this much room, so a slow or loaded machine cannot turn a success into
 * a timeout. */
static uint64_t far_deadline(void) {
    return now_ms() + UINT64_C(60000);
}

/* Block until the clock is past `deadline`. This waits on the clock itself,
 * the same one the library compares deadlines against, rather than sleeping
 * for a guessed duration. */
static void wait_past(uint64_t deadline) {
    uint64_t now;
    while ((now = now_ms()) <= deadline) pause_ms(deadline - now + 1);
}

typedef enum {
    CHECK_FAILED,
    CHECK_PASSED,
    /* The setup took longer than the deadline window it was given, so the
     * attempt proves nothing either way. */
    CHECK_RETRY
} check_outcome;

/* Expiry can only be exercised by letting a real deadline pass, and a deadline
 * has to be far enough away for the setup before it (a call reaching the peer,
 * a prompt coming back) to finish first. An attempt that finds it lost that
 * race reports CHECK_RETRY instead of failing and runs again with a wider
 * window. Whether a check passes never depends on scheduling; only how long
 * it takes does. */
static int with_widening_windows(
    const char *peer,
    const char *name,
    check_outcome (*attempt)(const char *peer, uint64_t window_ms)) {
    static const uint64_t windows_ms[] = {250, 1000, 5000};
    size_t index;
    for (index = 0; index < sizeof(windows_ms) / sizeof(windows_ms[0]); index++) {
        check_outcome outcome = attempt(peer, windows_ms[index]);
        if (outcome != CHECK_RETRY) return outcome == CHECK_PASSED;
        fprintf(stderr, "%s: setup outlived a %lu ms deadline window, widening it\n",
                name, (unsigned long)windows_ms[index]);
    }
    fprintf(stderr, "%s: setup never fit in a deadline window\n", name);
    return 0;
}

static unsigned long current_process_id(void) {
#ifdef _WIN32
    return (unsigned long)GetCurrentProcessId();
#else
    return (unsigned long)getpid();
#endif
}

static void ss_reset(secretspec_resolver_buffer *buffer) {
    buffer->data = NULL;
    buffer->size = 0;
}

static secretspec_resolver_slice slice(const char *text) {
    secretspec_resolver_slice value;
    value.data = (const unsigned char *)text;
    value.size = strlen(text);
    return value;
}

static void set_options(
    secretspec_resolver_options *options,
    const char *peer,
    const char *mode,
    const char *initialize) {
    static secretspec_resolver_slice arguments[1];
    memset(options, 0, sizeof(*options));
    arguments[0] = slice(mode);
    options->struct_size = sizeof(*options);
    options->abi_version = SECRETSPEC_RESOLVER_ABI_VERSION;
    options->executable = slice(peer);
    options->arguments = arguments;
    options->argument_count = 1;
    options->initialize_params_json = slice(initialize);
    options->max_stderr_bytes = 4096;
}

static int open_client(
    const char *peer,
    const char *mode,
    secretspec_resolver_client **client,
    secretspec_resolver_buffer *error) {
    secretspec_resolver_options options;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_status status;
    set_options(&options, peer, mode, client_initialize);
    status = secretspec_resolver_client_open(
        &options, far_deadline(), client, &server, error);
    secretspec_resolver_buffer_free(server);
    return status == SECRETSPEC_RESOLVER_OK;
}

static secretspec_resolver_status start_get(
    secretspec_resolver_client *client,
    uint64_t deadline,
    const char *params,
    secretspec_resolver_call **call,
    secretspec_resolver_buffer *error) {
    return secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        (const unsigned char *)params, strlen(params), deadline, call, error);
}

/* CreateProcessW requires a custom environment block to be sorted by variable
 * name without regard to case. Supply overrides in the opposite order and let
 * the child inspect the block it actually received. The value assertions run
 * on every platform; Windows additionally verifies the native ordering. */
static int launches_with_environment(const char *peer, int inherit) {
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    static secretspec_resolver_slice environment[3];
    environment[0] = slice("SECRETSPEC_Z_LAST=last");
    environment[1] = slice("SecretSpec_M_Middle=middle");
    environment[2] = slice("secretspec_a_first=first");
    set_options(&options, peer, "--check-environment", client_initialize);
    if (inherit) options.flags |= SECRETSPEC_RESOLVER_INHERIT_ENVIRONMENT;
    options.environment = environment;
    options.environment_count = 3;
    status = secretspec_resolver_client_open(
        &options, far_deadline(), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto failed;
    status = secretspec_resolver_client_close(
        client, far_deadline(), &error);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_OK;
failed:
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return 0;
}

static int launches_with_a_sorted_environment(const char *peer) {
    return launches_with_environment(peer, 1) &&
           launches_with_environment(peer, 0);
}

static int rejects_bad_shutdown(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    if (!open_client(peer, "--bad-shutdown", &client, &error)) goto failed;
    status = secretspec_resolver_client_close(
        client, far_deadline(), &error);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_PROTOCOL;
failed:
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return 0;
}

/* A handle freed without waiting still owns its in-flight slot until the call
 * ends, and a call the peer never answers ends at its deadline. Freed calls
 * that never expired would pin their slots and starve the session. */
static check_outcome freed_calls_expire_within(const char *peer, uint64_t window_ms) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    check_outcome outcome = CHECK_FAILED;
    uint64_t deadline;
    size_t index;
    if (!open_client(peer, "--ignore-calls", &client, &error)) goto done;
    deadline = now_ms() + window_ms;
    /* Fill every negotiated slot with a call the peer ignores, and free it. */
    for (index = 0; index < 4; index++) {
        status = start_get(client, deadline, "{}", &call, &error);
        if (status == SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) outcome = CHECK_RETRY;
        if (status != SECRETSPEC_RESOLVER_OK) goto done;
        secretspec_resolver_call_free(call);
        call = NULL;
    }
    /* The slots really are taken while those deadlines are ahead. */
    status = start_get(client, far_deadline(), "{}", &call, &error);
    if (status == SECRETSPEC_RESOLVER_OK) {
        if (now_ms() >= deadline) outcome = CHECK_RETRY;
        goto done;
    }
    if (status != SECRETSPEC_RESOLVER_UNAVAILABLE) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    /* Past the deadlines the session's deadline worker gives the slots back.
     * Wait for that to happen instead of guessing how long it takes; the
     * limit only turns a slot that is never released into a failure rather
     * than a hang. */
    wait_past(deadline);
    for (;;) {
        status = start_get(client, far_deadline(), "{}", &call, &error);
        if (status == SECRETSPEC_RESOLVER_OK) break;
        secretspec_resolver_buffer_free(error);
        ss_reset(&error);
        if (status != SECRETSPEC_RESOLVER_UNAVAILABLE ||
            now_ms() > deadline + UINT64_C(30000)) goto done;
        pause_ms(1);
    }
    secretspec_resolver_call_free(call);
    call = NULL;
    status = secretspec_resolver_client_close(client, far_deadline(), &error);
    if (status == SECRETSPEC_RESOLVER_OK) outcome = CHECK_PASSED;
done:
    secretspec_resolver_buffer_free(error);
    if (call != NULL) secretspec_resolver_call_free(call);
    if (client != NULL) secretspec_resolver_client_free(client);
    return outcome;
}

static int freed_calls_expire(const char *peer) {
    return with_widening_windows(peer, "freed_calls_expire", freed_calls_expire_within);
}

/* The peer forks a descendant that inherits its stdout and stderr and keeps
 * them open until this test process exits, then exits itself right after
 * answering rpc.shutdown. Close must finish once the peer is gone instead of
 * waiting for end of file on pipes the descendant still holds. Had it waited,
 * it would never return: the descendant outlives the call. */
static int descendant_pipes_do_not_block_close(const char *peer) {
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    static char watch[64];
    static secretspec_resolver_slice environment[1];
    int length = snprintf(watch, sizeof(watch), "SECRETSPEC_FAKE_PEER_HOLD_UNTIL_EXIT_OF=%lu",
                          current_process_id());
    if (length <= 0 || (size_t)length >= sizeof(watch)) return 0;
    environment[0] = slice(watch);
    set_options(&options, peer, "--descendant-holds-pipes", client_initialize);
    options.flags |= SECRETSPEC_RESOLVER_INHERIT_ENVIRONMENT;
    options.environment = environment;
    options.environment_count = 1;
    status = secretspec_resolver_client_open(&options, far_deadline(), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto failed;
    status = secretspec_resolver_client_close(client, far_deadline(), &error);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_OK;
failed:
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return 0;
}

/* An endpoint that prints a banner on the stream reserved for frames must be
 * named as such. Reporting it as a frame-size problem is what sends integrators
 * hunting a bug that is not there, so the diagnostic is pinned here and in the
 * Rust decoder's matching test. */
static int names_non_protocol_text(const char *peer) {
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    int named;
    set_options(&options, peer, "--banner-on-stdout", client_initialize);
    status = secretspec_resolver_client_open(
        &options, far_deadline(), &client, &server, &error);
    named = error.data != NULL &&
            strstr((const char *)error.data, "non-protocol text") != NULL;
    secretspec_resolver_buffer_free(server);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_PROTOCOL && client == NULL && named;
}

/* An error code and kind from a later revision of the protocol must reach the
 * caller as an ordinary remote failure. Refusing it would kill the session, and
 * the error set could then never grow without a new protocol version. Pinned
 * here and in the Rust decoder's matching test. */
static int a_future_error_kind_does_not_kill_the_session(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    secretspec_resolver_status status;
    static const unsigned char params[] = "{}";
    int reported;
    if (!open_client(peer, "--future-error-kind", &client, &error)) goto failed;
    status = secretspec_resolver_client_call(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, far_deadline(), &result, &error);
    reported = status == SECRETSPEC_RESOLVER_REMOTE_ERROR;
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    error.data = NULL;
    error.size = 0;
    /* The session survived, so an ordinary shutdown still works. */
    status = secretspec_resolver_client_close(client, far_deadline(), &error);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_client_free(client);
    return reported && status == SECRETSPEC_RESOLVER_OK;
failed:
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return 0;
}

/* The prompt loop end to end: the peer asks mid-call, the caller answers
 * without any callback into this library, and the call completes with the
 * answered value. The peer's prompt deliberately uses request ID 1, which the
 * client also used for its own initialize, so this also pins that the two
 * directions have separate ID spaces. */
static int answers_a_prompt_and_completes_the_call(const char *peer) {
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char params[] = "{}";
    static const unsigned char answer[] = "typed-by-a-person";
    static const unsigned char invalid_answer[] = {0xc3, 0x28};
    secretspec_resolver_status status;
    secretspec_resolver_slice asked;
    int outcome = 0;

    set_options(&options, peer, "--prompt", client_initialize);
    options.flags |= SECRETSPEC_RESOLVER_ANSWER_PROMPTS;
    status = secretspec_resolver_client_open(
        &options, far_deadline(), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;

    /* The one-shot form cannot resume after a prompt and must say so. */
    status = secretspec_resolver_client_call(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, far_deadline(), &result, &error);
    if (status != SECRETSPEC_RESOLVER_INVALID_ARGUMENT) goto done;
    secretspec_resolver_buffer_free(result);
    ss_reset(&result);
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);

    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, far_deadline(), &call, &error);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;

    status = secretspec_resolver_call_wait(call, &result, &error);
    if (status != SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    if (secretspec_resolver_prompt_take(client, &prompt, &error) != SECRETSPEC_RESOLVER_OK ||
        prompt == NULL) goto done;
    asked = secretspec_resolver_prompt_params(prompt);
    if (asked.data == NULL ||
        strstr((const char *)asked.data, "DEPLOY_PASSWORD") == NULL ||
        strstr((const char *)asked.data, "\"profile\"") == NULL) goto done;
    /* An empty answer is refused; declining is the way to say no. */
    if (secretspec_resolver_prompt_answer(prompt, answer, 0, &error) !=
        SECRETSPEC_RESOLVER_INVALID_ARGUMENT) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    /* Invalid UTF-8 is rejected before the one-shot prompt is consumed. */
    if (secretspec_resolver_prompt_answer(prompt, invalid_answer, sizeof(invalid_answer), &error) !=
        SECRETSPEC_RESOLVER_INVALID_ARGUMENT) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    if (secretspec_resolver_prompt_answer(prompt, answer, sizeof(answer) - 1, &error) !=
        SECRETSPEC_RESOLVER_OK) goto done;
    /* One prompt owes exactly one response. */
    if (secretspec_resolver_prompt_answer(prompt, answer, sizeof(answer) - 1, &error) !=
        SECRETSPEC_RESOLVER_INVALID_ARGUMENT) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    secretspec_resolver_prompt_free(prompt);
    prompt = NULL;

    status = secretspec_resolver_call_wait(call, &result, &error);
    if (status != SECRETSPEC_RESOLVER_OK || result.data == NULL) goto done;
    outcome = strstr((const char *)result.data, "typed-by-a-person") != NULL;
done:
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) {
        secretspec_resolver_buffer close_error = {NULL, 0};
        (void)secretspec_resolver_client_close(client, far_deadline(), &close_error);
        secretspec_resolver_buffer_free(close_error);
        secretspec_resolver_client_free(client);
    }
    return outcome;
}

static int open_answering(
    const char *peer,
    const char *mode,
    secretspec_resolver_client **client,
    secretspec_resolver_buffer *error);
static void close_and_free(secretspec_resolver_client *client);

/* Start the call the --expired-prompt peer raises a prompt for. The peer never
 * answers that call, and gives the prompt the deadline passed here. */
static secretspec_resolver_status start_expiring_prompt_call(
    secretspec_resolver_client *client,
    uint64_t prompt_deadline,
    uint64_t call_deadline,
    secretspec_resolver_call **call,
    secretspec_resolver_buffer *error) {
    char params[64];
    int length = snprintf(params, sizeof(params), "{\"prompt_deadline_unix_ms\":%llu}",
                          (unsigned long long)prompt_deadline);
    if (length <= 0 || (size_t)length >= sizeof(params)) return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    return start_get(client, call_deadline, params, call, error);
}

/* A later call completes normally and sees no prompt. The peer answers every
 * call after the first, and exits on any response it did not ask for, so this
 * also shows nothing was sent for a prompt that could no longer be answered. */
static int a_later_call_completes(secretspec_resolver_client *client) {
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    int completed = 0;
    if (start_get(client, far_deadline(), "{}", &call, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) != SECRETSPEC_RESOLVER_OK ||
        result.data == NULL) goto done;
    if (secretspec_resolver_prompt_take(client, &prompt, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    completed = prompt == NULL;
done:
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    return completed;
}

/* A prompt nobody takes must leave the queue at its own deadline. Its parent
 * call is still running when the later call is made, so only the prompt's
 * deadline can have removed it; a stale prompt would hand PROMPT_PENDING to
 * every later call. The parent then ends at its own, later deadline. */
static check_outcome an_expired_prompt_does_not_block_later_calls_within(
    const char *peer,
    uint64_t window_ms) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    secretspec_resolver_status status;
    check_outcome outcome = CHECK_FAILED;
    uint64_t prompt_deadline;
    uint64_t call_deadline;

    if (open_answering(peer, "--expired-prompt", &client, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    prompt_deadline = now_ms() + window_ms;
    call_deadline = prompt_deadline + window_ms;
    status = start_expiring_prompt_call(client, prompt_deadline, call_deadline, &call, &error);
    if (status == SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) outcome = CHECK_RETRY;
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_wait(call, &result, &error);
    /* The prompt arrived after its own deadline and was rightly dropped. */
    if (status == SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) outcome = CHECK_RETRY;
    if (status != SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);

    wait_past(prompt_deadline);
    if (!a_later_call_completes(client)) goto done;
    /* The parent's deadline passed too, so it may have been what removed the
     * prompt. The check has to see the prompt's own deadline do it. */
    if (now_ms() >= call_deadline) {
        outcome = CHECK_RETRY;
        goto done;
    }
    if (secretspec_resolver_call_wait(call, &result, &error) !=
        SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) goto done;
    outcome = CHECK_PASSED;
done:
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    close_and_free(client);
    return outcome;
}

static int an_expired_prompt_does_not_block_later_calls(const char *peer) {
    return with_widening_windows(peer, "an_expired_prompt_does_not_block_later_calls",
                                 an_expired_prompt_does_not_block_later_calls_within);
}

/* A taken prompt answered after its deadline is refused with
 * DEADLINE_EXCEEDED and nothing goes on the wire. The parent is still running
 * at that point, so the refusal is the prompt's own deadline, not a cancelled
 * parent. The parent then ends at its own, later deadline. */
static check_outcome an_answer_cannot_outlive_its_prompt_within(
    const char *peer,
    uint64_t window_ms) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char answer[] = "too-late";
    secretspec_resolver_status status;
    check_outcome outcome = CHECK_FAILED;
    uint64_t prompt_deadline;
    uint64_t call_deadline;

    if (open_answering(peer, "--expired-prompt", &client, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    prompt_deadline = now_ms() + window_ms;
    call_deadline = prompt_deadline + window_ms;
    status = start_expiring_prompt_call(client, prompt_deadline, call_deadline, &call, &error);
    if (status == SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) outcome = CHECK_RETRY;
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_wait(call, &result, &error);
    /* The prompt arrived after its own deadline and was rightly dropped. */
    if (status == SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) outcome = CHECK_RETRY;
    if (status != SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    if (secretspec_resolver_prompt_take(client, &prompt, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (prompt == NULL) {
        /* It expired between being announced and being taken. */
        if (now_ms() >= prompt_deadline) outcome = CHECK_RETRY;
        goto done;
    }

    wait_past(prompt_deadline);
    status = secretspec_resolver_prompt_answer(prompt, answer, sizeof(answer) - 1, &error);
    if (status == SECRETSPEC_RESOLVER_CANCELLED && now_ms() >= call_deadline) {
        /* The parent expired before the answer could be tried. */
        outcome = CHECK_RETRY;
        goto done;
    }
    if (status != SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    secretspec_resolver_prompt_free(prompt);
    prompt = NULL;
    if (!a_later_call_completes(client)) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) !=
        SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) goto done;
    outcome = CHECK_PASSED;
done:
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    close_and_free(client);
    return outcome;
}

static int an_answer_cannot_outlive_its_prompt(const char *peer) {
    return with_widening_windows(peer, "an_answer_cannot_outlive_its_prompt",
                                 an_answer_cannot_outlive_its_prompt_within);
}

/* A taken prompt whose parent call already finished is refused with
 * CANCELLED. The --parent-terminal-prompt peer finishes the parent only when
 * the next call arrives, answering the parent first. Responses are handled in
 * order, so once that next call completes the parent is terminal, with no
 * sleep on either side. */
static int a_prompt_cannot_outlive_its_parent(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_call *later = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char answer[] = "too-late";
    int outcome = 0;

    if (open_answering(peer, "--parent-terminal-prompt", &client, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (start_get(client, far_deadline(), "{}", &call, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) !=
        SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    if (secretspec_resolver_prompt_take(client, &prompt, &error) !=
            SECRETSPEC_RESOLVER_OK || prompt == NULL) goto done;
    if (start_get(client, far_deadline(), "{}", &later, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(later, &result, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    secretspec_resolver_buffer_free(result);
    ss_reset(&result);
    if (secretspec_resolver_prompt_answer(prompt, answer, sizeof(answer) - 1, &error) !=
        SECRETSPEC_RESOLVER_CANCELLED) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    outcome = secretspec_resolver_call_wait(call, &result, &error) ==
              SECRETSPEC_RESOLVER_OK;
done:
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (later != NULL) secretspec_resolver_call_free(later);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    close_and_free(client);
    return outcome;
}

static int rejects_a_callback_deadline_after_its_parent(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char params[] = "{}";
    secretspec_resolver_status status;
    int outcome = 0;
    secretspec_resolver_options options;
    secretspec_resolver_buffer server = {NULL, 0};

    set_options(&options, peer, "--late-deadline-prompt", client_initialize);
    options.flags |= SECRETSPEC_RESOLVER_ANSWER_PROMPTS;
    status = secretspec_resolver_client_open(
        &options, far_deadline(), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, far_deadline(), &call, &error);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_wait(call, &result, &error);
    outcome = status == SECRETSPEC_RESOLVER_PROTOCOL;
done:
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return outcome;
}

static int notification_semantics_are_consistent(const char *peer) {
    static const unsigned char params[] = "{}";
    const char *modes[] = {"--unknown-notification", "--invalid-notification"};
    size_t index;
    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); index++) {
        secretspec_resolver_client *client = NULL;
        secretspec_resolver_buffer error = {NULL, 0};
        secretspec_resolver_buffer result = {NULL, 0};
        secretspec_resolver_status status;
        if (!open_client(peer, modes[index], &client, &error)) goto failed;
        status = secretspec_resolver_client_call(
            client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
            params, sizeof(params) - 1, far_deadline(), &result, &error);
        if ((index == 0 && status != SECRETSPEC_RESOLVER_OK) ||
            (index == 1 && status != SECRETSPEC_RESOLVER_PROTOCOL)) goto failed;
        secretspec_resolver_buffer_free(result);
        secretspec_resolver_buffer_free(error);
        secretspec_resolver_client_free(client);
        continue;
failed:
        secretspec_resolver_buffer_free(result);
        secretspec_resolver_buffer_free(error);
        if (client != NULL) secretspec_resolver_client_free(client);
        return 0;
    }
    return 1;
}

#ifndef _WIN32
static int closed_standard_streams_work(const char *peer) {
    /* Isolate descriptor changes, exercising every combination of closed streams. */
    for (unsigned mask = 1; mask < 8; mask++) {
        pid_t pid = fork();
        int status;
        if (pid < 0) return 0;
        if (pid == 0) {
            for (int fd = 0; fd <= 2; fd++) {
                if (mask & (1u << fd)) close(fd);
            }
            _exit(notification_semantics_are_consistent(peer) ? 0 : 1);
        }
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            return 0;
    }
    return 1;
}
#endif

static int open_answering(
    const char *peer,
    const char *mode,
    secretspec_resolver_client **client,
    secretspec_resolver_buffer *error) {
    secretspec_resolver_options options;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_status status;
    set_options(&options, peer, mode, client_initialize);
    options.flags |= SECRETSPEC_RESOLVER_ANSWER_PROMPTS;
    status = secretspec_resolver_client_open(
        &options, far_deadline(), client, &server, error);
    secretspec_resolver_buffer_free(server);
    return status;
}

static void close_and_free(secretspec_resolver_client *client) {
    secretspec_resolver_buffer close_error = {NULL, 0};
    if (client == NULL) return;
    (void)secretspec_resolver_client_close(client, far_deadline(), &close_error);
    secretspec_resolver_buffer_free(close_error);
    secretspec_resolver_client_free(client);
}

/* An answer that cannot fit in one negotiated frame is refused before the
 * prompt is consumed, so the caller can still answer or decline it instead of
 * leaving the endpoint waiting out the deadline. */
static int an_oversized_answer_leaves_the_prompt_open(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char params[] = "{}";
    static const unsigned char answer[] = "short-enough";
    unsigned char *oversized = NULL;
    const size_t oversized_size = 5000;
    int outcome = 0;

    if (open_answering(peer, "--small-frame-prompt", &client, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_start(
            client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
            params, sizeof(params) - 1, far_deadline(), &call, &error) !=
        SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) != SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    if (secretspec_resolver_prompt_take(client, &prompt, &error) != SECRETSPEC_RESOLVER_OK ||
        prompt == NULL) goto done;
    oversized = (unsigned char *)malloc(oversized_size);
    if (oversized == NULL) goto done;
    memset(oversized, 'a', oversized_size);
    if (secretspec_resolver_prompt_answer(prompt, oversized, oversized_size, &error) !=
        SECRETSPEC_RESOLVER_INVALID_ARGUMENT) goto done;
    if (error.data == NULL || strstr((const char *)error.data, "frame size") == NULL) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    if (secretspec_resolver_prompt_answer(prompt, answer, sizeof(answer) - 1, &error) !=
        SECRETSPEC_RESOLVER_OK) goto done;
    secretspec_resolver_prompt_free(prompt);
    prompt = NULL;
    if (secretspec_resolver_call_wait(call, &result, &error) != SECRETSPEC_RESOLVER_OK ||
        result.data == NULL) goto done;
    outcome = strstr((const char *)result.data, "short-enough") != NULL;
done:
    free(oversized);
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    close_and_free(client);
    return outcome;
}

/* rpc.initialize is the library's own request. A prompt claiming it as parent
 * is a peer defect, not something to hand to a caller who has no call yet. */
static int rejects_a_prompt_parented_on_initialize(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status = open_answering(peer, "--initialize-prompt", &client, &error);
    secretspec_resolver_buffer_free(error);
    close_and_free(client);
    return status == SECRETSPEC_RESOLVER_PROTOCOL;
}

/* A prompt nobody took must not surface from close as PROMPT_PENDING, which
 * only call_wait documents, and the endpoint gets a decline rather than
 * silence. The peer answers shutdown with a malformed result unless it saw
 * the decline. */
static int close_declines_untaken_prompts(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char params[] = "{}";
    secretspec_resolver_status status = SECRETSPEC_RESOLVER_UNAVAILABLE;

    if (open_answering(peer, "--prompt-then-close", &client, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_start(
            client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
            params, sizeof(params) - 1, far_deadline(), &call, &error) !=
        SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) != SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    status = secretspec_resolver_client_close(client, far_deadline(), &error);
done:
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_OK;
}

/* The peer waits until rpc.shutdown to send a prompt for an earlier call.
 * That guarantees the prompt arrives after close has drained its snapshot. */
static int close_declines_prompts_arriving_during_shutdown(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    static const unsigned char params[] = "{}";
    secretspec_resolver_status status = SECRETSPEC_RESOLVER_UNAVAILABLE;

    if (open_answering(peer, "--prompt-during-close", &client, &error) != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_start(
            client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
            params, sizeof(params) - 1, far_deadline(), &call, &error) !=
        SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_client_close(client, far_deadline(), &error);
done:
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_OK;
}

typedef struct {
    const char *name;
    int (*run)(const char *peer);
} regression_check;

static const regression_check checks[] = {
#ifndef _WIN32
    {"closed_standard_streams_work", closed_standard_streams_work},
#endif
    {"launches_with_a_sorted_environment", launches_with_a_sorted_environment},
    {"names_non_protocol_text", names_non_protocol_text},
    {"answers_a_prompt_and_completes_the_call", answers_a_prompt_and_completes_the_call},
    {"an_oversized_answer_leaves_the_prompt_open", an_oversized_answer_leaves_the_prompt_open},
    {"rejects_a_prompt_parented_on_initialize", rejects_a_prompt_parented_on_initialize},
    {"close_declines_untaken_prompts", close_declines_untaken_prompts},
    {"close_declines_prompts_arriving_during_shutdown", close_declines_prompts_arriving_during_shutdown},
    {"an_expired_prompt_does_not_block_later_calls", an_expired_prompt_does_not_block_later_calls},
    {"an_answer_cannot_outlive_its_prompt", an_answer_cannot_outlive_its_prompt},
    {"a_prompt_cannot_outlive_its_parent", a_prompt_cannot_outlive_its_parent},
    {"rejects_a_callback_deadline_after_its_parent", rejects_a_callback_deadline_after_its_parent},
    {"notification_semantics_are_consistent", notification_semantics_are_consistent},
    {"a_future_error_kind_does_not_kill_the_session", a_future_error_kind_does_not_kill_the_session},
    {"rejects_bad_shutdown", rejects_bad_shutdown},
    {"freed_calls_expire", freed_calls_expire},
    {"descendant_pipes_do_not_block_close", descendant_pipes_do_not_block_close},
};

/* Every check runs and names itself on stderr, so a failure says which
 * regression it was, and a hang shows the check it stopped in. */
int main(int argc, char **argv) {
    const size_t count = sizeof(checks) / sizeof(checks[0]);
    size_t index;
    size_t failed = 0;
    if (argc != 2) {
        fputs("usage: secretspec_resolver_regressions <fake peer executable>\n", stderr);
        return EXIT_FAILURE;
    }
    for (index = 0; index < count; index++) {
        fprintf(stderr, "check %s\n", checks[index].name);
        (void)fflush(stderr);
        if (!checks[index].run(argv[1])) {
            fprintf(stderr, "FAILED %s\n", checks[index].name);
            (void)fflush(stderr);
            failed++;
        }
    }
    if (failed != 0) {
        fprintf(stderr, "%lu of %lu regression checks failed\n",
                (unsigned long)failed, (unsigned long)count);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

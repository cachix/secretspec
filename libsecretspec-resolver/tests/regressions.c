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
        &options, now_ms() + UINT64_C(2000), client, &server, error);
    secretspec_resolver_buffer_free(server);
    return status == SECRETSPEC_RESOLVER_OK;
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
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto failed;
    status = secretspec_resolver_client_close(
        client, now_ms() + UINT64_C(2000), &error);
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
        client, now_ms() + UINT64_C(2000), &error);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_PROTOCOL;
failed:
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return 0;
}

static int freed_calls_expire(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    size_t index;
    if (!open_client(peer, "--ignore-calls", &client, &error)) goto failed;
    for (index = 0; index < 4; index++) {
        static const unsigned char params[] = "{}";
        uint64_t deadline = now_ms() + UINT64_C(100);
        status = secretspec_resolver_call_start(
            client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
            params, sizeof(params) - 1, deadline, &call, &error);
        if (status != SECRETSPEC_RESOLVER_OK) goto failed;
        secretspec_resolver_call_free(call);
        call = NULL;
    }
    pause_ms(UINT64_C(400));
    {
        static const unsigned char params[] = "{}";
        uint64_t deadline = now_ms() + UINT64_C(1000);
        status = secretspec_resolver_call_start(
            client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
            params, sizeof(params) - 1, deadline, &call, &error);
        if (status != SECRETSPEC_RESOLVER_OK) goto failed;
    }
    secretspec_resolver_call_free(call);
    call = NULL;
    status = secretspec_resolver_client_close(
        client, now_ms() + UINT64_C(2000), &error);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_OK;
failed:
    secretspec_resolver_buffer_free(error);
    if (call != NULL) secretspec_resolver_call_free(call);
    if (client != NULL) secretspec_resolver_client_free(client);
    return 0;
}

static int descendant_pipes_do_not_block_close(const char *peer) {
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_status status;
    uint64_t started;
    if (!open_client(peer, "--descendant-holds-pipes", &client, &error)) goto failed;
    started = now_ms();
    status = secretspec_resolver_client_close(
        client, started + UINT64_C(250), &error);
    secretspec_resolver_buffer_free(error);
    secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_OK && now_ms() - started < UINT64_C(2000);
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
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
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
        params, sizeof(params) - 1, now_ms() + UINT64_C(2000), &result, &error);
    reported = status == SECRETSPEC_RESOLVER_REMOTE_ERROR;
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    error.data = NULL;
    error.size = 0;
    /* The session survived, so an ordinary shutdown still works. */
    status = secretspec_resolver_client_close(client, now_ms() + UINT64_C(2000), &error);
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
        &options, now_ms() + UINT64_C(5000), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;

    /* The one-shot form cannot resume after a prompt and must say so. */
    status = secretspec_resolver_client_call(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, now_ms() + UINT64_C(5000), &result, &error);
    if (status != SECRETSPEC_RESOLVER_INVALID_ARGUMENT) goto done;
    secretspec_resolver_buffer_free(result);
    ss_reset(&result);
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);

    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, now_ms() + UINT64_C(5000), &call, &error);
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
        (void)secretspec_resolver_client_close(client, now_ms() + UINT64_C(2000), &close_error);
        secretspec_resolver_buffer_free(close_error);
        secretspec_resolver_client_free(client);
    }
    return outcome;
}

static int an_expired_prompt_does_not_block_later_calls(const char *peer) {
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char params[] = "{}";
    secretspec_resolver_status status;
    int outcome = 0;

    set_options(&options, peer, "--expired-prompt", client_initialize);
    options.flags |= SECRETSPEC_RESOLVER_ANSWER_PROMPTS;
    status = secretspec_resolver_client_open(
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;

    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, now_ms() + UINT64_C(200), &call, &error);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) !=
        SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    pause_ms(UINT64_C(300));
    if (secretspec_resolver_call_wait(call, &result, &error) !=
        SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    secretspec_resolver_call_free(call);
    call = NULL;

    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, now_ms() + UINT64_C(2000), &call, &error);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_wait(call, &result, &error);
    if (status != SECRETSPEC_RESOLVER_OK || result.data == NULL) goto done;
    if (secretspec_resolver_prompt_take(client, &prompt, &error) !=
            SECRETSPEC_RESOLVER_OK || prompt != NULL) goto done;
    outcome = 1;
done:
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) {
        secretspec_resolver_buffer close_error = {NULL, 0};
        (void)secretspec_resolver_client_close(client, now_ms() + UINT64_C(2000), &close_error);
        secretspec_resolver_buffer_free(close_error);
        secretspec_resolver_client_free(client);
    }
    return outcome;
}

static int an_answer_cannot_outlive_its_prompt(const char *peer) {
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char params[] = "{}";
    static const unsigned char answer[] = "too-late";
    secretspec_resolver_status status;
    int outcome = 0;

    set_options(&options, peer, "--expired-prompt", client_initialize);
    options.flags |= SECRETSPEC_RESOLVER_ANSWER_PROMPTS;
    status = secretspec_resolver_client_open(
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, now_ms() + UINT64_C(250), &call, &error);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) !=
        SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    if (secretspec_resolver_prompt_take(client, &prompt, &error) !=
            SECRETSPEC_RESOLVER_OK || prompt == NULL) goto done;
    pause_ms(UINT64_C(150));
    if (secretspec_resolver_prompt_answer(prompt, answer, sizeof(answer) - 1, &error) !=
        SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    pause_ms(UINT64_C(150));
    outcome = secretspec_resolver_call_wait(call, &result, &error) ==
        SECRETSPEC_RESOLVER_DEADLINE_EXCEEDED;
done:
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) {
        secretspec_resolver_buffer close_error = {NULL, 0};
        (void)secretspec_resolver_client_close(client, now_ms() + UINT64_C(2000), &close_error);
        secretspec_resolver_buffer_free(close_error);
        secretspec_resolver_client_free(client);
    }
    return outcome;
}

static int a_prompt_cannot_outlive_its_parent(const char *peer) {
    secretspec_resolver_options options;
    secretspec_resolver_client *client = NULL;
    secretspec_resolver_call *call = NULL;
    secretspec_resolver_prompt *prompt = NULL;
    secretspec_resolver_buffer server = {NULL, 0};
    secretspec_resolver_buffer error = {NULL, 0};
    secretspec_resolver_buffer result = {NULL, 0};
    static const unsigned char params[] = "{}";
    static const unsigned char answer[] = "too-late";
    secretspec_resolver_status status;
    int outcome = 0;

    set_options(&options, peer, "--parent-terminal-prompt", client_initialize);
    options.flags |= SECRETSPEC_RESOLVER_ANSWER_PROMPTS;
    status = secretspec_resolver_client_open(
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, now_ms() + UINT64_C(2000), &call, &error);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) !=
        SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    if (secretspec_resolver_prompt_take(client, &prompt, &error) !=
            SECRETSPEC_RESOLVER_OK || prompt == NULL) goto done;
    pause_ms(UINT64_C(200));
    if (secretspec_resolver_prompt_answer(prompt, answer, sizeof(answer) - 1, &error) !=
        SECRETSPEC_RESOLVER_CANCELLED) goto done;
    secretspec_resolver_buffer_free(error);
    ss_reset(&error);
    outcome = secretspec_resolver_call_wait(call, &result, &error) ==
              SECRETSPEC_RESOLVER_OK;
done:
    if (prompt != NULL) secretspec_resolver_prompt_free(prompt);
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(result);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) {
        secretspec_resolver_buffer close_error = {NULL, 0};
        (void)secretspec_resolver_client_close(client, now_ms() + UINT64_C(500), &close_error);
        secretspec_resolver_buffer_free(close_error);
        secretspec_resolver_client_free(client);
    }
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
        &options, now_ms() + UINT64_C(2000), &client, &server, &error);
    secretspec_resolver_buffer_free(server);
    if (status != SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_call_start(
        client, (const unsigned char *)"resolver.get", strlen("resolver.get"),
        params, sizeof(params) - 1, now_ms() + UINT64_C(1000), &call, &error);
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
            params, sizeof(params) - 1, now_ms() + UINT64_C(1000), &result, &error);
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
        &options, now_ms() + UINT64_C(5000), client, &server, error);
    secretspec_resolver_buffer_free(server);
    return status;
}

static void close_and_free(secretspec_resolver_client *client) {
    secretspec_resolver_buffer close_error = {NULL, 0};
    if (client == NULL) return;
    (void)secretspec_resolver_client_close(client, now_ms() + UINT64_C(2000), &close_error);
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
            params, sizeof(params) - 1, now_ms() + UINT64_C(5000), &call, &error) !=
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
            params, sizeof(params) - 1, now_ms() + UINT64_C(5000), &call, &error) !=
        SECRETSPEC_RESOLVER_OK) goto done;
    if (secretspec_resolver_call_wait(call, &result, &error) != SECRETSPEC_RESOLVER_PROMPT_PENDING) goto done;
    status = secretspec_resolver_client_close(client, now_ms() + UINT64_C(2000), &error);
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
            params, sizeof(params) - 1, now_ms() + UINT64_C(5000), &call, &error) !=
        SECRETSPEC_RESOLVER_OK) goto done;
    status = secretspec_resolver_client_close(client, now_ms() + UINT64_C(2000), &error);
done:
    if (call != NULL) secretspec_resolver_call_free(call);
    secretspec_resolver_buffer_free(error);
    if (client != NULL) secretspec_resolver_client_free(client);
    return status == SECRETSPEC_RESOLVER_OK;
}

int main(int argc, char **argv) {
    if (argc != 2) return EXIT_FAILURE;
#ifndef _WIN32
    if (!closed_standard_streams_work(argv[1])) return EXIT_FAILURE;
#endif
    if (!launches_with_a_sorted_environment(argv[1])) return EXIT_FAILURE;
    if (!names_non_protocol_text(argv[1])) return EXIT_FAILURE;
    if (!answers_a_prompt_and_completes_the_call(argv[1])) return EXIT_FAILURE;
    if (!an_oversized_answer_leaves_the_prompt_open(argv[1])) return EXIT_FAILURE;
    if (!rejects_a_prompt_parented_on_initialize(argv[1])) return EXIT_FAILURE;
    if (!close_declines_untaken_prompts(argv[1])) {
        fputs("close did not decline an untaken prompt\n", stderr);
        return EXIT_FAILURE;
    }
    if (!close_declines_prompts_arriving_during_shutdown(argv[1])) {
        fputs("close did not decline a prompt arriving during shutdown\n", stderr);
        return EXIT_FAILURE;
    }
    if (!an_expired_prompt_does_not_block_later_calls(argv[1])) return EXIT_FAILURE;
    if (!an_answer_cannot_outlive_its_prompt(argv[1])) return EXIT_FAILURE;
    if (!a_prompt_cannot_outlive_its_parent(argv[1])) return EXIT_FAILURE;
    if (!rejects_a_callback_deadline_after_its_parent(argv[1])) return EXIT_FAILURE;
    if (!notification_semantics_are_consistent(argv[1])) return EXIT_FAILURE;
    if (!a_future_error_kind_does_not_kill_the_session(argv[1])) return EXIT_FAILURE;
    if (!rejects_bad_shutdown(argv[1])) return EXIT_FAILURE;
    if (!freed_calls_expire(argv[1])) return EXIT_FAILURE;
    if (!descendant_pipes_do_not_block_close(argv[1])) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

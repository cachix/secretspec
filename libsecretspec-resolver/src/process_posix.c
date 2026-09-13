#ifndef _WIN32

#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

struct ss_process {
    pid_t pid;
    int input;
    int output;
    int error;
    bool reaped;
    atomic_bool interrupted;
};

static void close_fd(int *descriptor) {
    if (*descriptor >= 0) {
        (void)close(*descriptor);
        *descriptor = -1;
    }
}

static bool set_cloexec(int descriptor) {
    int flags = fcntl(descriptor, F_GETFD);
    return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL);
    return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool make_pipe(int descriptors[2]) {
    if (pipe(descriptors) != 0) return false;
    if (!set_cloexec(descriptors[0]) || !set_cloexec(descriptors[1])) {
        close(descriptors[0]);
        close(descriptors[1]);
        return false;
    }
    return true;
}

static size_t env_key_size(const char *entry) {
    const char *equals = strchr(entry, '=');
    return equals == NULL ? strlen(entry) : (size_t)(equals - entry);
}

static bool same_env_key(const char *left, const char *right) {
    size_t left_size = env_key_size(left);
    size_t right_size = env_key_size(right);
    return left_size == right_size && memcmp(left, right, left_size) == 0;
}

static char **build_environment(const ss_launch *launch, bool *allocated) {
    size_t inherited = 0;
    size_t index;
    size_t position = 0;
    char **result;
    *allocated = false;
    if (!launch->inherit_environment) return launch->environment;
    while (environ[inherited] != NULL) inherited++;
    result = (char **)calloc(inherited + launch->environment_count + 1, sizeof(char *));
    if (result == NULL) return NULL;
    *allocated = true;
    for (index = 0; index < inherited; index++) {
        size_t override_index;
        bool overridden = false;
        for (override_index = 0; override_index < launch->environment_count; override_index++) {
            if (same_env_key(environ[index], launch->environment[override_index])) {
                overridden = true;
                break;
            }
        }
        if (!overridden) result[position++] = environ[index];
    }
    for (index = 0; index < launch->environment_count; index++) {
        result[position++] = launch->environment[index];
    }
    result[position] = NULL;
    return result;
}

secretspec_resolver_status ss_process_spawn(const ss_launch *launch, ss_process **process_out) {
    int input[2] = {-1, -1};
    int output[2] = {-1, -1};
    int error[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    bool actions_ready = false;
    char **argv = NULL;
    char **environment = NULL;
    bool environment_allocated = false;
    ss_process *process = NULL;
    pid_t pid = -1;
    int spawn_error;
    size_t index;

    if (process_out == NULL || launch == NULL) return SECRETSPEC_RESOLVER_INVALID_ARGUMENT;
    *process_out = NULL;
    if (!make_pipe(input) || !make_pipe(output) || !make_pipe(error)) goto io_error;
    argv = (char **)calloc(launch->argument_count + 2, sizeof(char *));
    if (argv == NULL) goto unavailable;
    argv[0] = launch->executable;
    for (index = 0; index < launch->argument_count; index++) argv[index + 1] = launch->arguments[index];
    environment = build_environment(launch, &environment_allocated);
    if (environment == NULL) goto unavailable;
    if (posix_spawn_file_actions_init(&actions) != 0) goto io_error;
    actions_ready = true;
    if (posix_spawn_file_actions_adddup2(&actions, input[0], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, error[1], STDERR_FILENO) != 0 ||
        posix_spawn_file_actions_addclose(&actions, input[1]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, output[0]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, error[0]) != 0) goto io_error;

    if (launch->discover) {
        spawn_error = posix_spawnp(&pid, launch->executable, &actions, NULL, argv, environment);
    } else {
        spawn_error = posix_spawn(&pid, launch->executable, &actions, NULL, argv, environment);
    }
    if (spawn_error != 0) goto io_error;
    process = (ss_process *)calloc(1, sizeof(*process));
    if (process == NULL) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        goto unavailable;
    }
    process->pid = pid;
    process->input = input[1];
    process->output = output[0];
    process->error = error[0];
    input[1] = -1;
    output[0] = -1;
    error[0] = -1;
    atomic_init(&process->interrupted, false);
    if (!set_nonblocking(process->input) || !set_nonblocking(process->output) ||
        !set_nonblocking(process->error)) {
        ss_process_free(process);
        process = NULL;
        goto io_error;
    }
    close_fd(&input[0]);
    close_fd(&output[1]);
    close_fd(&error[1]);
    posix_spawn_file_actions_destroy(&actions);
    free(argv);
    if (environment_allocated) free(environment);
    *process_out = process;
    return SECRETSPEC_RESOLVER_OK;

unavailable:
    spawn_error = SECRETSPEC_RESOLVER_UNAVAILABLE;
    goto cleanup;
io_error:
    spawn_error = SECRETSPEC_RESOLVER_IO;
cleanup:
    close_fd(&input[0]);
    close_fd(&input[1]);
    close_fd(&output[0]);
    close_fd(&output[1]);
    close_fd(&error[0]);
    close_fd(&error[1]);
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    free(argv);
    if (environment_allocated) free(environment);
    return (secretspec_resolver_status)spawn_error;
}

static ptrdiff_t read_interruptible(
    ss_process *process,
    int descriptor,
    unsigned char *buffer,
    size_t size) {
    struct pollfd descriptor_state = {descriptor, POLLIN | POLLHUP, 0};
    while (!atomic_load(&process->interrupted)) {
        int ready = poll(&descriptor_state, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (ready == 0) continue;
        for (;;) {
            ssize_t count = read(descriptor, buffer, size);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            return (ptrdiff_t)count;
        }
    }
    return -1;
}

ptrdiff_t ss_process_read_stdout(ss_process *process, unsigned char *buffer, size_t size) {
    return process == NULL || process->output < 0 ? -1 :
           read_interruptible(process, process->output, buffer, size);
}

ptrdiff_t ss_process_read_stderr(ss_process *process, unsigned char *buffer, size_t size) {
    return process == NULL || process->error < 0 ? -1 :
           read_interruptible(process, process->error, buffer, size);
}

bool ss_process_write_stdin(ss_process *process, const unsigned char *buffer, size_t size) {
    size_t written = 0;
    sigset_t blocked;
    sigset_t previous;
    bool mask_changed = false;
    if (process == NULL || process->input < 0) return false;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &blocked, &previous) == 0) mask_changed = true;
    while (written < size && !atomic_load(&process->interrupted)) {
        ssize_t count = write(process->input, buffer + written, size - written);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd descriptor_state = {process->input, POLLOUT, 0};
            int ready;
            do {
                ready = poll(&descriptor_state, 1, 100);
            } while (ready < 0 && errno == EINTR);
            if (ready >= 0) continue;
        }
        if (count <= 0) {
            if (mask_changed && !sigismember(&previous, SIGPIPE)) {
                // Drain the SIGPIPE this write just raised, which is pending on
                // this thread because we blocked it above. macOS has no
                // sigtimedwait, and sigwait cannot block here: the signal is
                // thread-directed, so no other thread can consume it first.
                sigset_t pending;
                if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE)) {
                    int drained;
                    (void)sigwait(&blocked, &drained);
                }
            }
            if (mask_changed) (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
            return false;
        }
        written += (size_t)count;
    }
    if (mask_changed) (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
    return written == size;
}

void ss_process_close_stdin(ss_process *process) {
    if (process != NULL) close_fd(&process->input);
}

void ss_process_interrupt_io(ss_process *process) {
    if (process != NULL) atomic_store(&process->interrupted, true);
}

bool ss_process_wait(ss_process *process, uint64_t deadline_unix_ms) {
    struct timespec pause = {0, 10000000};
    if (process == NULL || process->reaped) return true;
    for (;;) {
        pid_t result = waitpid(process->pid, NULL, WNOHANG);
        if (result == process->pid || (result < 0 && errno == ECHILD)) {
            process->reaped = true;
            return true;
        }
        if (result < 0 && errno != EINTR) return false;
        if (ss_now_unix_ms() >= deadline_unix_ms) return false;
        (void)nanosleep(&pause, NULL);
    }
}

void ss_process_terminate(ss_process *process) {
    uint64_t grace;
    if (process == NULL || process->reaped) return;
    (void)kill(process->pid, SIGTERM);
    grace = ss_now_unix_ms() + UINT64_C(250);
    if (!ss_process_wait(process, grace)) {
        (void)kill(process->pid, SIGKILL);
        (void)waitpid(process->pid, NULL, 0);
        process->reaped = true;
    }
}

void ss_process_free(ss_process *process) {
    if (process == NULL) return;
    ss_process_close_stdin(process);
    close_fd(&process->output);
    close_fd(&process->error);
    ss_process_terminate(process);
    free(process);
}

#endif

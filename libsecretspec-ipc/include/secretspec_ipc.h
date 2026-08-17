#ifndef SECRETSPEC_IPC_H
#define SECRETSPEC_IPC_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(SECRETSPEC_IPC_SHARED)
#  if defined(SECRETSPEC_IPC_BUILDING)
#    define SECRETSPEC_IPC_API __declspec(dllexport)
#  else
#    define SECRETSPEC_IPC_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define SECRETSPEC_IPC_API __attribute__((visibility("default")))
#else
#  define SECRETSPEC_IPC_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SECRETSPEC_IPC_ABI_VERSION ((1u << 16) | 0u)

typedef struct secretspec_ipc_client secretspec_ipc_client;
typedef struct secretspec_ipc_call secretspec_ipc_call;

typedef struct {
    const unsigned char *data;
    size_t size;
} secretspec_ipc_slice;

enum {
    SECRETSPEC_IPC_DISCOVER_EXECUTABLE = 1u << 0,
    SECRETSPEC_IPC_INHERIT_ENVIRONMENT = 1u << 1
};

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t flags;
    uint32_t reserved;
    secretspec_ipc_slice executable;
    const secretspec_ipc_slice *arguments;
    size_t argument_count;
    const secretspec_ipc_slice *environment;
    size_t environment_count;
    secretspec_ipc_slice initialize_params_json;
    size_t max_stderr_bytes;
} secretspec_ipc_options;

typedef enum {
    SECRETSPEC_IPC_OK = 0,
    SECRETSPEC_IPC_INVALID_ARGUMENT = 1,
    SECRETSPEC_IPC_UNAVAILABLE = 2,
    SECRETSPEC_IPC_IO = 3,
    SECRETSPEC_IPC_PROTOCOL = 4,
    SECRETSPEC_IPC_REMOTE_ERROR = 5,
    SECRETSPEC_IPC_CANCELLED = 6,
    SECRETSPEC_IPC_DEADLINE_EXCEEDED = 7
} secretspec_ipc_status;

typedef struct {
    unsigned char *data;
    size_t size;
} secretspec_ipc_buffer;

SECRETSPEC_IPC_API uint32_t secretspec_ipc_abi_version(void);

SECRETSPEC_IPC_API secretspec_ipc_status secretspec_ipc_client_open(
    const secretspec_ipc_options *options,
    uint64_t deadline_unix_ms,
    secretspec_ipc_client **client,
    secretspec_ipc_buffer *server_info,
    secretspec_ipc_buffer *error);

SECRETSPEC_IPC_API secretspec_ipc_status secretspec_ipc_call_start(
    secretspec_ipc_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_ipc_call **call,
    secretspec_ipc_buffer *error);

/* Convenience form for callers that do not need cancellation or multiplexing. */
SECRETSPEC_IPC_API secretspec_ipc_status secretspec_ipc_client_call(
    secretspec_ipc_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error);

SECRETSPEC_IPC_API secretspec_ipc_status secretspec_ipc_call_wait(
    secretspec_ipc_call *call,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error);

SECRETSPEC_IPC_API void secretspec_ipc_call_cancel(secretspec_ipc_call *call);
SECRETSPEC_IPC_API void secretspec_ipc_call_free(secretspec_ipc_call *call);

SECRETSPEC_IPC_API secretspec_ipc_status secretspec_ipc_client_close(
    secretspec_ipc_client *client,
    uint64_t deadline_unix_ms,
    secretspec_ipc_buffer *error);

SECRETSPEC_IPC_API void secretspec_ipc_client_free(secretspec_ipc_client *client);
SECRETSPEC_IPC_API void secretspec_ipc_buffer_free(secretspec_ipc_buffer buffer);

#ifdef __cplusplus
}
#endif

#endif

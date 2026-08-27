#ifndef SECRETSPEC_RESOLVER_INTERNAL_H
#define SECRETSPEC_RESOLVER_INTERNAL_H

#include "secretspec_resolver.h"
#include "yyjson.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SS_ABSOLUTE_MAX_FRAME ((size_t)1048576)
#define SS_MIN_FRAME ((size_t)4096)
#define SS_MAX_IN_FLIGHT ((size_t)32)
#define SS_MAX_ID UINT64_C(9007199254740991)
/* Largest interval a caller-supplied deadline may place in the future. Mirrors
 * MAX_DEADLINE_HORIZON in the Rust implementation. Without it a deadline near
 * UINT64_MAX makes every timed wait unrepresentable and requests never expire. */
#define SS_MAX_DEADLINE_HORIZON_MS UINT64_C(300000)
#define SS_KNOWN_FLAGS (SECRETSPEC_RESOLVER_DISCOVER_EXECUTABLE | SECRETSPEC_RESOLVER_INHERIT_ENVIRONMENT | \
                        SECRETSPEC_RESOLVER_ANSWER_PROMPTS)

typedef struct ss_process ss_process;

#define SS_FRAME_READ_CHUNK ((size_t)8192)

typedef struct {
    unsigned char data[SS_FRAME_READ_CHUNK];
    size_t start;
    size_t end;
} ss_frame_reader;

typedef struct {
    char *executable;
    char **arguments;
    size_t argument_count;
    char **environment;
    size_t environment_count;
    bool discover;
    bool inherit_environment;
} ss_launch;

secretspec_resolver_status ss_process_spawn(const ss_launch *launch, ss_process **process);
ptrdiff_t ss_process_read_stdout(ss_process *process, unsigned char *buffer, size_t size);
ptrdiff_t ss_process_read_stderr(ss_process *process, unsigned char *buffer, size_t size);
bool ss_process_write_stdin(ss_process *process, const unsigned char *buffer, size_t size);
void ss_process_close_stdin(ss_process *process);
void ss_process_interrupt_io(ss_process *process);
bool ss_process_wait(ss_process *process, uint64_t deadline_unix_ms);
void ss_process_terminate(ss_process *process);
void ss_process_free(ss_process *process);

uint64_t ss_now_unix_ms(void);
void ss_secure_clear(void *pointer, size_t size);
void ss_buffer_reset(secretspec_resolver_buffer *buffer);
bool ss_buffer_copy(secretspec_resolver_buffer *buffer, const unsigned char *data, size_t size);
void ss_set_error(secretspec_resolver_buffer *error, const char *kind, const char *message);

bool ss_json_validate(const unsigned char *json, size_t size, yyjson_doc **document);
bool ss_json_is_closed_object(yyjson_val *object, const char *const *keys, size_t key_count);
bool ss_json_u64(yyjson_val *value, uint64_t *number);
bool ss_json_write_value(yyjson_val *value, secretspec_resolver_buffer *buffer);
secretspec_resolver_status ss_frame_read(
    ss_process *process,
    ss_frame_reader *reader,
    size_t limit,
    secretspec_resolver_buffer *payload,
    bool *clean_eof,
    bool *non_protocol_text);
bool ss_frame_write(ss_process *process, const unsigned char *payload, size_t size, size_t limit);

#endif

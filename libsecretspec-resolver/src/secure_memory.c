#include "internal.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

uint64_t ss_now_unix_ms(void) {
#if defined(_WIN32)
    FILETIME file_time;
    ULARGE_INTEGER value;
    GetSystemTimeAsFileTime(&file_time);
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    return (value.QuadPart - UINT64_C(116444736000000000)) / UINT64_C(10000);
#else
    struct timeval time;
    if (gettimeofday(&time, NULL) != 0) return 0;
    return (uint64_t)time.tv_sec * UINT64_C(1000) + (uint64_t)time.tv_usec / UINT64_C(1000);
#endif
}

void ss_secure_clear(void *pointer, size_t size) {
    volatile unsigned char *bytes = (volatile unsigned char *)pointer;
    while (size-- != 0) *bytes++ = 0;
}

/* yyjson's free hook passes no size, so each block records its own in a
 * header. The header is as wide as max_align_t so the block keeps malloc's
 * alignment guarantee. */
typedef union {
    size_t size;
    max_align_t align;
} ss_block_header;

static void *ss_zeroing_malloc(void *context, size_t size) {
    ss_block_header *header;
    (void)context;
    if (size > SIZE_MAX - sizeof(*header)) return NULL;
    header = (ss_block_header *)malloc(sizeof(*header) + size);
    if (header == NULL) return NULL;
    header->size = size;
    return header + 1;
}

void ss_zeroing_free(void *pointer) {
    ss_block_header *header;
    if (pointer == NULL) return;
    header = (ss_block_header *)pointer - 1;
    ss_secure_clear(pointer, header->size);
    free(header);
}

static void ss_zeroing_free_hook(void *context, void *pointer) {
    (void)context;
    ss_zeroing_free(pointer);
}

/* Never delegate to realloc: it may move the block and release the old copy
 * without wiping it. */
static void *ss_zeroing_realloc(void *context, void *pointer, size_t old_size, size_t size) {
    void *moved;
    size_t kept;
    (void)old_size;
    if (pointer == NULL) return ss_zeroing_malloc(context, size);
    moved = ss_zeroing_malloc(context, size);
    if (moved == NULL) return NULL;
    kept = ((ss_block_header *)pointer - 1)->size;
    memcpy(moved, pointer, kept < size ? kept : size);
    ss_zeroing_free(pointer);
    return moved;
}

const yyjson_alc ss_zeroing_alc = {
    ss_zeroing_malloc,
    ss_zeroing_realloc,
    ss_zeroing_free_hook,
    NULL,
};

void ss_buffer_reset(secretspec_resolver_buffer *buffer) {
    if (buffer != NULL) {
        buffer->data = NULL;
        buffer->size = 0;
    }
}

bool ss_buffer_copy(secretspec_resolver_buffer *buffer, const unsigned char *data, size_t size) {
    unsigned char *copy;
    if (buffer == NULL) return false;
    ss_buffer_reset(buffer);
    if (size == 0) return true;
    copy = (unsigned char *)malloc(size);
    if (copy == NULL) return false;
    memcpy(copy, data, size);
    buffer->data = copy;
    buffer->size = size;
    return true;
}

void ss_set_error(secretspec_resolver_buffer *error, const char *kind, const char *message) {
    char stable[256];
    int count;
    if (error == NULL) return;
    ss_buffer_reset(error);
    count = snprintf(stable, sizeof(stable),
                     "{\"kind\":\"%s\",\"message\":\"%s\"}", kind, message);
    if (count > 0 && (size_t)count < sizeof(stable)) {
        (void)ss_buffer_copy(error, (const unsigned char *)stable, (size_t)count);
    }
}

void secretspec_resolver_buffer_free(secretspec_resolver_buffer buffer) {
    if (buffer.data != NULL) {
        ss_secure_clear(buffer.data, buffer.size);
        free(buffer.data);
    }
}

uint32_t secretspec_resolver_abi_version(void) {
    return SECRETSPEC_RESOLVER_ABI_VERSION;
}

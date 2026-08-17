#include "internal.h"

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

void ss_buffer_reset(secretspec_ipc_buffer *buffer) {
    if (buffer != NULL) {
        buffer->data = NULL;
        buffer->size = 0;
    }
}

bool ss_buffer_copy(secretspec_ipc_buffer *buffer, const unsigned char *data, size_t size) {
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

void ss_set_error(secretspec_ipc_buffer *error, const char *kind, const char *message) {
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

void secretspec_ipc_buffer_free(secretspec_ipc_buffer buffer) {
    if (buffer.data != NULL) {
        ss_secure_clear(buffer.data, buffer.size);
        free(buffer.data);
    }
}

uint32_t secretspec_ipc_abi_version(void) {
    return SECRETSPEC_IPC_ABI_VERSION;
}

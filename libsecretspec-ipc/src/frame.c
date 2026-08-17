#include "internal.h"

#include <stdlib.h>

secretspec_ipc_status ss_frame_read(
    ss_process *process,
    size_t limit,
    secretspec_ipc_buffer *payload,
    bool *clean_eof) {
    unsigned char prefix[4];
    size_t read_count = 0;
    size_t length;
    ptrdiff_t count;

    ss_buffer_reset(payload);
    if (clean_eof != NULL) *clean_eof = false;
    while (read_count < sizeof(prefix)) {
        count = ss_process_read_stdout(process, prefix + read_count, sizeof(prefix) - read_count);
        if (count < 0) return SECRETSPEC_IPC_IO;
        if (count == 0) {
            if (read_count == 0 && clean_eof != NULL) *clean_eof = true;
            return read_count == 0 ? SECRETSPEC_IPC_OK : SECRETSPEC_IPC_PROTOCOL;
        }
        read_count += (size_t)count;
    }
    length = ((size_t)prefix[0] << 24) |
             ((size_t)prefix[1] << 16) |
             ((size_t)prefix[2] << 8) |
             (size_t)prefix[3];
    if (length == 0 || length > limit || length > SS_ABSOLUTE_MAX_FRAME) {
        return SECRETSPEC_IPC_PROTOCOL;
    }
    payload->data = (unsigned char *)malloc(length);
    if (payload->data == NULL) return SECRETSPEC_IPC_UNAVAILABLE;
    payload->size = length;
    read_count = 0;
    while (read_count < length) {
        count = ss_process_read_stdout(process, payload->data + read_count, length - read_count);
        if (count <= 0) {
            secretspec_ipc_buffer_free(*payload);
            ss_buffer_reset(payload);
            return count < 0 ? SECRETSPEC_IPC_IO : SECRETSPEC_IPC_PROTOCOL;
        }
        read_count += (size_t)count;
    }
    return SECRETSPEC_IPC_OK;
}

bool ss_frame_write(ss_process *process, const unsigned char *payload, size_t size, size_t limit) {
    unsigned char prefix[4];
    if (process == NULL || payload == NULL || size == 0 ||
        size > limit || size > SS_ABSOLUTE_MAX_FRAME || size > UINT32_MAX) return false;
    prefix[0] = (unsigned char)(size >> 24);
    prefix[1] = (unsigned char)(size >> 16);
    prefix[2] = (unsigned char)(size >> 8);
    prefix[3] = (unsigned char)size;
    return ss_process_write_stdin(process, prefix, sizeof(prefix)) &&
           ss_process_write_stdin(process, payload, size);
}

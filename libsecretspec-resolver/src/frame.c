#include "internal.h"

#include <stdlib.h>

/* One UTF-8 JSON object per LF. The payload limit excludes that delimiter;
 * buffering never exceeds it, even when a peer never sends LF. */
secretspec_resolver_status ss_frame_read(
    ss_process *process,
    size_t limit,
    secretspec_resolver_buffer *payload,
    bool *clean_eof,
    bool *non_protocol_text) {
    unsigned char byte;
    ptrdiff_t count;

    ss_buffer_reset(payload);
    if (clean_eof != NULL) *clean_eof = false;
    if (non_protocol_text != NULL) *non_protocol_text = false;
    if (process == NULL || limit == 0 || limit > SS_ABSOLUTE_MAX_FRAME) {
        return SECRETSPEC_RESOLVER_PROTOCOL;
    }
    payload->data = (unsigned char *)malloc(limit);
    if (payload->data == NULL) return SECRETSPEC_RESOLVER_UNAVAILABLE;
    payload->size = 0;
    for (;;) {
        count = ss_process_read_stdout(process, &byte, 1);
        if (count < 0) {
            secretspec_resolver_buffer_free(*payload);
            ss_buffer_reset(payload);
            return SECRETSPEC_RESOLVER_IO;
        }
        if (count == 0) {
            bool empty = payload->size == 0;
            if (empty && clean_eof != NULL) *clean_eof = true;
            secretspec_resolver_buffer_free(*payload);
            ss_buffer_reset(payload);
            return empty ? SECRETSPEC_RESOLVER_OK : SECRETSPEC_RESOLVER_PROTOCOL;
        }
        if (byte == '\n') {
            if (payload->size == 0) {
                secretspec_resolver_buffer_free(*payload);
                ss_buffer_reset(payload);
                return SECRETSPEC_RESOLVER_PROTOCOL;
            }
            return SECRETSPEC_RESOLVER_OK;
        }
        if (byte == '\r' || payload->size >= limit) {
            secretspec_resolver_buffer_free(*payload);
            ss_buffer_reset(payload);
            return SECRETSPEC_RESOLVER_PROTOCOL;
        }
        payload->data[payload->size++] = byte;
    }
}

bool ss_frame_write(ss_process *process, const unsigned char *payload, size_t size, size_t limit) {
    static const unsigned char newline = '\n';
    if (process == NULL || payload == NULL || size == 0 || size > limit ||
        size > SS_ABSOLUTE_MAX_FRAME) return false;
    for (size_t index = 0; index < size; index++) {
        if (payload[index] == '\n' || payload[index] == '\r') return false;
    }
    return ss_process_write_stdin(process, payload, size) &&
           ss_process_write_stdin(process, &newline, 1);
}

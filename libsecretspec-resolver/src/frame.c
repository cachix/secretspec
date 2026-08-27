#include "internal.h"

#include <stdlib.h>
#include <string.h>

static bool looks_like_non_protocol_text(const secretspec_resolver_buffer *payload) {
    size_t index = 0;
    while (index < payload->size &&
           (payload->data[index] == ' ' || payload->data[index] == '\t')) index++;
    if (index == payload->size || payload->data[index] == '{') return false;
    for (; index < payload->size; index++) {
        unsigned char byte = payload->data[index];
        if (byte != '\t' && (byte < 0x20 || byte > 0x7e)) return false;
    }
    return true;
}

static secretspec_resolver_status frame_failure(
    secretspec_resolver_buffer *payload,
    bool *non_protocol_text,
    secretspec_resolver_status status) {
    if (non_protocol_text != NULL) {
        *non_protocol_text = looks_like_non_protocol_text(payload);
    }
    secretspec_resolver_buffer_free(*payload);
    ss_buffer_reset(payload);
    return status;
}

/* One UTF-8 JSON object per LF. The payload limit excludes that delimiter;
 * buffering never exceeds it, even when a peer never sends LF. */
secretspec_resolver_status ss_frame_read(
    ss_process *process,
    ss_frame_reader *reader,
    size_t limit,
    secretspec_resolver_buffer *payload,
    bool *clean_eof,
    bool *non_protocol_text) {
    ss_buffer_reset(payload);
    if (clean_eof != NULL) *clean_eof = false;
    if (non_protocol_text != NULL) *non_protocol_text = false;
    if (process == NULL || reader == NULL || limit == 0 ||
        limit > SS_ABSOLUTE_MAX_FRAME) {
        return SECRETSPEC_RESOLVER_PROTOCOL;
    }
    payload->data = (unsigned char *)malloc(limit);
    if (payload->data == NULL) return SECRETSPEC_RESOLVER_UNAVAILABLE;
    payload->size = 0;
    for (;;) {
        unsigned char *newline;
        size_t available;
        size_t copied;
        size_t consumed;
        if (reader->start == reader->end) {
            ptrdiff_t count = ss_process_read_stdout(
                process, reader->data, sizeof(reader->data));
            reader->start = 0;
            reader->end = count > 0 ? (size_t)count : 0;
            if (count < 0) {
                return frame_failure(payload, non_protocol_text,
                                     SECRETSPEC_RESOLVER_IO);
            }
            if (count == 0) {
                bool empty = payload->size == 0;
                if (empty && clean_eof != NULL) *clean_eof = true;
                return frame_failure(
                    payload, non_protocol_text,
                    empty ? SECRETSPEC_RESOLVER_OK : SECRETSPEC_RESOLVER_PROTOCOL);
            }
        }

        available = reader->end - reader->start;
        newline = (unsigned char *)memchr(reader->data + reader->start, '\n', available);
        copied = newline == NULL ? available : (size_t)(newline - (reader->data + reader->start));
        consumed = copied + (newline == NULL ? 0 : 1);
        if (memchr(reader->data + reader->start, '\r', copied) != NULL ||
            copied > limit - payload->size) {
            return frame_failure(payload, non_protocol_text,
                                 SECRETSPEC_RESOLVER_PROTOCOL);
        }
        memcpy(payload->data + payload->size, reader->data + reader->start, copied);
        payload->size += copied;
        ss_secure_clear(reader->data + reader->start, consumed);
        reader->start += consumed;
        if (reader->start == reader->end) reader->start = reader->end = 0;

        if (newline != NULL) {
            if (payload->size == 0) {
                return frame_failure(payload, non_protocol_text,
                                     SECRETSPEC_RESOLVER_PROTOCOL);
            }
            if (looks_like_non_protocol_text(payload)) {
                if (non_protocol_text != NULL) *non_protocol_text = true;
                secretspec_resolver_buffer_free(*payload);
                ss_buffer_reset(payload);
                return SECRETSPEC_RESOLVER_PROTOCOL;
            }
            return SECRETSPEC_RESOLVER_OK;
        }
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

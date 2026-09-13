#include "internal.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *data;
    size_t size;
} ss_key;

static int ss_key_compare(const void *left_pointer, const void *right_pointer) {
    const ss_key *left = (const ss_key *)left_pointer;
    const ss_key *right = (const ss_key *)right_pointer;
    size_t common = left->size < right->size ? left->size : right->size;
    int order = memcmp(left->data, right->data, common);
    if (order != 0) return order;
    return left->size < right->size ? -1 : left->size > right->size;
}

static bool ss_json_tree_valid(yyjson_val *value, size_t depth) {
    yyjson_val *child;
    size_t index;
    size_t maximum;

    if (yyjson_is_arr(value)) {
        if (depth >= 64) return false;
        yyjson_arr_foreach(value, index, maximum, child) {
            if (!ss_json_tree_valid(child, depth + 1)) return false;
        }
        return true;
    }
    if (yyjson_is_obj(value)) {
        yyjson_obj_iter iterator;
        yyjson_val *key;
        size_t count;
        size_t position = 0;
        ss_key *keys;
        bool valid = true;
        if (depth >= 64) return false;
        count = yyjson_obj_size(value);
        keys = count == 0 ? NULL : (ss_key *)calloc(count, sizeof(*keys));
        if (count != 0 && keys == NULL) return false;
        yyjson_obj_iter_init(value, &iterator);
        while ((key = yyjson_obj_iter_next(&iterator)) != NULL) {
            yyjson_val *member = yyjson_obj_iter_get_val(key);
            keys[position].data = yyjson_get_str(key);
            keys[position].size = yyjson_get_len(key);
            position++;
            if (!ss_json_tree_valid(member, depth + 1)) valid = false;
        }
        if (valid && count > 1) {
            qsort(keys, count, sizeof(*keys), ss_key_compare);
            for (position = 1; position < count; position++) {
                if (keys[position - 1].size == keys[position].size &&
                    memcmp(keys[position - 1].data, keys[position].data, keys[position].size) == 0) {
                    valid = false;
                    break;
                }
            }
        }
        free(keys);
        return valid;
    }
    return true;
}

bool ss_json_validate(const unsigned char *json, size_t size, yyjson_doc **document) {
    yyjson_read_err error;
    yyjson_doc *parsed;
    yyjson_val *root;
    if (document == NULL || json == NULL || size == 0) return false;
    *document = NULL;
    parsed = yyjson_read_opts((char *)json, size, YYJSON_READ_NOFLAG, NULL, &error);
    if (parsed == NULL) return false;
    root = yyjson_doc_get_root(parsed);
    if (!yyjson_is_obj(root) || !ss_json_tree_valid(root, 0)) {
        yyjson_doc_free(parsed);
        return false;
    }
    *document = parsed;
    return true;
}

bool ss_json_is_closed_object(yyjson_val *object, const char *const *keys, size_t key_count) {
    yyjson_obj_iter iterator;
    yyjson_val *key;
    if (!yyjson_is_obj(object)) return false;
    yyjson_obj_iter_init(object, &iterator);
    while ((key = yyjson_obj_iter_next(&iterator)) != NULL) {
        const char *name = yyjson_get_str(key);
        size_t size = yyjson_get_len(key);
        size_t index;
        bool known = false;
        for (index = 0; index < key_count; index++) {
            if (strlen(keys[index]) == size && memcmp(keys[index], name, size) == 0) {
                known = true;
                break;
            }
        }
        if (!known) return false;
    }
    return true;
}

bool ss_json_u64(yyjson_val *value, uint64_t *number) {
    if (!yyjson_is_uint(value) || number == NULL) return false;
    *number = yyjson_get_uint(value);
    return true;
}

bool ss_json_write_value(yyjson_val *value, secretspec_resolver_buffer *buffer) {
    yyjson_write_err error;
    size_t size = 0;
    char *json;
    bool copied;
    if (value == NULL || buffer == NULL) return false;
    json = yyjson_val_write_opts((yyjson_val *)value, YYJSON_WRITE_NOFLAG, NULL, &size, &error);
    if (json == NULL) return false;
    copied = ss_buffer_copy(buffer, (const unsigned char *)json, size);
    ss_secure_clear(json, size);
    free(json);
    return copied;
}

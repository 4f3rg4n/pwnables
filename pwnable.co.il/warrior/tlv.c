#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tlv.h"


struct buffer_t {
    uint8_t* buf;
    size_t offset;
    size_t buffer_size;
};


void destroy_object(object_t* obj) {
    if (obj == NULL) {
        return;
    }
    obj->type = MAX_OBJECT_TYPE;
    obj->length = 0;
    if (obj->type == STRING) {
        free(obj->object.string);
        obj->object.string = NULL;
    } else if (obj->type == BYTES) {
        free(obj->object.bytes);
        obj->object.bytes = NULL;
    }
    free(obj);
}


object_t* parse_object(uint8_t** buffer, size_t* buffer_size) {
    if (buffer == NULL || *buffer_size <= 2) {
        return NULL;
    }
    size_t offset = 0;
    object_t* obj = calloc(sizeof(object_t), 1);
    uint8_t* data = *buffer;
    uint8_t type = data[0];
    if (type >= MAX_OBJECT_TYPE) {
        goto cleanup;
    }
    data++;
    offset++;
    size_t length = data[0];
    data++;
    offset++;
    if (length == 0) {
        goto cleanup;
    }
    switch (type) {
        case INT:
            if (length > sizeof(uint64_t) || offset + length > *buffer_size) {
                goto cleanup;
            }
            obj->type = INT;
            obj->length = sizeof(uint64_t);
            if (length == 1) {
                obj->object.num = data[0];
            } else if (length == 2) {
                obj->object.num = *(uint16_t*)data;
            } else if (length == 4) {
                obj->object.num = *(uint32_t*)data;
            } else if (length == 8) {
                obj->object.num = *(uint64_t*)data;
            } else {
                goto cleanup;
            }
            data += length;
            break;
        case STRING:
            if (offset + length > *buffer_size) {
                goto cleanup;
            }
            obj->type = STRING;
            obj->object.string = calloc(sizeof(char), length + 1);
            memcpy(obj->object.string, data, length);
            obj->length = length;
            obj->object.string[length] = 0;
            data += length;
            break;
        case BYTES:
            if (offset + length > *buffer_size || length % 2 != 0) {
                goto cleanup;
            }
            // decode hex
            uint8_t* bytes = malloc((length / 2) * sizeof(uint8_t));
            for (size_t i = 0, j = 0; i < length; i += 2) {
                if (!isxdigit(data[i])) {
                    continue;
                }
                // convert from hex
                uint8_t val_first = 0, val_second = 0;
                
                if ('0' <= data[i] && data[i] <= '9') {
                    val_first = data[i] - '0';
                } else if ('a' <= data[i] && data[i] <= 'f') {
                    val_first = data[i] - 'a' + 0xa;
                } else if ('A' <= data[i] && data[i] <= 'f') {
                    val_first = data[i] - 'A' + 0xa;
                } else {
                    free(bytes);
                    goto cleanup;
                }

                if ('0' <= data[i+1] && data[i+1] <= '9') {
                    val_second = data[i+1] - '0';
                } else if ('a' <= data[i+1] && data[i+1] <= 'f') {
                    val_second = data[i+1] - 'a' + 0xa;
                } else if ('A' <= data[i+1] && data[i+1] <= 'f') {
                    val_second = data[i+1] - 'A' + 0xa;
                } else {
                    free(bytes);
                    goto cleanup;
                }

                bytes[j++] = (val_first << 4) | val_second;
            }
            obj->type = BYTES;
            obj->length = length / 2;
            obj->object.bytes = bytes;
            data += length;
            break;
        default:
            goto cleanup;
    }
    // move buffer to after parsed object
    *buffer_size -= 2 + length;
    *buffer = data;
    return obj;
cleanup:
    free(obj);
    return NULL;
}


buffer_t* create_buffer() {
    buffer_t* buf = calloc(sizeof(buffer_t), 1);
    buf->buf = calloc(sizeof(uint8_t), 8);
    buf->buffer_size = 8;
    buf->offset = 0;
    return buf;
}


void add_int(buffer_t* buffer, uint64_t num) {
    while (buffer->offset + sizeof(uint64_t) + 2 >= buffer->buffer_size) {
        buffer->buf = realloc(buffer->buf, buffer->buffer_size * 2);
        buffer->buffer_size = buffer->buffer_size * 2;
    }
    buffer->buf[buffer->offset++] = INT;
    buffer->buf[buffer->offset++] = sizeof(uint64_t);
    memcpy(&buffer->buf[buffer->offset], &num, sizeof(uint64_t));
    buffer->offset += sizeof(uint64_t);
}


void add_string(buffer_t* buffer, char* string) {
    size_t string_len = strlen(string);
    while (buffer->offset + string_len + 2 >= buffer->buffer_size) {
        buffer->buf = realloc(buffer->buf, buffer->buffer_size * 2);
        buffer->buffer_size = buffer->buffer_size * 2;
    }
    buffer->buf[buffer->offset++] = STRING;
    buffer->buf[buffer->offset++] = string_len;
    memcpy(&buffer->buf[buffer->offset], string, string_len);
    buffer->offset += string_len;
}


void add_bytes(buffer_t* buffer, uint8_t* bytes, size_t bytes_len) {
    size_t needed_size = bytes_len * 2;
    while (buffer->offset + needed_size + 2 >= buffer->buffer_size) {
        buffer->buf = realloc(buffer->buf, buffer->buffer_size * 2);
        buffer->buffer_size = buffer->buffer_size * 2;
    }
    buffer->buf[buffer->offset++] = BYTES;
    buffer->buf[buffer->offset++] = needed_size;
    for (size_t i = 0; i < bytes_len; ++i) {
        sprintf((char*)&buffer->buf[buffer->offset], "%02x", bytes[i]);
        buffer->offset += 2;
    }
}


uint8_t* finalize_buffer(buffer_t* buffer, size_t* buflen) {
    uint8_t* buf = buffer->buf;
    *buflen = buffer->offset;
    buffer->buf = NULL;
    buffer->offset = 0;
    buffer->buffer_size = 0;
    free(buffer);
    return buf;
}
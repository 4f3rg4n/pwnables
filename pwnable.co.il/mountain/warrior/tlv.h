#ifndef __TLV_H
#define __TLV_H

#include <stdint.h>
#include <stddef.h>

#define GET_INT(x) ((x)->object.num)
#define GET_BYTES(x) ((x)->object.bytes)
#define GET_STRING(x) ((x)->object.string)
#define GET_LENGTH(x) ((x)->length)

enum object_type {
    INT = 1,
    STRING,
    BYTES,
    MAX_OBJECT_TYPE
};

typedef struct {
    enum object_type type;
    size_t length;
    union tlv
    {
        uint64_t num;
        char* string;
        uint8_t* bytes;
    } object;
} object_t;

typedef struct buffer_t buffer_t;

object_t* parse_object(uint8_t** buffer, size_t* buffer_size);
void destroy_object(object_t* obj);

buffer_t* create_buffer();
void add_int(buffer_t* buffer, uint64_t num);
void add_string(buffer_t* buffer, char* string);
void add_bytes(buffer_t* buffer, uint8_t* bytes, size_t bytes_len);
uint8_t* finalize_buffer(buffer_t* buffer, size_t* buflen);

#endif
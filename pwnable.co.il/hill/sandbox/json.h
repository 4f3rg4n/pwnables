#ifndef __JSON_H
#define __JSON_H

#include <stddef.h>
#include <stdint.h>


#define GET_STRING(x) ((x)->data.string)
#define GET_NUMBER(x) ((x)->data.number)
#define GET_ARRAY(x) ((x)->data.array)
#define GET_OBJECT(x) ((x)->data.object)
#define GET_BOOLEAN(x) ((x)->data.boolean)


typedef enum {
    JSON_NULL,
    JSON_BOOLEAN,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;


struct json_value_t;


typedef struct {
    struct json_value_t** items;
    size_t count;
} json_array;

struct json_value_t;

typedef struct json_object_entry_t {
    char* key;
    struct json_value_t* value;
    struct json_object_entry_t* next;
} json_object_entry_t;


typedef struct {
    json_object_entry_t* head;
    size_t count;
} json_object_t;


typedef struct json_value_t {
    json_type_t type;
    union {
        int boolean;
        uint64_t number;
        char* string;
        json_array array;
        json_object_t object;
    } data;
} json_value_t;


json_value_t* parse_json(char* json_string);
json_value_t* get_key(json_value_t* obj, char* key);
json_value_t* get_item(json_value_t* obj, size_t index);


#endif
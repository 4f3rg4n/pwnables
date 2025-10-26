#include "json.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>


typedef struct json_key_value_t {
    json_value_t* key;
    json_value_t* value;
} json_key_value_t;


json_key_value_t* parse_key_value(char** json_string);
json_value_t* parse_object(char** json_string);


char read_next_char(char** json_string) {
    char* curr = *json_string;
    while (isspace(*curr)) {
        curr++;
    }
    return curr[0];
}


json_value_t* parse_string(char** json_string) {
    char* curr = *json_string;
    while (isspace(*curr)) {
        curr++;
    }
    // check string starts and ends with a "
    if (*curr != '"' || !strchr(curr+1, '"')) {
        return NULL;
    }
    char* end_str = strchr(curr+1, '"');
    size_t str_length = (end_str - curr);
    json_value_t* value = calloc(sizeof(*value), 1);
    value->type = JSON_STRING;
    value->data.string = calloc(sizeof(char), str_length);
    strncpy(value->data.string, curr+1, str_length - 1);
    *json_string = end_str + 1;
    return value;
}


json_value_t* parse_number(char** json_string) {
    char* curr = *json_string;
    while (isspace(*curr)) {
        curr++;
    }
    char* end_number = curr;
    while (isdigit(end_number[0])) {
        end_number++;
    }
    size_t number_length = end_number - curr + 1;
    char* number_str = calloc(sizeof(char), number_length);
    memcpy(number_str, curr, number_length - 1);
    uint64_t number = (uint64_t)strtol(number_str, NULL, 10);
    json_value_t* value = calloc(sizeof(*value), 1);
    value->type = JSON_NUMBER;
    value->data.number = number;
    *json_string = end_number;
    return value;
}


json_value_t* parse_array(char** json_string) {
    char* curr = *json_string;
    while (isspace(*curr)) {
        curr++;
    }
    if (*curr != '[' || !strchr(curr+1, ']')) {
        return NULL;
    }
    json_value_t* array = calloc(sizeof(*array), 1);
    array->type = JSON_ARRAY;
    GET_ARRAY(array).count = 0;
    GET_ARRAY(array).items = NULL;
    curr++;
    char tok;
    int first = 1;
    while ((tok=read_next_char(&curr)) != ']') {
        if (!first) {
            if (read_next_char(&curr) != ',') {
                return NULL;
            }
            curr++;
            tok = read_next_char(&curr);
        }
        json_value_t* json_value;
        if (tok == '"') {
            json_value = parse_string(&curr);
        } else if (tok == '{') {
            json_value = parse_object(&curr);
        } else if (tok == '[') {
            json_value = parse_array(&curr);
        } else if (isdigit(tok)) {
            json_value = parse_number(&curr);
        } else {
            return NULL;
        }
        GET_ARRAY(array).items = realloc(GET_ARRAY(array).items, ++GET_ARRAY(array).count * sizeof(json_value_t*));
        GET_ARRAY(array).items[GET_ARRAY(array).count - 1] = json_value;
        first = 0;

    }
    // skip ]
    *json_string = curr + 1;
    return array;
}


json_value_t* parse_object(char** json_string) {
    char* curr = *json_string;
    while (isspace(*curr)) {
        curr++;
    }
    // check string starts and ends with a {
    if (*curr != '{' || !strchr(curr, '}')) {
        return NULL;
    }
    json_value_t* obj = calloc(sizeof(*obj), 1);
    obj->type = JSON_OBJECT;
    obj->data.object.count = 0;
    obj->data.object.head = NULL;
    // skip the {
    curr++;
    char tok;
    int first = 1;
    while ((tok=read_next_char(&curr)) != '}') {
        if (!first) {
            // check that , is here
            if (read_next_char(&curr) != ',') {
                return NULL;
            }
            curr++;
            tok = read_next_char(&curr);
        }
        if (tok != '"') {
            // bad key
            return NULL;
        }
        json_key_value_t* json_key_value = parse_key_value(&curr);
        if (!json_key_value) {
            return NULL;
        }
        // insert into object
        json_object_entry_t* curr_entry = calloc(sizeof(*curr_entry), 1);
        curr_entry->key = GET_STRING(json_key_value->key);
        curr_entry->value = json_key_value->value;
        curr_entry->next = GET_OBJECT(obj).head;
        obj->data.object.head = curr_entry;
        obj->data.object.count++;
        first = 0;
    }
    // skip }
    *json_string = curr + 1;
    return obj;
    
}


json_value_t* parse_json(char* json_string) {
    char* temp = json_string;
    return parse_object(&temp);
}


json_key_value_t* parse_key_value(char** json_string) {
    char tok;
    char* curr = *json_string;
    while (isspace(*curr)) {
        curr++;
    }
    json_value_t* json_key = parse_string(&curr);
    tok = read_next_char(&curr);
    if (tok != ':') {
        // bad format
        return NULL;
    }
    curr++;
    tok = read_next_char(&curr);
    json_value_t* json_value;
    if (tok == '"') {
        json_value = parse_string(&curr);
    } else if (tok == '{') {
        json_value = parse_object(&curr);
    } else if (tok == '[') {
        json_value = parse_array(&curr);
    } else if (isdigit(tok)) {
        json_value = parse_number(&curr);
    } else {
        return NULL;
    }
    *json_string = curr;
    json_key_value_t* keyval = calloc(sizeof(*keyval), 1);
    keyval->key = json_key;
    keyval->value = json_value;
    return keyval;
}


json_value_t* get_key(json_value_t* obj, char* key) {
    if (obj->type != JSON_OBJECT) {
        return NULL;
    }
    json_object_entry_t* curr = GET_OBJECT(obj).head;
    for (size_t i = 0; i < GET_OBJECT(obj).count && curr != NULL; ++i) {
        if (!strcmp(key, curr->key)) {
            return curr->value;
        }
        curr = curr->next;
    }
    return NULL;
}


json_value_t* get_item(json_value_t* obj, size_t index) {
    if (index >= GET_ARRAY(obj).count) {
        return NULL;
    }
    return GET_ARRAY(obj).items[index];
}
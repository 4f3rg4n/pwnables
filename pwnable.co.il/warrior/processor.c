#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "tlv.h"
#include "auth.h"
#include "processor.h"
#include "safe_storage.h"

result_t* results;
uint8_t taken_ids[256];


int process_request(uint8_t* request, size_t request_size) {
    uint8_t** preq = &request;
    size_t* remaining_size = &request_size;
    while (1) {
        object_t* module = parse_object(preq, remaining_size);
        if (module == NULL || module->type != STRING) { break; }
        object_t* id = parse_object(preq, remaining_size);
        if (id == NULL || id->type != INT) { break; }
        object_t* cmd = parse_object(preq, remaining_size);
        if (cmd == NULL || cmd->type != STRING) { break; }

        if (!strcmp(GET_STRING(module), "auth")) {
            if (process_auth_request(GET_INT(id), GET_STRING(cmd), preq, remaining_size) != 0) {
                return 1;
            }
        } else if (!strcmp(GET_STRING(module), "storage")) {
            if (process_storage_request(GET_INT(id), GET_STRING(cmd), preq, remaining_size) != 0) {
                return 1;
            }
        }
        destroy_object(module);
        destroy_object(id);
        destroy_object(cmd);
    }
    return 0;
}


uint64_t send_request(char* module, char* action, char* format, ...) {
    va_list args;
    va_start(args, format);
    buffer_t* buf = create_buffer();
    uint64_t id = get_id();
    add_string(buf, module);
    add_int(buf, id);
    add_string(buf, action);
    for (char* ptr = format; ptr[0] != 0; ++ptr) {
        switch (ptr[0]) {
            case 's':
                add_string(buf, va_arg(args, char*));
                break;
            case 'b': {
                uint8_t* data = va_arg(args, uint8_t*);
                uint64_t length = va_arg(args, uint64_t);
                add_bytes(buf, data, length);
                break;
            }
            case 'i':
                add_int(buf, va_arg(args, uint64_t));
                break;
        }
    }
    size_t datalen;
    uint8_t* data = finalize_buffer(buf, &datalen);
    if (process_request(data, datalen) == 1) {
        puts("Request processing failed");
        exit(1);
    }
    return id;
}


void processor_init() {
    auth_init();
    storage_init();
    results = calloc(sizeof(result_t), MAX_RESULTS);
    if (results == NULL) {
        puts("results allocation error");
        exit(1);
    }
    memset(taken_ids, 0, sizeof(taken_ids));
}

uint64_t get_id() {
    for (size_t i = 0; i < sizeof(taken_ids); ++i) {
        if (!taken_ids[i]) {
            taken_ids[i] = 1;
            return i;
        }
    }
    puts("All id's taken, halting system");
    exit(1);
}

void release_id(uint64_t id) {
    if (taken_ids[id]) {
        taken_ids[id] = 0;
        return;
    }
    puts("Released id already free");
    exit(1);
}

int request_successful(uint64_t id) {
    uint8_t res = results[id].error_code == SUCCESS;
    results[id].error_code = SYSTEM_FAIL;
    release_id(id);
    return res;
}
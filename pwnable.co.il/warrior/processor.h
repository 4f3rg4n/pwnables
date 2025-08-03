#ifndef __PROCESSOR_H
#define __PROCESSOR_H

#include <stdint.h>


#define MAX_RESULTS 256

enum error_code {
    SYSTEM_FAIL = -1,
    SUCCESS,
    FAILURE
};

void processor_init();
// int process_request(uint8_t* request, size_t request_size);
uint64_t send_request(char* module, char* action, char* format, ...);
int request_successful(uint64_t id);

uint64_t get_id();
void release_id(uint64_t id);

typedef struct __attribute__((__packed__)) result_t {
    enum error_code error_code;
    size_t length;
    uint8_t result_data[0x1000 - sizeof(enum error_code) - sizeof(size_t)];
} result_t;

extern result_t* results;
#endif
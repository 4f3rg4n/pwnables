#ifndef __STORAGE_H
#define __STORAGE_H


#include <stdint.h>
#include <stddef.h>


#define MAX_KEY_LEN 256


typedef struct storage_t storage_t;


void storage_init();
int process_storage_request(uint64_t id, char* cmd, uint8_t** prequest, size_t* remaining_size);

#endif
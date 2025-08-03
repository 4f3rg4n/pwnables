#ifndef __AUTH_H
#define __AUTH_H
#include "safe_storage.h"

typedef struct {
    char* username;
    char* password;
} user_t;

typedef struct usernode_t {
    user_t* user;
    struct usernode_t* next;
    struct usernode_t* prev;
} usernode_t;

void auth_init();
int process_auth_request(uint64_t id, char* cmd, uint8_t** prequest, size_t* remaining_size);


extern user_t* current_logged_user;
extern usernode_t* registered_users;
#endif

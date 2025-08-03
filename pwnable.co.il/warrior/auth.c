#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tlv.h"
#include "auth.h"
#include "processor.h"

user_t* current_logged_user;
usernode_t* registered_users;


void auth_init() {
    current_logged_user = NULL;
    registered_users = calloc(sizeof(usernode_t), 1);
    registered_users->next = NULL;
    registered_users->prev = NULL;
    registered_users->user = NULL;
}

void register_user(char* username, char* password) {
    user_t* new_user = calloc(sizeof(user_t), 1);
    new_user->username = strdup(username);
    new_user->password = strdup(password);
    usernode_t* curr = registered_users;
    while (curr->next != NULL) {
        if (!strcmp(curr->user->username, new_user->username)) {
            return;
        }
        curr = curr->next;
    }
    // didn't find user, insert at beginning of list
    usernode_t* new_usernode = calloc(sizeof(usernode_t), 1);
    new_usernode->prev = NULL;
    new_usernode->next = registered_users;
    registered_users->prev = new_usernode;
    new_usernode->user = new_user;
    registered_users = new_usernode;
}

int login_user(char* username, char* password) {
    usernode_t* curr = registered_users;
    while (curr->next != NULL) {
        if (!strcmp(curr->user->username, username)) {
            if (!strcmp(curr->user->password, password)) {
                current_logged_user = curr->user;
                return 1;
            }
        }
        curr = curr->next;
    }
    return 0;
}

void logout() {
    current_logged_user = NULL;
}

void delete_user(char* username) {
    usernode_t* curr = registered_users;
    while (curr->next != NULL) {
        if (!strcmp(curr->user->username, username)) {
            goto found;
        }
        curr = curr->next;
    }
    return;
found:
    // free used memory
    free(curr->user->username);
    curr->user->username = NULL;
    free(curr->user->password);
    curr->user->password = NULL;
    free(curr->user);
    curr->user = NULL;
    // remove from linked list
    if (curr->prev) {
        curr->prev->next = curr->next;
        curr->prev = NULL;
    } else {
        // this is the head of the list
        registered_users = curr->next;
        registered_users->prev = NULL;
    }
    if (curr->next) {
        curr->next->prev = curr->prev;
        curr->next = NULL;
    }
    free(curr);
}

int process_auth_request(uint64_t id, char* cmd, uint8_t** prequest, size_t* remaining_size) {
    if (id >= MAX_RESULTS) {
        return 1;
    }
    result_t* res = &results[id];
    res->error_code = SYSTEM_FAIL;
    if (!strcmp(cmd, "login")) {
        // logout of currently logged in user
        current_logged_user = NULL;
        object_t* user = parse_object(prequest, remaining_size);
        if (user == NULL || user->type != STRING) { return 1; }

        object_t* password = parse_object(prequest, remaining_size);
        if (password == NULL || password->type != STRING) { return 1; }

        int login_res = login_user(GET_STRING(user), GET_STRING(password));
        if (login_res == 0) {
            res->error_code = FAILURE;
        } else {
            res->error_code = SUCCESS;
        }
        destroy_object(user);
        destroy_object(password);
    } else if (!strcmp(cmd, "register")) {
        object_t* user = parse_object(prequest, remaining_size);
        if (user == NULL || user->type != STRING) { return 1; }

        object_t* password = parse_object(prequest, remaining_size);
        if (password == NULL || password->type != STRING) { return 1; }

        register_user(GET_STRING(user), GET_STRING(password));
        res->error_code = SUCCESS;
        destroy_object(user);
        destroy_object(password);
    } else if (!strcmp(cmd, "del_user")) {
        object_t* user = parse_object(prequest, remaining_size);
        if (user == NULL || user->type != STRING) { return 1; }

        delete_user(GET_STRING(user));
        res->error_code = SUCCESS;
        destroy_object(user);
    } else if (!strcmp(cmd, "logout")) {
        logout();        
        res->error_code = SUCCESS;
    } else if (!strcmp(cmd, "forgot_password")) {
        object_t* password = parse_object(prequest, remaining_size);
        if (password == NULL || password->type != STRING) { return 1; }

        if (strlen(current_logged_user->password) < GET_LENGTH(password)) {
            free(current_logged_user->password);
            current_logged_user->password = calloc(strlen(GET_STRING(password)) + 1, sizeof(char));
        }
        strcpy(current_logged_user->password, GET_STRING(password));
        res->error_code = SUCCESS;
        destroy_object(password);
    } else {
        return 1;
    }
    return 0;
}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "json.h"


#define MAKE_COMMAND(idx, bin, args, allow) {cmds[(idx)].binary=strdup((bin)); cmds[(idx)].num_args=(args); ;cmds[(idx)].is_allowed=(allow);}
#define NUM_COMMANDS 5


static char buffer[0x4000];


typedef struct {
    char* binary;
    int num_args;
    int is_allowed;
} cmd_perm_t;


cmd_perm_t cmds[NUM_COMMANDS];


void init_commands() {
    MAKE_COMMAND(0, "ps", 0, 0);
    MAKE_COMMAND(1, "ls", 0, 1);
    MAKE_COMMAND(2, "date", 0, 1);
    MAKE_COMMAND(3, "cat", 1, 0);
    MAKE_COMMAND(4, "echo", 1, 1);
}


void allow_elevated_commands() {
    cmds[0].is_allowed = 1;
    cmds[3].is_allowed = 1;
}


void disallow_elevated_commands() {
    cmds[0].is_allowed = 0;
    cmds[3].is_allowed = 0;
}


cmd_perm_t get_cmd_perm(char* cmd) {
    for (size_t i = 0; i < NUM_COMMANDS; ++i) {
        if (!strcmp(cmd, cmds[i].binary)) {
            return cmds[i];
        }
    }
    return (cmd_perm_t){0};
}


void run_single_command(json_value_t* cmd, json_value_t* args) {
    char* binary = GET_STRING(cmd);
    cmd_perm_t perm = get_cmd_perm(binary);
    if (!perm.is_allowed) {
        return;
    }
    char** exec_args = calloc(perm.num_args + 2, sizeof(char*));
    exec_args[0] = binary;
    exec_args[perm.num_args + 1] = NULL;
    for (size_t i = 0; i < perm.num_args; ++i) {
        exec_args[i + 1] = GET_STRING(get_item(args, i));
    }
    printf("Running command %s\n", binary);
    pid_t pid = fork();
    if (pid == 0) {
        execvp(binary, exec_args);
    } else {
        wait(NULL);
        printf("Process completed!");
    }
}


void run_command(json_value_t* json) {
    if (json->type != JSON_OBJECT) {
        printf("Bad json");
        goto cleanup;
    }

    json_value_t* user_array = get_key(json, "users");
    json_value_t* cmds_array = get_key(json, "cmds");
    json_value_t* args_array = get_key(json, "args");
    if (!user_array  || !cmds_array || !args_array || 
    user_array->type != JSON_ARRAY || 
    cmds_array->type != JSON_ARRAY || 
    args_array->type != JSON_ARRAY || 
    GET_ARRAY(user_array).count != GET_ARRAY(cmds_array).count || 
    GET_ARRAY(user_array).count != GET_ARRAY(args_array).count) {
        printf("Bad json");
        goto cleanup;
    }
    for(size_t i = 0; i < GET_ARRAY(user_array).count; ++i) {
        json_value_t* val = get_item(user_array, i);
        if (!strcmp(GET_STRING(val), "admin")) {
            allow_elevated_commands();
        }
        json_value_t* cmd = get_item(cmds_array, i);
        json_value_t* args = get_item(args_array, i);
        run_single_command(cmd, args);
        disallow_elevated_commands();
    }
cleanup:
    free(json);
}


int main() {
    init_commands();
    read(0, buffer, sizeof(buffer)- 1);
    json_value_t* val = parse_json(buffer);
    run_command(val);
}
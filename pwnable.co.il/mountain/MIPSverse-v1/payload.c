#include <stdio.h>

int main() {
    char *const args[] = {"/bin/sh", NULL};
    execve(args[0], args, NULL);
    return 0;
}

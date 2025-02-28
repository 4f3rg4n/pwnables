from pwn import *

r = remote("pwnable.co.il", 9006)
r.sendline("g4nw4") # "g4nw4\n" = 537500598c2101141d3d9f25fb41f9e6
print(r.recvall().decode())


